package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vpn-router/internal/config"
)

// EmptyRuleSet is a valid sing-box source rule-set that matches nothing.
// Verified against sing-box 1.13: an empty rules array is accepted, whereas a
// rule object with no conditions is rejected — so this is the right shape for
// "no forced domains yet".
const EmptyRuleSet = `{
  "version": 4,
  "rules": []
}
`

// runtimeFile is one input the running system needs, and where it belongs.
type runtimeFile struct {
	label string
	// repoRel is where the pre-vpnctl setup kept it.
	repoRel string
	// destRel is its place in the config directory.
	destRel string
	mode    os.FileMode
}

var runtimeFiles = []runtimeFile{
	{"VPN profile", "company.ovpn", "company.ovpn", 0o600},
	{"auth file", "auth.txt", "auth.txt", 0o600},
	{"environment file", ".env", ".env", 0o600},
	{"force-VPN rules", "singbox/rules/force-vpn.json", "rules/force-vpn.json", 0o644},
}

// Migrate copies the runtime inputs out of a source checkout and into the
// config directory, then rewrites the config to point at the new locations.
//
// The point is that an installed vpnctl owns everything it needs to run. Until
// this has happened, the running system reads the VPN profile, the auth file
// and the force-VPN rules out of a git checkout — so moving or deleting that
// checkout breaks a working installation, and the container holds bind mounts
// into it.
//
// Originals are copied, not moved. They are secrets, and deleting someone's
// only copy of a credential to tidy up a directory is not the installer's
// call to make.
func Migrate(repoDir string, o Options) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("migrate must run as root:\n  sudo vpnctl migrate")
	}

	target, err := ResolveTarget()
	if err != nil {
		return err
	}

	configPath := o.ConfigPath
	if configPath == "" {
		configPath = target.DefaultConfigPath()
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", configPath, err)
	}
	configDir := filepath.Dir(configPath)

	var copied, kept []string

	for _, rf := range runtimeFiles {
		dest := filepath.Join(configDir, rf.destRel)

		if _, err := os.Stat(dest); err == nil {
			kept = append(kept, fmt.Sprintf("%s already at %s", rf.label, dest))
			continue
		}

		src := filepath.Join(repoDir, rf.repoRel)
		data, rerr := os.ReadFile(src)
		if rerr != nil {
			if rf.destRel == "rules/force-vpn.json" {
				// Without this file sing-box refuses to start, so an absent
				// one becomes an empty rule-set rather than a broken install.
				if err := writeFileAs(dest, EmptyRuleSet, target.UID, target.GID, rf.mode); err != nil {
					return err
				}
				copied = append(copied, fmt.Sprintf("%s created empty at %s", rf.label, dest))
				continue
			}
			kept = append(kept, fmt.Sprintf("%s not found at %s (skipped)", rf.label, src))
			continue
		}

		if err := writeFileAs(dest, string(data), target.UID, target.GID, rf.mode); err != nil {
			return err
		}
		copied = append(copied, fmt.Sprintf("%s %s -> %s", rf.label, src, dest))
	}

	for _, line := range copied {
		o.logf("copied %s", line)
	}
	for _, line := range kept {
		o.logf("%s", line)
	}

	if err := rewriteConfigPaths(configPath, cfg, configDir, target, o); err != nil {
		return err
	}

	o.logf("the originals are untouched; delete them from %s once you are happy", repoDir)
	return nil
}

// rewriteConfigPaths points the config at the config directory. A backup is
// written first, because this is the one place the installer edits a file the
// user owns.
func rewriteConfigPaths(configPath string, cfg *config.Config, configDir string, t *Target, o Options) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	backup := configPath + ".before-migrate"
	if err := writeFileAs(backup, string(raw), t.UID, t.GID, 0o600); err != nil {
		return err
	}
	o.logf("backed up the config to %s", backup)

	text := string(raw)
	replacements := map[string]string{
		"config":          "company.ovpn",
		"auth_file":       "auth.txt",
		"env_file":        ".env",
		"force_vpn_rules": "rules/force-vpn.json",
		// Beside the config, not in the state directory: only paths the
		// container runtime shares with its virtual machine work as bind
		// mounts, and /usr/local is not one of them.
		"vpn_dns_file": "run/vpn-dns",
	}

	// The container name has to move too. A configuration carried over from
	// the compose setup names the container compose generated, and creating
	// ours under that name fails on the conflict — while the old container is
	// still sitting there holding the SOCKS port.
	if legacy := cfg.Docker.Project + "-vpn-1"; cfg.Docker.Container == legacy {
		replacements["container"] = config.Defaults().Docker.Container
		o.logf("renaming the managed container from %s to %s", legacy, replacements["container"])
	}

	changed := 0
	var out []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		replaced := false

		for key, rel := range replacements {
			prefix := key + ":"
			if !strings.HasPrefix(trimmed, prefix) {
				continue
			}
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			out = append(out, fmt.Sprintf("%s%s %s", indent, prefix, rel))
			replaced = true
			changed++
			break
		}

		if !replaced {
			out = append(out, line)
		}
	}

	if changed == 0 {
		o.logf("the config already points inside %s", configDir)
		return nil
	}

	if err := writeFileAs(configPath, strings.Join(out, "\n"), t.UID, t.GID, 0o600); err != nil {
		return err
	}

	// Prove the result still loads before declaring success, so a bad rewrite
	// is caught here rather than by the daemon at the next boot.
	if _, err := config.Load(configPath); err != nil {
		restore, rerr := os.ReadFile(backup)
		if rerr == nil {
			_ = writeFileAs(configPath, string(restore), t.UID, t.GID, 0o600)
		}
		return fmt.Errorf("the rewritten config does not load, restored the backup: %w", err)
	}

	o.logf("rewrote %d path(s) in %s to be relative to it", changed, configPath)
	return nil
}
