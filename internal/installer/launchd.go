package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// launchctl is addressed by absolute path: the daemon's environment has a
// minimal PATH, and this is a system binary rather than something a user can
// replace.
const launchctl = "/bin/launchctl"

// daemonPlist is the LaunchDaemon definition.
//
// RunAtLoad plus KeepAlive is what makes the stack survive without anyone
// logged in: the supervisor starts at boot and is restarted if it ever exits.
// That is safe precisely because sing-box cannot outlive it (see
// internal/singbox), so a restart begins from a machine on its own routing
// rather than one left half-configured.
func daemonPlist(configPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>daemon</string>
    <string>-config</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>%s/daemon.log</string>
  <key>StandardErrorPath</key><string>%s/daemon.log</string>
</dict>
</plist>
`, DaemonLabel, BinaryPath, configPath, LogDir, LogDir)
}

// agentPlist is the per-user LaunchAgent for the menu bar. The menu bar needs a
// GUI session, which is why it cannot be part of the daemon.
//
// KeepAlive is conditional on the process having crashed, unlike the daemon's.
// The menu bar has a Quit item, and an unconditional KeepAlive would put the
// icon straight back — making the item look broken. A crash still brings it
// back, which is what KeepAlive is for.
func agentPlist() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>menubar</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key><false/>
  </dict>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
`, AgentLabel, BinaryPath)
}

// writeFileAs writes content and sets ownership, creating parents. launchd
// refuses a plist that is group- or world-writable, so the mode matters.
func writeFileAs(path, content string, uid, gid int, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, text)
		}
		return text, fmt.Errorf("%s %s: %w", filepath.Base(name), strings.Join(args, " "), err)
	}
	return text, nil
}

// bootstrapDaemon loads the daemon, replacing any previous instance.
//
// Unloading is not synchronous: launchctl returns before launchd has finished
// tearing the job down, and bootstrapping into that window fails with a bare
// "Input/output error". So the unload is waited out, and if the job somehow
// still exists afterwards it is restarted in place instead — which achieves
// the same thing, picking up the new binary.
func bootstrapDaemon() error {
	// Ignore the error: booting out something that is not loaded is not a
	// failure, and there is no cheap way to ask first.
	_, _ = run(launchctl, "bootout", "system/"+DaemonLabel)
	waitUntilUnloaded(10 * time.Second)

	_, err := run(launchctl, "bootstrap", "system", DaemonPlist)
	if err == nil {
		return nil
	}

	if !DaemonLoaded() {
		return err
	}

	// It is loaded after all, so the bootstrap raced a slow unload rather
	// than failing for a real reason. Restart it to pick up the new binary.
	if _, kerr := run(launchctl, "kickstart", "-k", "system/"+DaemonLabel); kerr != nil {
		return fmt.Errorf("%w (and restarting the loaded job failed: %v)", err, kerr)
	}
	return nil
}

// waitUntilUnloaded polls until launchd forgets the job, or the timeout
// expires.
func waitUntilUnloaded(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !DaemonLoaded() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func bootoutDaemon() error {
	_, err := run(launchctl, "bootout", "system/"+DaemonLabel)
	if err != nil && strings.Contains(err.Error(), "No such process") {
		return nil
	}
	return err
}

// bootstrapAgent loads the menu bar into the target user's GUI session. It
// fails harmlessly when no session exists, e.g. during a remote install.
func bootstrapAgent(t *Target) error {
	domain := fmt.Sprintf("gui/%d", t.UID)
	_, _ = run(launchctl, "bootout", domain+"/"+AgentLabel)

	_, err := run(launchctl, "bootstrap", domain, t.AgentPlist())
	return err
}

func bootoutAgent(t *Target) error {
	_, err := run(launchctl, "bootout", fmt.Sprintf("gui/%d/%s", t.UID, AgentLabel))
	if err != nil && strings.Contains(err.Error(), "No such process") {
		return nil
	}
	return err
}

// staleJob is a launchd job that launches our binary under a label that is no
// longer the one we install.
type staleJob struct {
	Label string
	Path  string
}

var plistLabel = regexp.MustCompile(`(?s)<key>Label</key>\s*<string>([^<]*)</string>`)

// findStaleJobs scans a launchd directory for jobs that start our binary under
// some other label.
//
// This is a scan rather than a list of names the project used to use. A list
// would have to be carried forever, and would name every label ever shipped —
// including one borrowed from an organisation with no connection to this
// software. Asking "which jobs launch my binary?" answers the same question
// without remembering anything.
//
// Left alone, such a job is not merely untidy: a plist in a launchd directory
// is loaded again at the next boot, so an old label would keep a second daemon
// running against the same ports as this one.
func findStaleJobs(dir, keepLabel string) []staleJob {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var stale []staleJob
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".plist" {
			continue
		}

		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if !strings.Contains(string(data), BinaryPath) {
			continue // not ours
		}

		m := plistLabel.FindSubmatch(data)
		if m == nil {
			continue
		}
		label := string(m[1])
		if label == keepLabel {
			continue
		}

		stale = append(stale, staleJob{Label: label, Path: path})
	}
	return stale
}

// RemoveStaleDaemonJobs unloads and deletes system jobs left by an earlier
// label.
func RemoveStaleDaemonJobs(logf func(string, ...any)) {
	for _, job := range findStaleJobs("/Library/LaunchDaemons", DaemonLabel) {
		_, _ = run(launchctl, "bootout", "system/"+job.Label)
		if err := os.Remove(job.Path); err == nil && logf != nil {
			logf("unloaded and removed a job from an earlier name: %s", job.Label)
		}
	}
}

// RemoveStaleAgentJobs is the same for the target user's agents.
func RemoveStaleAgentJobs(t *Target, logf func(string, ...any)) {
	dir := filepath.Join(t.HomeDir, "Library", "LaunchAgents")
	for _, job := range findStaleJobs(dir, AgentLabel) {
		_, _ = run(launchctl, "bootout", fmt.Sprintf("gui/%d/%s", t.UID, job.Label))
		if err := os.Remove(job.Path); err == nil && logf != nil {
			logf("unloaded and removed a job from an earlier name: %s", job.Label)
		}
	}
}

// StartAgent brings the menu bar back after its Quit item was used. launchd
// remembers the job; it just is not running.
func StartAgent(t *Target) error {
	_, err := run(launchctl, "kickstart", fmt.Sprintf("gui/%d/%s", t.UID, AgentLabel))
	return err
}

// AgentLoaded reports whether launchd knows about the menu bar job.
func AgentLoaded(uid int) bool {
	_, err := run(launchctl, "print", fmt.Sprintf("gui/%d/%s", uid, AgentLabel))
	return err == nil
}

// DaemonLoaded reports whether launchd knows about the daemon.
func DaemonLoaded() bool {
	_, err := run(launchctl, "print", "system/"+DaemonLabel)
	return err == nil
}
