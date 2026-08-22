package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"vpn-router/internal/config"
	"vpn-router/internal/installer"
	"vpn-router/internal/ipc"
	"vpn-router/internal/otp"
	"vpn-router/internal/status"
)

// setupCmd collects the three things a VPN connection needs and puts them
// where the daemon expects them.
//
// It runs as the user, not root: these are the user's credentials, they belong
// in the user's config directory, and nothing here needs privilege. The daemon
// reads them as root when it creates the container.
func setupCmd(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	profile := fs.String("profile", "", "path to the .ovpn profile (prompted for if omitted)")
	username := fs.String("username", "", "VPN username (prompted for if omitted)")
	configPath := fs.String("config", "", "path to config.yaml")
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
	force := fs.Bool("force", false, "overwrite existing credentials without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := *configPath
	if path == "" {
		if rec, err := installer.LoadRecord(); err == nil {
			path = rec.ConfigPath
		} else {
			path = config.DefaultPath()
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Someone may run this before installing anything, so there may be no
	// config to read paths out of yet.
	if _, err := os.Stat(path); err != nil {
		if err := os.WriteFile(path, []byte(config.ExampleYAML), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Printf("Wrote a starting config at %s\n\n", path)
	}

	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	in := bufio.NewReader(os.Stdin)

	if !*force {
		if err := confirmOverwrite(in, cfg); err != nil {
			return err
		}
	}

	profilePath := *profile
	if profilePath == "" {
		profilePath, err = ask(in, "Path to your .ovpn profile")
		if err != nil {
			return err
		}
	}
	profileData, err := readProfile(profilePath)
	if err != nil {
		return err
	}

	user := *username
	if user == "" {
		user, err = ask(in, "VPN username")
		if err != nil {
			return err
		}
	}
	if user == "" {
		return errors.New("the username cannot be empty")
	}

	password, err := askSecret(in, "VPN password")
	if err != nil {
		return err
	}
	if password == "" {
		return errors.New("the password cannot be empty")
	}

	secret, err := askTOTP(in)
	if err != nil {
		return err
	}

	// Written together and only after everything has been collected and
	// checked, so an abandoned run leaves the previous credentials intact.
	files := []struct {
		path, body string
	}{
		{cfg.VPN.Config, string(profileData)},
		{cfg.VPN.AuthFile, user + "\n" + password + "\n"},
		{cfg.VPN.EnvFile, envFile(secret)},
	}
	for _, f := range files {
		if err := writeSecret(f.path, f.body); err != nil {
			return err
		}
		fmt.Printf("  wrote %s\n", f.path)
	}

	// sing-box refuses to start when its configuration names a rule-set file
	// that is not there, so the config has to be self-consistent by the time
	// this returns — even if install has not run yet.
	if rules := cfg.SingBox.ForceVPNRules; rules != "" {
		if _, err := os.Stat(rules); err != nil {
			if err := os.MkdirAll(filepath.Dir(rules), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(rules, []byte(installer.EmptyRuleSet), 0o644); err != nil {
				return err
			}
			fmt.Printf("  wrote %s (empty; nothing is forced through the VPN yet)\n", rules)
		}
	}

	fmt.Println()
	return applyOrExplain(*socketPath)
}

// confirmOverwrite refuses to silently replace credentials that are already
// there. Getting a working VPN set up again is not a five minute job.
func confirmOverwrite(in *bufio.Reader, cfg *config.Config) error {
	var existing []string
	for _, p := range []string{cfg.VPN.Config, cfg.VPN.AuthFile, cfg.VPN.EnvFile} {
		if _, err := os.Stat(p); err == nil {
			existing = append(existing, p)
		}
	}
	if len(existing) == 0 {
		return nil
	}

	fmt.Println("These already exist and will be replaced:")
	for _, p := range existing {
		fmt.Printf("  %s\n", p)
	}

	answer, err := ask(in, "\nReplace them? [y/N]")
	if err != nil {
		return err
	}
	if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
		return errors.New("nothing was changed")
	}
	fmt.Println()
	return nil
}

// readProfile checks the file looks like an OpenVPN profile before it is
// copied. A path typo produces a container that fails to start with an error
// from inside a container, which is a long way from the mistake.
func readProfile(path string) ([]byte, error) {
	expanded, err := expandHome(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("read the profile: %w", err)
	}

	text := string(data)
	if !strings.Contains(text, "remote ") && !strings.Contains(text, "<connection>") {
		return nil, fmt.Errorf("%s has no \"remote\" line, so it does not look like an OpenVPN profile", expanded)
	}
	if strings.Contains(text, "auth-user-pass ") {
		fmt.Println("  note: the profile names its own auth-user-pass file; vpnctl passes one explicitly,")
		fmt.Println("        so the line in the profile is ignored.")
	}
	return data, nil
}

// askTOTP takes the setup secret and proves it is the right one by generating
// the code it produces right now.
func askTOTP(in *bufio.Reader) (string, error) {
	for {
		secret, err := askSecret(in, "TOTP setup secret (Base32)")
		if err != nil {
			return "", err
		}

		code, err := otp.Code(secret, time.Now())
		if err != nil {
			fmt.Printf("  %v\n\n", err)
			continue
		}

		fmt.Printf("\n  That secret produces %s right now, valid for %d more seconds.\n",
			code, otp.SecondsRemaining(time.Now()))

		answer, err := ask(in, "  Does that match your authenticator? [Y/n]")
		if err != nil {
			return "", err
		}
		if answer == "" || strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
			fmt.Println()
			return secret, nil
		}
		fmt.Println("\n  Try again.")
	}
}

func envFile(secret string) string {
	return "# Base32 TOTP setup secret. The container generates the one-time code\n" +
		"# the VPN challenges for; nothing else reads this.\n" +
		"TOTP_SECRET=" + secret + "\n"
}

// writeSecret writes a credential: 0600, and through a temporary file so a
// crash cannot leave half a profile behind.
func writeSecret(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".vpnctl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// applyOrExplain puts the new credentials into effect if there is a daemon to
// tell, and otherwise says what to run.
func applyOrExplain(socketPath string) error {
	c := &ipc.Client{Path: socketPath, Timeout: 5 * time.Second}

	if _, err := c.Do(ipc.Request{Op: ipc.OpVersion}); err != nil {
		fmt.Println("Credentials are in place. Install the daemon to use them:")
		fmt.Println("  sudo vpnctl install")
		return nil
	}

	// The container carries its environment from creation, so new credentials
	// mean a new container rather than a restart of the old one. Asking for a
	// restart is enough: the daemon compares the running container against
	// the configuration and recreates it when they differ.
	if _, err := c.Do(ipc.Request{Op: ipc.OpRestart, Component: status.CompVPN}); err != nil {
		fmt.Printf("Credentials are in place, but the daemon did not accept a restart: %v\n", err)
		fmt.Println("Apply them with:  vpnctl restart vpn")
		return nil
	}

	fmt.Println("Credentials are in place and the VPN container is being recreated with them.")
	fmt.Println("Watch it come up with:  vpnctl status -w")
	return nil
}

func ask(in *bufio.Reader, prompt string) (string, error) {
	fmt.Printf("%s: ", prompt)
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// askSecret reads without echoing when there is a terminal, and falls back to
// a plain read when input is piped, so the command can still be scripted.
func askSecret(in *bufio.Reader, prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return ask(in, prompt)
	}

	fmt.Printf("%s: ", prompt)
	data, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[2:]), nil
}
