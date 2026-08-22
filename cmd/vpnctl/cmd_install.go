package main

import (
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"path/filepath"

	"vpn-router/internal/installer"
)

// --- install / uninstall ---

func installCmd(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	configPath := fs.String("config", "", "config path to install (default: the invoking user's ~/.config/vpnctl/config.yaml)")
	from := fs.String("from", "", "copy this local sing-box binary instead of downloading one")
	fromBrew := fs.Bool("from-path", false, "copy the sing-box already on PATH instead of downloading one")
	withMenuBar := fs.Bool("menubar", true, "install the per-user menu bar agent")
	keepStopped := fs.Bool("keep-stopped", false, "install the files but do not start the daemon")
	if err := fs.Parse(args); err != nil {
		return err
	}

	source := *from
	if source == "" && *fromBrew {
		found, err := exec.LookPath("sing-box")
		if err != nil {
			return fmt.Errorf("-from-path given but no sing-box on PATH: %w", err)
		}
		source = found
	}

	opts := installer.Options{
		ConfigPath:  *configPath,
		SingBoxFrom: source,
		WithMenuBar: *withMenuBar,
		KeepStopped: *keepStopped,
		Logf:        func(format string, a ...any) { fmt.Printf("  "+format+"\n", a...) },
	}

	fmt.Println("Installing vpnctl:")
	if err := installer.Install(opts); err != nil {
		return err
	}

	record, _ := installer.LoadRecord()
	fmt.Println("\nDone. What to do next:")
	if record != nil {
		fmt.Printf("  1. Check the config:            %s\n", record.ConfigPath)
	}
	fmt.Println("  2. Point it at your VPN profile and auth file if they are not there yet.")
	fmt.Println("  3. Watch it come up:            vpnctl status -w")
	fmt.Println("     Read the merged log:         vpnctl logs -f")
	fmt.Println("\nNo further password prompts: the daemon is resident, so restarts from the")
	fmt.Println("menu bar or the CLI do not need authorisation again.")
	return nil
}

func uninstallCmd(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also delete the VPN container, its image and the logs")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Println("Removing vpnctl:")
	if err := installer.Uninstall(installer.Options{
		Purge: *purge,
		Logf:  func(format string, a ...any) { fmt.Printf("  "+format+"\n", a...) },
	}); err != nil {
		return err
	}

	fmt.Println("\nYour config and credentials are untouched. Reinstall with:")
	fmt.Println("  curl -fsSL https://raw.githubusercontent.com/nhatphat/vpn-router/main/install.sh | sh")
	return nil
}

func migrateCmd(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	configPath := fs.String("config", "", "config path (default: the invoking user's ~/.config/vpnctl/config.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return errors.New("give the source checkout to migrate from, e.g.\n  sudo vpnctl migrate ~/src/vpn-router")
	}

	repo, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}

	fmt.Printf("Migrating runtime files out of %s:\n", repo)
	if err := installer.Migrate(repo, installer.Options{
		ConfigPath: *configPath,
		Logf:       func(format string, a ...any) { fmt.Printf("  "+format+"\n", a...) },
	}); err != nil {
		return err
	}

	fmt.Println("\nThe installation no longer reads anything from the checkout.")
	fmt.Println("Apply it with:  sudo vpnctl install   (rebuilds the container from the new paths)")
	return nil
}
