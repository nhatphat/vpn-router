package main

import (
	"flag"
	"fmt"

	"vpn-router/internal/config"
	"vpn-router/internal/installer"
	"vpn-router/internal/ipc"
	"vpn-router/internal/ui/menubar"
)

// menubarCmd runs the menu bar. It never returns: the menu bar owns the main
// goroutine, because a status item has to live on the process's first thread.
func menubarCmd(args []string) error {
	fs := flag.NewFlagSet("menubar", flag.ExitOnError)
	start := fs.Bool("start", false, "bring the installed menu bar back after its Quit item was used")
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
	webListen := fs.String("web-listen", "", "address for the log page (default: from the config)")
	configPath := fs.String("config", "", "config path, for the Open config item")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *start {
		return startInstalledMenuBar()
	}

	opts := menubar.Options{
		SocketPath: *socketPath,
		WebListen:  *webListen,
		ConfigPath: *configPath,
	}

	// The menu bar runs as the user and holds no configuration of its own, so
	// it takes what it needs from the installation record and, failing that,
	// from the config the daemon was pointed at.
	if opts.ConfigPath == "" {
		if rec, err := installer.LoadRecord(); err == nil {
			opts.ConfigPath = rec.ConfigPath
		}
	}
	if opts.WebListen == "" {
		if cfg, err := loadConfig(opts.ConfigPath); err == nil {
			opts.WebListen = cfg.UI.WebListen
		} else {
			opts.WebListen = config.Defaults().UI.WebListen
		}
	}

	return menubar.Run(opts)
}

// startInstalledMenuBar restarts the LaunchAgent rather than running a second
// copy in this terminal, so the one launchd manages is the one on screen.
func startInstalledMenuBar() error {
	rec, err := installer.LoadRecord()
	if err != nil {
		return fmt.Errorf("no installation record, so there is no menu bar job to start: %w\n\n"+
			"Run it in the foreground instead:\n  vpnctl menubar", err)
	}

	if !installer.AgentLoaded(rec.UID) {
		return fmt.Errorf("launchd has no menu bar job for uid %d\n\nInstall it with:\n  sudo vpnctl install", rec.UID)
	}

	target := &installer.Target{UID: rec.UID}
	if err := installer.StartAgent(target); err != nil {
		return err
	}

	fmt.Println("menu bar started")
	return nil
}
