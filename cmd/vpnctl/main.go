// Command vpnctl supervises the split-routing stack: the VPN container, the
// split-horizon DNS router, the TCP racer and sing-box.
//
// The subcommands are split across cmd_*.go by the job they do. This file
// holds only the usage text and the dispatch.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"vpn-router/internal/config"
	"vpn-router/internal/singbox"
)

const usage = `vpnctl - split-routing supervisor for macOS

Usage:
  vpnctl install [flags]      set it up once as a launchd daemon (root)
  vpnctl stop                 switch the stack off, removing nothing
  vpnctl start                switch it back on
  vpnctl update [-check]      install the latest published release (root)
  vpnctl uninstall [-purge]   remove what install added; -purge drops the container too
  vpnctl setup                point it at your .ovpn profile and credentials
  vpnctl migrate <repo-dir>   copy the VPN profile, secrets and rules out of a source
                              checkout into the config directory (root)

  vpnctl daemon [flags]       supervise the whole stack (root; normally started by launchd)
  vpnctl status [-w]          show what every component is doing
  vpnctl logs [-f] [-source]  read the merged log of every component
  vpnctl restart [component]  restart vpn, singbox, dns-router, racer or all
  vpnctl retry                leave safe mode and try sing-box again
  vpnctl reload               apply the config file without restarting the daemon
  vpnctl resolver [on|off d]  list scoped resolver domains, or switch one

  vpnctl menubar              run the menu bar in the foreground
  vpnctl menubar -start       bring the installed menu bar back after quitting it
  vpnctl version              what this binary is, without asking the network
  vpnctl doctor               check the installation and say how to fix what is wrong
  vpnctl check [flags]        validate the config and the sing-box document it generates
  vpnctl gen-singbox [flags]  print the generated sing-box config.json
  vpnctl config-example       print the annotated default configuration
  vpnctl run-router [flags]   run just the DNS router and the racer in the foreground

Run "vpnctl <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "install":
		err = installCmd(os.Args[2:])
	case "uninstall":
		err = uninstallCmd(os.Args[2:])
	case "stop":
		err = stopCmd(os.Args[2:])
	case "start":
		err = startCmd(os.Args[2:])
	case "update":
		err = updateCmd(os.Args[2:])
	case "version", "--version", "-v":
		err = versionCmd(nil)
	case "migrate":
		err = migrateCmd(os.Args[2:])
	case "setup":
		err = setupCmd(os.Args[2:])
	case "config-example":
		err = configExampleCmd(os.Args[2:])
	case "doctor":
		err = doctorCmd(os.Args[2:])
	case "menubar":
		err = menubarCmd(os.Args[2:])
	case "daemon":
		err = daemon(os.Args[2:])
	case "singbox-shim":
		err = singbox.RunShim(os.Args[2:])
	case "status":
		err = statusCmd(os.Args[2:])
	case "logs":
		err = logsCmd(os.Args[2:])
	case "restart":
		err = restartCmd(os.Args[2:])
	case "retry":
		err = retryCmd(os.Args[2:])
	case "reload":
		err = reloadCmd(os.Args[2:])
	case "resolver":
		err = resolverCmd(os.Args[2:])
	case "run-router":
		err = runRouter(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	case "gen-singbox":
		err = genSingbox(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "vpnctl: %v\n", err)
		os.Exit(1)
	}
}

// loadConfig reads the config file when one is available, and otherwise falls
// back to the built-in defaults so the commands stay usable before
// "vpnctl install" has ever run.

func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		path = config.DefaultPath()
		if _, err := os.Stat(path); err != nil {
			cfg := config.Defaults()
			cwd, _ := os.Getwd()
			cfg.Path = "<defaults>"
			if err := cfg.Init(cwd); err != nil {
				return nil, err
			}
			return &cfg, nil
		}
	}
	return config.Load(path)
}

func routerProcessName() string {
	exe, err := os.Executable()
	if err != nil {
		return "vpnctl"
	}
	return filepath.Base(exe)
}

func generate(configPath string) (*config.Config, []byte, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, nil, err
	}

	in, err := singbox.FromConfig(cfg, routerProcessName())
	if err != nil {
		return nil, nil, err
	}

	out, err := singbox.Generate(in)
	if err != nil {
		return nil, nil, err
	}
	return cfg, out, nil
}
