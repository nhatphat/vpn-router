package main

import (
	"errors"
	"flag"
	"fmt"

	"vpn-router/internal/config"
	"vpn-router/internal/installer"
	"vpn-router/internal/ipc"
	"vpn-router/internal/status"
)

// resolverCmd is the command-line half of the menu bar's checkboxes. It exists
// so the same change can be scripted, and so a machine with no menu bar
// running is not stuck editing the config by hand.
func resolverCmd(args []string) error {
	fs := flag.NewFlagSet("resolver", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yaml")
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
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

	switch fs.Arg(0) {
	case "", "list":
		return listResolvers(*socketPath, path)
	case "on":
		return setResolver(*socketPath, path, fs.Arg(1), true)
	case "off":
		return setResolver(*socketPath, path, fs.Arg(1), false)
	default:
		return fmt.Errorf("unknown subcommand %q; use list, on or off", fs.Arg(0))
	}
}

// listResolvers reads the declaration from the config and the effect from the
// daemon, rather than trusting either alone.
//
// The config is what is asked for and is always available. The daemon knows
// what is actually installed, which the config cannot say — but a daemon that
// answers without that detail (an older one, or one that has not applied the
// list yet) must not turn into "nothing is configured".
func listResolvers(socketPath, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	declared := cfg.DNSRouter.ResolverDomains
	if len(declared) == 0 {
		fmt.Println("no resolver domains configured")
		fmt.Printf("\nAdd one under dns_router.resolver_domains in %s, then: vpnctl reload\n", configPath)
		return nil
	}

	effect := map[string]status.Resolver{}
	known := false
	if resp, err := client(socketPath).Do(ipc.Request{Op: ipc.OpStatus}); err == nil && resp.Status != nil {
		for _, r := range resp.Status.Resolvers {
			effect[r.Domain] = r
			known = true
		}
	}

	for _, d := range declared {
		state := "off"
		if d.Enabled {
			state = "on"
		}

		note := ""
		if r, ok := effect[d.Domain]; ok {
			switch {
			case r.Foreign:
				note = "  (answered by a file vpnctl did not write)"
			case r.Enabled && !r.Installed:
				note = "  (not installed yet)"
			case !r.Enabled && r.Installed:
				note = "  (still installed)"
			}
		} else if !known {
			note = "  (the daemon has not reported on this one)"
		}

		fmt.Printf("  %-4s %s%s\n", state, d.Domain, note)
	}
	return nil
}

func setResolver(socketPath, configPath, domain string, enabled bool) error {
	if domain == "" {
		return errors.New("name a domain, e.g.\n  vpnctl resolver off corp.example.com")
	}

	if _, err := config.ToggleResolverDomain(configPath, domain, enabled); err != nil {
		return err
	}

	// Written, but not yet in effect: the daemon owns /etc/resolver.
	if _, err := client(socketPath).Do(ipc.Request{Op: ipc.OpReload}); err != nil {
		return fmt.Errorf("saved to %s, but the daemon did not apply it: %w", configPath, err)
	}

	if enabled {
		fmt.Printf("%s is on, resolved through vpnctl\n", domain)
	} else {
		fmt.Printf("%s is off, its scoped resolver removed\n", domain)
	}
	return nil
}
