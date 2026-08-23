package installer

import (
	"context"
	"fmt"
	"os"
	"time"

	"vpn-router/internal/dockerctl"
	"vpn-router/internal/vpnbox"
)

// Stop takes the whole stack down without removing anything.
//
// It exists because the only way to stop using vpnctl used to be to uninstall
// it, which is far too much: uninstalling drops the launchd jobs, the managed
// binaries and the scoped resolvers, and getting back means downloading and
// installing again. Wanting the machine's own networking back for an hour is
// an ordinary thing to want.
//
// Everything installed stays installed. The daemon exits, which takes sing-box
// and the TUN with it, so the machine returns to routing its own traffic.
func Stop(o Options) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("stopping the daemon needs root:\n  sudo vpnctl stop")
	}

	if err := bootoutDaemon(); err != nil {
		o.logf("unloading the daemon: %v", err)
	} else {
		o.logf("daemon stopped; the machine is routing its own traffic again")
	}

	if target, err := ResolveTarget(); err == nil {
		if err := bootoutAgent(target); err == nil {
			o.logf("menu bar stopped")
		}
	}

	stopContainer(o)

	o.logf("nothing was removed. Start it again with: sudo vpnctl start")
	return nil
}

// Start puts back what Stop took down.
func Start(o Options) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("starting the daemon needs root:\n  sudo vpnctl start")
	}

	if _, err := os.Stat(DaemonPlist); err != nil {
		return fmt.Errorf("vpnctl is not installed on this machine:\n  sudo vpnctl install")
	}

	// The container comes back on its own: the daemon creates or starts it
	// once the container runtime answers.
	if err := bootstrapDaemon(); err != nil {
		return fmt.Errorf("load the daemon: %w", err)
	}
	o.logf("daemon started")

	if err := waitForDaemon(15 * time.Second); err != nil {
		o.logf("daemon started, but it has not answered yet: %v", err)
	} else {
		o.logf("daemon answering")
	}

	if target, err := ResolveTarget(); err == nil {
		if _, statErr := os.Stat(target.AgentPlist()); statErr == nil {
			if err := bootstrapAgent(target); err != nil {
				o.logf("menu bar not started now (%v); it will start at next login", err)
			} else {
				o.logf("menu bar started")
			}
		}
	}

	return nil
}

// stopContainer stops the VPN container too, since "stop using vpnctl"
// reasonably means the tunnel goes away and its published port with it. It is
// stopped, not removed, so starting again costs nothing.
func stopContainer(o Options) {
	c, err := dockerctl.New("")
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := c.Ping(ctx); err != nil {
		return
	}

	list, err := c.ListByLabel(ctx, vpnbox.LabelOwner+"=true")
	if err != nil {
		return
	}

	for _, ct := range list {
		if ct.State != "running" {
			continue
		}
		if err := c.Stop(ctx, ct.ID, 15*time.Second); err != nil {
			o.logf("could not stop %s: %v", ct.Name(), err)
			continue
		}
		o.logf("VPN container %s stopped", ct.Name())
	}
}
