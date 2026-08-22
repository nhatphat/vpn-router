package supervisor

import (
	"fmt"
	"reflect"

	"vpn-router/internal/config"
	"vpn-router/internal/logbus"
	"vpn-router/internal/singbox"
	"vpn-router/internal/status"
)

// Reload re-reads the configuration file and applies it.
//
// The order matters. The new file is parsed, the sing-box document is
// regenerated and validated by sing-box itself, and only then is anything
// swapped in — so a configuration that would not start cannot take the routing
// layer down. Components whose settings did not change are left alone, because
// the cheapest reload is the one that restarts nothing: restarting sing-box
// drops the tunnel and every connection through it.
func (s *Supervisor) Reload() (*status.ReloadResult, error) {
	old := s.cfg()

	if old.Path == "" || old.Path == "<defaults>" {
		return nil, fmt.Errorf("this daemon was started without a config file, so there is nothing to reload")
	}

	fresh, err := config.Load(old.Path)
	if err != nil {
		return nil, fmt.Errorf("the config was not applied: %w", err)
	}

	in, err := singbox.FromConfig(fresh, s.o.RouterProcess)
	if err != nil {
		return nil, fmt.Errorf("the config was not applied: %w", err)
	}
	doc, err := singbox.Generate(in)
	if err != nil {
		return nil, fmt.Errorf("the config was not applied: %w", err)
	}

	if err := singbox.Validate(s.o.SingBoxBinary, doc); err != nil {
		return nil, fmt.Errorf("the config was not applied: %w", err)
	}

	affected := Affected(old, fresh, !bytesEqual(s.sb.Document(), doc))

	result := &status.ReloadResult{
		ConfigPath: old.Path,
		Restarted:  affected.Components,
		Disruptive: affected.SingBox,
	}

	// Swap first: every component reads the configuration when it starts, so
	// the new values have to be in place before anything is restarted.
	s.current.Store(fresh)

	if old.DNSRouter.BindInterface != fresh.DNSRouter.BindInterface {
		s.refreshBindAddress()
	}

	// Scoped resolvers name the daemon's own port, so both the list and the
	// address can invalidate them.
	if !reflect.DeepEqual(old.DNSRouter.ResolverDomains, fresh.DNSRouter.ResolverDomains) ||
		old.DNSRouter.Listen != fresh.DNSRouter.Listen {
		s.applyResolvers()
	}

	for _, name := range affected.Components {
		if name == status.CompSingBox {
			s.sb.SetDocument(doc)
			s.sb.Restart()
			continue
		}
		s.signalRestart(name)
	}

	if len(result.Restarted) == 0 {
		s.logf(logbus.LevelInfo, "reloaded %s: no effective change", old.Path)
	} else {
		s.logf(logbus.LevelInfo, "reloaded %s: restarting %v", old.Path, result.Restarted)
	}

	return result, nil
}

// Change describes what a configuration change touches.
type Change struct {
	// Components are restarted, in the order they appear.
	Components []string
	// SingBox is true when the routing layer is among them, which is the
	// only disruptive case: dropping the TUN resets every connection through
	// it, while the other components are loopback listeners.
	SingBox bool
}

// Affected decides which components a configuration change reaches.
//
// The point of being specific is that the cheapest reload restarts nothing.
// Each component is matched against the settings it actually reads, so
// editing a racer timeout does not drop the tunnel, and editing the TUN does
// not disturb the resolver.
func Affected(old, fresh *config.Config, singboxDocChanged bool) Change {
	var c Change

	// The SOCKS endpoint is read by all three host-side components, which is
	// why it appears in each comparison rather than only under docker.
	socksChanged := old.Docker.Socks != fresh.Docker.Socks

	if !reflect.DeepEqual(old.DNSRouter, fresh.DNSRouter) ||
		socksChanged ||
		old.Docker.VPNDNSFile != fresh.Docker.VPNDNSFile {
		c.Components = append(c.Components, status.CompDNSRouter)
	}

	if !reflect.DeepEqual(old.Racer, fresh.Racer) || socksChanged {
		c.Components = append(c.Components, status.CompRacer)
	}

	// The container is recreated by the watcher, which derives its
	// specification from these fields.
	if !reflect.DeepEqual(old.VPN, fresh.VPN) ||
		old.Docker.Container != fresh.Docker.Container ||
		old.Docker.Host != fresh.Docker.Host ||
		socksChanged {
		c.Components = append(c.Components, status.CompVPN)
	}

	if singboxDocChanged {
		c.Components = append(c.Components, status.CompSingBox)
		c.SingBox = true
	}

	return c
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
