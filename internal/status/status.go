// Package status is the vocabulary the supervisor, the IPC layer and the UI
// share for describing what the stack is doing.
package status

import "time"

type Phase string

const (
	// PhaseStopped means not running and not trying to.
	PhaseStopped Phase = "stopped"
	// PhaseStarting means launched but not yet confirmed working.
	PhaseStarting Phase = "starting"
	// PhaseRunning means alive and behaving.
	PhaseRunning Phase = "running"
	// PhaseDegraded means alive but not fully functional — the public path
	// works while the VPN path does not, for instance.
	PhaseDegraded Phase = "degraded"
	// PhaseBackoff means it exited and a retry is scheduled.
	PhaseBackoff Phase = "backoff"
	// PhaseFailed means it cannot run and no retry is scheduled.
	PhaseFailed Phase = "failed"
	// PhaseSafeMode means retries were abandoned on purpose to protect the
	// machine's networking. The stack stays down until asked again.
	PhaseSafeMode Phase = "safemode"
	// PhaseUnavailable means a dependency outside our control is missing,
	// such as the container runtime before the user has logged in.
	PhaseUnavailable Phase = "unavailable"
)

// Overall is the single colour the menu bar shows.
type Overall string

const (
	OverallGreen  Overall = "green"
	OverallYellow Overall = "yellow"
	OverallRed    Overall = "red"
)

const (
	CompVPN       = "vpn"
	CompSingBox   = "singbox"
	CompDNSRouter = "dns-router"
	CompRacer     = "racer"
)

type Component struct {
	Name     string    `json:"name"`
	Phase    Phase     `json:"phase"`
	Detail   string    `json:"detail"`
	Since    time.Time `json:"since"`
	Restarts int       `json:"restarts"`
	LastErr  string    `json:"last_error,omitempty"`
}

// Resolver is one scoped resolver: what the config asks for, and what is
// actually in place. The two can differ — a file deleted by hand, or a config
// edited but not yet applied — and a display that showed only intent would be
// telling people what should be true rather than what is.
type Resolver struct {
	Domain string `json:"domain"`
	// Enabled is the configured intent.
	Enabled bool `json:"enabled"`
	// Installed is whether a scoped resolver written by us is in place.
	Installed bool `json:"installed"`
	// Foreign is whether a file exists for this suffix that we did not write,
	// and so will not touch.
	Foreign bool `json:"foreign"`
}

// InEffect reports whether names under this suffix currently reach us.
func (r Resolver) InEffect() bool { return r.Installed || r.Foreign }

type Snapshot struct {
	Overall    Overall     `json:"overall"`
	Reason     string      `json:"reason"`
	Components []Component `json:"components"`
	Resolvers  []Resolver  `json:"resolvers,omitempty"`
	// Paused means the stack was switched off deliberately. It is not a
	// failure, and a display that showed it as one would send people looking
	// for a fault they caused.
	Paused bool `json:"paused"`
	// Generation increments whenever the network path underneath the stack
	// changed (VPN restarted, tunnel flapped, interface address changed,
	// VPN-pushed DNS servers changed).
	Generation uint64    `json:"generation"`
	Since      time.Time `json:"since"`
	Version    string    `json:"version"`
}

// Aggregate reduces component phases to one colour.
//
// The rule follows the design principle that public connectivity matters more
// than VPN connectivity: sing-box down is red because it means the routing
// layer is gone, while the VPN being down is only yellow, since public
// traffic keeps working and VPN traffic is meant to fail closed.
func Aggregate(comps []Component) (Overall, string) {
	return aggregate(comps, false)
}

// AggregatePaused reports the state of a stack that was switched off on
// purpose. It is deliberately not an error: showing a fault for something
// somebody chose sends them looking for a problem they created.
func AggregatePaused() (Overall, string) {
	return OverallYellow, "paused — run \"vpnctl start\" to route traffic again"
}

func aggregate(comps []Component, paused bool) (Overall, string) {
	if paused {
		return AggregatePaused()
	}

	byName := make(map[string]Component, len(comps))
	for _, c := range comps {
		byName[c.Name] = c
	}

	critical := []string{CompSingBox, CompDNSRouter, CompRacer}
	for _, name := range critical {
		c, ok := byName[name]
		if !ok {
			continue
		}
		switch c.Phase {
		case PhaseSafeMode:
			return OverallRed, name + " in safe mode: " + c.Detail
		case PhaseFailed:
			return OverallRed, name + " failed: " + firstNonEmpty(c.LastErr, c.Detail)
		case PhaseBackoff, PhaseStarting:
			return OverallYellow, name + " " + string(c.Phase)
		}
	}

	if vpn, ok := byName[CompVPN]; ok {
		switch vpn.Phase {
		case PhaseRunning:
		case PhaseUnavailable:
			return OverallYellow, "container runtime unavailable: " + vpn.Detail
		default:
			return OverallYellow, "vpn " + string(vpn.Phase) + ": " + firstNonEmpty(vpn.Detail, vpn.LastErr)
		}
	}

	return OverallGreen, "all components running"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ReloadResult reports what a configuration reload changed.
type ReloadResult struct {
	ConfigPath string `json:"config_path"`
	// Restarted names the components whose settings changed. An empty list
	// means the file parsed to the same configuration already running.
	Restarted []string `json:"restarted"`
	// Disruptive is true when the routing layer had to restart, which drops
	// the tunnel interface for a moment.
	Disruptive bool `json:"disruptive"`
}
