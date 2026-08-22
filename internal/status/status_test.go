package status

import "testing"

func comp(name string, phase Phase) Component {
	return Component{Name: name, Phase: phase, Detail: "detail"}
}

// TestAggregatePrefersPublicConnectivity encodes the design decision that the
// VPN being down is not an emergency — public traffic still works and VPN
// traffic is meant to fail closed — while the routing layer being down is.
func TestAggregatePrefersPublicConnectivity(t *testing.T) {
	cases := []struct {
		name  string
		comps []Component
		want  Overall
	}{
		{
			name:  "everything running",
			comps: []Component{comp(CompVPN, PhaseRunning), comp(CompSingBox, PhaseRunning), comp(CompDNSRouter, PhaseRunning), comp(CompRacer, PhaseRunning)},
			want:  OverallGreen,
		},
		{
			name:  "vpn down is only a warning",
			comps: []Component{comp(CompVPN, PhaseDegraded), comp(CompSingBox, PhaseRunning), comp(CompDNSRouter, PhaseRunning), comp(CompRacer, PhaseRunning)},
			want:  OverallYellow,
		},
		{
			name:  "container runtime missing before login is a warning",
			comps: []Component{comp(CompVPN, PhaseUnavailable), comp(CompSingBox, PhaseRunning), comp(CompDNSRouter, PhaseRunning), comp(CompRacer, PhaseRunning)},
			want:  OverallYellow,
		},
		{
			name:  "safe mode is red",
			comps: []Component{comp(CompVPN, PhaseRunning), comp(CompSingBox, PhaseSafeMode), comp(CompDNSRouter, PhaseRunning), comp(CompRacer, PhaseRunning)},
			want:  OverallRed,
		},
		{
			name:  "resolver failed is red even with a healthy vpn",
			comps: []Component{comp(CompVPN, PhaseRunning), comp(CompSingBox, PhaseRunning), comp(CompDNSRouter, PhaseFailed), comp(CompRacer, PhaseRunning)},
			want:  OverallRed,
		},
		{
			name:  "racer backing off is a warning",
			comps: []Component{comp(CompVPN, PhaseRunning), comp(CompSingBox, PhaseRunning), comp(CompDNSRouter, PhaseRunning), comp(CompRacer, PhaseBackoff)},
			want:  OverallYellow,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := Aggregate(c.comps)
			if got != c.want {
				t.Errorf("Aggregate = %q (%s), want %q", got, reason, c.want)
			}
			if reason == "" {
				t.Error("Aggregate returned an empty reason")
			}
		})
	}
}
