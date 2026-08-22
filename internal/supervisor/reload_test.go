package supervisor

import (
	"strings"
	"testing"
	"time"

	"vpn-router/internal/config"
	"vpn-router/internal/status"
)

func base() *config.Config {
	c := config.Defaults()
	return &c
}

func names(c Change) string { return strings.Join(c.Components, ",") }

// TestAffectedRestartsOnlyWhatChanged is the property that makes reload worth
// having: restarting sing-box drops the tunnel and every connection through
// it, so an unrelated edit must not cause one.
func TestAffectedRestartsOnlyWhatChanged(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*config.Config)
		docChanged bool
		want       string
		disruptive bool
	}{
		{
			name:   "nothing changed",
			mutate: func(*config.Config) {},
			want:   "",
		},
		{
			name:   "racer timeout",
			mutate: func(c *config.Config) { c.Racer.DialTimeout = config.Duration(3 * time.Second) },
			want:   status.CompRacer,
		},
		{
			name:   "dns grace window",
			mutate: func(c *config.Config) { c.DNSRouter.GraceWindow = config.Duration(400 * time.Millisecond) },
			want:   status.CompDNSRouter,
		},
		{
			name:   "shared file path",
			mutate: func(c *config.Config) { c.Docker.VPNDNSFile = "/tmp/elsewhere" },
			want:   status.CompDNSRouter,
		},
		{
			name:   "vpn profile",
			mutate: func(c *config.Config) { c.VPN.Config = "/tmp/other.ovpn" },
			want:   status.CompVPN,
		},
		{
			// The SOCKS endpoint is read by every host-side component, so
			// moving it has to reach all of them.
			name:   "socks endpoint",
			mutate: func(c *config.Config) { c.Docker.Socks = "127.0.0.1:2080" },
			want:   status.CompDNSRouter + "," + status.CompRacer + "," + status.CompVPN,
		},
		{
			name:       "tun settings",
			mutate:     func(c *config.Config) { c.SingBox.TUN.MTU = 1500 },
			docChanged: true,
			want:       status.CompSingBox,
			disruptive: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old, fresh := base(), base()
			tc.mutate(fresh)

			got := Affected(old, fresh, tc.docChanged)
			if names(got) != tc.want {
				t.Errorf("restarted %q, want %q", names(got), tc.want)
			}
			if got.SingBox != tc.disruptive {
				t.Errorf("disruptive = %v, want %v", got.SingBox, tc.disruptive)
			}
		})
	}
}

// TestAffectedTreatsOnlySingBoxAsDisruptive documents why the distinction
// exists: the other components are loopback listeners, and restarting them
// does not touch the machine's routing.
func TestAffectedTreatsOnlySingBoxAsDisruptive(t *testing.T) {
	old, fresh := base(), base()
	fresh.Racer.DialTimeout = config.Duration(9 * time.Second)
	fresh.DNSRouter.PublicDNS = "9.9.9.9:53"
	fresh.VPN.RetryDelay = config.Duration(30 * time.Second)

	got := Affected(old, fresh, false)
	if got.SingBox {
		t.Error("changes to the loopback components should not be reported as disruptive")
	}
	if len(got.Components) != 3 {
		t.Errorf("expected all three non-routing components, got %v", got.Components)
	}
}
