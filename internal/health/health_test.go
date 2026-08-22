package health

import (
	"context"
	"net"
	"testing"
	"time"

	"vpn-router/internal/netmon"
)

func listening(t *testing.T, network, addr string) bool {
	t.Helper()
	c, err := net.DialTimeout(network, addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// TestVerdictTable runs the real Probe against listeners rigged to make each
// probe pass or fail, so the decision table is exercised through the code the
// supervisor actually calls rather than a copy of its logic.
func TestVerdictTable(t *testing.T) {
	open := openPort(t)     // accepts: probe succeeds
	closed := "127.0.0.1:1" // refuses: probe fails

	cases := []struct {
		name        string
		direct, app string
		wantVerdict Verdict
		wantCulprit string
	}{
		{"both work", open, open, VerdictHealthy, ""},
		{"apps broken, network fine", open, closed, VerdictStackBroken, "resolver-or-racer"},
		{"apps fine, bind address stale", closed, open, VerdictBindStale, ""},
		{"machine offline", closed, closed, VerdictOffline, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, port, err := net.SplitHostPort(c.app)
			if err != nil {
				t.Fatal(err)
			}
			p := &Prober{
				DirectTarget: c.direct,
				DNSAddr:      "127.0.0.1:1", // chain always fails here
				RacerAddr:    "127.0.0.1:1",
				ChainName:    host,
				ChainPort:    port,
				Timeout:      2 * time.Second,
			}
			res := p.Probe(context.Background())
			if res.Verdict != c.wantVerdict {
				t.Errorf("verdict = %s, want %s (%s)", res.Verdict, c.wantVerdict, res)
			}
			if got := res.Culprit(); got != c.wantCulprit {
				t.Errorf("culprit = %q, want %q", got, c.wantCulprit)
			}
		})
	}
}

// openPort returns the address of a listener that accepts and immediately
// closes, standing in for a reachable endpoint.
func openPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}

// TestProbeAgainstRunningStack measures the stack that is actually running on
// this machine, if it is.
func TestProbeAgainstRunningStack(t *testing.T) {
	const (
		dnsAddr   = "127.0.0.1:15353"
		racerAddr = "127.0.0.1:15080"
	)

	if !listening(t, "tcp", racerAddr) {
		t.Skipf("racer not listening on %s", racerAddr)
	}

	bindIP, resolved, err := netmon.Static("en0")
	if err != nil {
		t.Skipf("no en0: %v", err)
	}
	t.Logf("binding direct probe to %s", resolved)

	p := &Prober{
		DirectTarget: "1.1.1.1:443",
		DNSAddr:      dnsAddr,
		RacerAddr:    racerAddr,
		ChainName:    "example.com",
		BindIP:       bindIP,
		Timeout:      8 * time.Second,
	}

	res := p.Probe(context.Background())
	t.Logf("verdict: %s", res)
	for label, err := range map[string]error{
		"direct": res.DirectErr, "app": res.AppErr, "chain": res.ChainErr,
	} {
		if err != nil {
			t.Logf("%s error: %v", label, err)
		}
	}

	if res.Verdict != VerdictHealthy {
		t.Errorf("running stack is not healthy: %s", res)
	}
}

// TestProbeDetectsBrokenChain points the chain probe at closed ports, which
// must produce the one verdict that makes the supervisor shut sing-box down.
func TestProbeDetectsBrokenChain(t *testing.T) {
	bindIP, _, err := netmon.Static("en0")
	if err != nil {
		t.Skipf("no en0: %v", err)
	}

	p := &Prober{
		DirectTarget: "1.1.1.1:443",
		DNSAddr:      "127.0.0.1:1", // nothing here
		RacerAddr:    "127.0.0.1:1",
		ChainName:    "example.com",
		BindIP:       bindIP,
		Timeout:      3 * time.Second,
	}

	res := p.Probe(context.Background())
	if !res.Direct {
		t.Skipf("no direct connectivity to judge against: %v", res.DirectErr)
	}
	if res.Chain {
		t.Errorf("chain probe unexpectedly succeeded against a closed port")
	}
	if res.Verdict == VerdictHealthy && res.Culprit() != "" {
		t.Errorf("healthy verdict should name no culprit, got %q", res.Culprit())
	}
}
