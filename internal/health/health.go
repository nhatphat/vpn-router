// Package health answers the only question that matters for deciding whether
// to keep the stack running: can this machine reach the network, and is our
// own stack the reason it cannot?
//
// Watching processes is not enough. Every component can be alive while the
// machine is still unusable — sing-box holds the routes, so if the resolver or
// the racer those routes depend on stops answering, every lookup and every
// connection fails even though nothing has crashed. So three paths are probed
// and compared:
//
//	direct — bound to the physical interface, bypassing the TUN entirely.
//	         The control measurement: is the network reachable at all?
//	app    — an ordinary unbound connection by name, which follows the
//	         default route into the TUN. This is what an application
//	         experiences, and the only probe that covers sing-box.
//	chain  — our resolver and our racer, addressed directly on loopback.
//	         Diagnostic only: it says which half of the stack is at fault,
//	         and it keeps working even when sing-box is gone, which is
//	         precisely why it cannot be the probe that judges the stack.
//
// direct working while app fails is the signature of the stack breaking the
// machine, and it is the one case where the right response is to shut our own
// stack down rather than keep restarting it.
package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"

	"vpn-router/internal/netmon"
)

type Prober struct {
	// DirectTarget is dialled off the physical interface. A well-known
	// always-on TCP endpoint, not a name: resolving it would drag DNS into
	// what is meant to be the control measurement.
	DirectTarget string

	// DNSAddr is our own resolver, RacerAddr our own SOCKS5 racer.
	DNSAddr   string
	RacerAddr string

	// ChainName is resolved through DNSAddr and then connected to through
	// RacerAddr, so one probe covers both hops an application depends on.
	// It is also the name the app probe connects to.
	ChainName string
	ChainPort string

	BindIP  netmon.IPFunc
	Timeout time.Duration
}

type Verdict string

const (
	// VerdictHealthy: applications can reach the network.
	VerdictHealthy Verdict = "healthy"
	// VerdictStackBroken: reachable directly but not the way an application
	// goes. Our routing layer is the problem, and shutting it down restores
	// the machine.
	VerdictStackBroken Verdict = "stack-broken"
	// VerdictOffline: nothing is reachable. Not our problem; wait.
	VerdictOffline Verdict = "offline"
	// VerdictBindStale: applications are fine but the direct probe is not,
	// which usually means the address direct traffic binds to is no longer
	// valid — a network change we have not caught up with yet.
	VerdictBindStale Verdict = "bind-stale"
)

type Result struct {
	Verdict Verdict
	Direct  bool
	App     bool
	// Chain is diagnostic: it distinguishes "the resolver or racer is at
	// fault" from "sing-box is at fault", which decides what to restart.
	Chain     bool
	DirectErr error
	AppErr    error
	ChainErr  error
	Took      time.Duration
}

// Culprit names the half of the stack to act on when the verdict is
// stack-broken. An empty string means there is nothing to single out.
func (r Result) Culprit() string {
	if r.Verdict != VerdictStackBroken {
		return ""
	}
	if !r.Chain {
		return "resolver-or-racer"
	}
	return "singbox"
}

func (r Result) String() string {
	ok := func(b bool) string {
		if b {
			return "ok"
		}
		return "fail"
	}
	return fmt.Sprintf("%s (direct=%s app=%s chain=%s in %s)",
		r.Verdict, ok(r.Direct), ok(r.App), ok(r.Chain), r.Took.Round(time.Millisecond))
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout <= 0 {
		return 5 * time.Second
	}
	return p.Timeout
}

// Probe runs both measurements concurrently so a slow path cannot make the
// other look slow.
func (p *Prober) Probe(ctx context.Context) Result {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	directCh := make(chan error, 1)
	appCh := make(chan error, 1)
	chainCh := make(chan error, 1)

	go func() { directCh <- p.probeDirect(ctx) }()
	go func() { appCh <- p.probeApp(ctx) }()
	go func() { chainCh <- p.probeChain(ctx) }()

	directErr, appErr, chainErr := <-directCh, <-appCh, <-chainCh

	res := Result{
		Direct:    directErr == nil,
		App:       appErr == nil,
		Chain:     chainErr == nil,
		DirectErr: directErr,
		AppErr:    appErr,
		ChainErr:  chainErr,
		Took:      time.Since(start),
	}

	// The app path is what decides the verdict: it is the only one that
	// answers "can something on this machine actually use the network".
	switch {
	case res.App && res.Direct:
		res.Verdict = VerdictHealthy
	case res.App && !res.Direct:
		res.Verdict = VerdictBindStale
	case !res.App && res.Direct:
		res.Verdict = VerdictStackBroken
	default:
		res.Verdict = VerdictOffline
	}
	return res
}

// probeApp dials by name without binding a source address, so it resolves
// through whatever the system resolver is and routes through whatever the
// default route is — the TUN, when sing-box is running. It is the only probe
// that exercises the routing layer, and the only one whose failure means
// applications are broken.
func (p *Prober) probeApp(ctx context.Context) error {
	port := p.ChainPort
	if port == "" {
		port = "443"
	}
	target := net.JoinHostPort(p.ChainName, port)

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("app dial %s: %w", target, err)
	}
	conn.Close()
	return nil
}

// probeDirect dials off the physical interface. Binding the source address is
// what keeps this measurement independent: without it the connection would
// follow the default route straight back into the TUN it is meant to bypass,
// and the "control" would be measuring the very thing under test.
func (p *Prober) probeDirect(ctx context.Context) error {
	d := &net.Dialer{}
	if p.BindIP != nil {
		if ip := p.BindIP(); ip != nil {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}

	conn, err := d.DialContext(ctx, "tcp", p.DirectTarget)
	if err != nil {
		return fmt.Errorf("direct dial %s: %w", p.DirectTarget, err)
	}
	conn.Close()
	return nil
}

func (p *Prober) probeChain(ctx context.Context) error {
	if err := p.probeDNS(ctx); err != nil {
		return err
	}
	return p.probeRacer(ctx)
}

func (p *Prober) probeDNS(ctx context.Context) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(p.ChainName), dns.TypeA)

	c := &dns.Client{Net: "udp", Timeout: p.timeout()}
	resp, _, err := c.ExchangeContext(ctx, m, p.DNSAddr)
	if err != nil {
		return fmt.Errorf("dns probe via %s: %w", p.DNSAddr, err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dns probe via %s: rcode %s", p.DNSAddr, dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		return fmt.Errorf("dns probe via %s: empty answer for %s", p.DNSAddr, p.ChainName)
	}
	return nil
}

// probeRacer connects through the racer by name, so the racer performs its own
// resolution and race exactly as it does for real traffic.
func (p *Prober) probeRacer(ctx context.Context) error {
	port := p.ChainPort
	if port == "" {
		port = "443"
	}

	dialer, err := proxy.SOCKS5("tcp", p.RacerAddr, nil, &net.Dialer{Timeout: p.timeout()})
	if err != nil {
		return fmt.Errorf("build racer dialer: %w", err)
	}

	target := net.JoinHostPort(p.ChainName, port)

	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return errors.New("racer dialer does not support contexts")
	}

	conn, err := cd.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("racer dial %s via %s: %w", target, p.RacerAddr, err)
	}
	conn.Close()
	return nil
}
