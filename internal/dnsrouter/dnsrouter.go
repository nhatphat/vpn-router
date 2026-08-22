// Package dnsrouter is the split-horizon DNS server that sits behind
// sing-box's TUN (as its configured dns.servers upstream) on the macOS host.
//
// For every query it races two lookups in parallel:
//   - "public"   -> a normal public DNS resolver, dialed directly off the
//     physical interface so it bypasses the TUN's default route.
//   - "internal" -> the corporate DNS server pushed by the VPN, reached over
//     the container's SOCKS5 proxy using UDP ASSOCIATE.
//
// If the internal branch answers with a private/CGNAT IP, that answer wins
// immediately: sing-box's existing "private IP -> SOCKS" route rule then
// takes care of routing without ever needing a per-domain rule. Otherwise the
// public answer is used, falling back to a non-private internal answer, and
// finally to SERVFAIL if both branches fail.
package dnsrouter

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	"vpn-router/internal/netmon"
)

// Config is everything the DNS router needs. It mirrors the flags the
// standalone host-dns-router binary used to take.
type Config struct {
	Listen          string
	PublicDNS       string
	SocksAddr       string
	RefreshInterval time.Duration
	QueryTimeout    time.Duration
	GraceWindow     time.Duration

	// BindIP returns the source address for public DNS queries, re-read on
	// every query so a later interface change is picked up.
	BindIP netmon.IPFunc

	// Servers reports the DNS servers the VPN currently pushes. It is
	// injected rather than read here so this package never shells out: the
	// daemon runs as root, and on this platform the `docker` command is a
	// user-owned symlink into an application bundle.
	Servers ServerSource

	// Logf receives this component's log lines. Defaults to the standard
	// logger, which is what the standalone binary used.
	Logf func(string, ...any)
}

// ServerSource returns the current VPN-pushed DNS server addresses.
type ServerSource func(context.Context) ([]string, error)

// internalDNS tracks the VPN-pushed internal DNS server IPs (a VPN commonly
// pushes more than one, e.g. a primary/secondary pair), refreshed periodically
// from the injected source.
type internalDNS struct {
	mu     sync.RWMutex
	addrs  []string
	source ServerSource
	logf   func(string, ...any)
	// warned suppresses repeated "not available yet" lines during warmup.
	warned bool
}

// warmupInterval is how often to retry while no servers are known yet. The
// source can legitimately be unavailable at startup — the VPN container may
// not be located, or the tunnel may not have come up — and waiting a full
// refresh interval in that state would leave internal names unresolvable for
// half a minute after every start.
const warmupInterval = 2 * time.Second

func newInternalDNS(ctx context.Context, source ServerSource, interval time.Duration, logf func(string, ...any)) *internalDNS {
	d := &internalDNS{source: source, logf: logf}
	d.refresh(ctx)

	go func() {
		for {
			wait := interval
			if len(d.get()) == 0 && warmupInterval < interval {
				wait = warmupInterval
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
				d.refresh(ctx)
			}
		}
	}()

	return d
}

func (d *internalDNS) refresh(ctx context.Context) {
	if d.source == nil {
		return
	}

	addrs, err := d.source(ctx)
	if err != nil {
		d.mu.RLock()
		known := len(d.addrs)
		d.mu.RUnlock()
		if known > 0 {
			// Losing a working source is worth reporting every time.
			d.logf("internal-dns: refresh failed, keeping %d known server(s): %v", known, err)
		} else if !d.warned {
			// During warmup say it once instead of every couple of seconds.
			d.warned = true
			d.logf("internal-dns: not available yet (%v); retrying every %s", err, warmupInterval)
		}
		return
	}
	d.warned = false

	d.mu.Lock()
	defer d.mu.Unlock()

	if !equalStrings(addrs, d.addrs) {
		d.logf("internal-dns: servers changed %v -> %v", d.addrs, addrs)
		d.addrs = addrs
	}
}

func (d *internalDNS) get() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, len(d.addrs))
	copy(out, d.addrs)
	return out
}

func equalStrings(a, b []string) bool {
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

// resolver implements the dual-lookup + decision logic for one query.
type resolver struct {
	publicAddr   string
	bindIP       netmon.IPFunc
	socksAddr    string
	internal     *internalDNS
	queryTimeout time.Duration
	graceWindow  time.Duration
	logf         func(string, ...any)
}

var privateBlocks = mustParseCIDRs(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10", // CGNAT, also used by some corporate VPNs
	"fc00::/7",      // IPv6 ULA
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	blocks := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, block, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		blocks = append(blocks, block)
	}
	return blocks
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func firstIP(m *dns.Msg) net.IP {
	if m == nil {
		return nil
	}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			return v.A
		case *dns.AAAA:
			return v.AAAA
		}
	}
	return nil
}

func qname(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return "?"
	}
	return m.Question[0].Name
}

// queryPublic resolves m against the public resolver, binding the local
// source address to the physical interface so the query never gets recaptured
// by the TUN it is meant to bypass.
func (r *resolver) queryPublic(m *dns.Msg) (*dns.Msg, error) {
	dialer := &net.Dialer{Timeout: r.queryTimeout}
	if ip := r.bindIP(); ip != nil {
		dialer.LocalAddr = &net.UDPAddr{IP: ip}
	}

	conn, err := dialer.Dial("udp", r.publicAddr)
	if err != nil {
		return nil, fmt.Errorf("dial public dns: %w", err)
	}
	defer conn.Close()

	client := &dns.Client{Timeout: r.queryTimeout}
	resp, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
	return resp, err
}

// queryInternal resolves m against every VPN-pushed DNS server in parallel,
// tunneled over the container's SOCKS5 proxy using DNS-over-UDP. A VPN
// commonly pushes more than one server (primary/secondary); a private-IP
// answer from any of them wins immediately, otherwise the first successful
// answer is used.
func (r *resolver) queryInternal(m *dns.Msg) (*dns.Msg, error) {
	ips := r.internal.get()
	if len(ips) == 0 {
		return nil, fmt.Errorf("internal dns server not known yet")
	}

	type branch struct {
		resp *dns.Msg
		err  error
	}

	results := make(chan branch, len(ips))
	for _, ip := range ips {
		ip := ip
		go func() {
			resp, err := r.queryInternalAt(ip, m.Copy())
			results <- branch{resp, err}
		}()
	}

	var firstOK *branch
	var lastErr error
	for range ips {
		b := <-results
		if b.err != nil {
			lastErr = b.err
			continue
		}
		if isPrivateIP(firstIP(b.resp)) {
			return b.resp, nil
		}
		if firstOK == nil {
			bCopy := b
			firstOK = &bCopy
		}
	}

	if firstOK != nil {
		return firstOK.resp, nil
	}
	return nil, lastErr
}

func (r *resolver) queryInternalAt(ip string, m *dns.Msg) (*dns.Msg, error) {
	target := &net.UDPAddr{IP: net.ParseIP(ip), Port: 53}

	conn, err := socksUDPAssociate(r.socksAddr, target, r.queryTimeout)
	if err != nil {
		return nil, fmt.Errorf("udp associate to %s via socks: %w", ip, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(r.queryTimeout))

	client := &dns.Client{Timeout: r.queryTimeout}
	resp, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, fmt.Errorf("exchange with %s: %w", ip, err)
	}
	return resp, nil
}

type branchResult struct {
	resp *dns.Msg
	err  error
}

// resolve races both branches and applies the decision rules described in
// the package comment.
func (r *resolver) resolve(req *dns.Msg) *dns.Msg {
	publicCh := make(chan branchResult, 1)
	internalCh := make(chan branchResult, 1)

	go func() {
		resp, err := r.queryPublic(req.Copy())
		publicCh <- branchResult{resp, err}
	}()
	go func() {
		resp, err := r.queryInternal(req.Copy())
		internalCh <- branchResult{resp, err}
	}()

	var pub, intr branchResult
	pubDone, intrDone := false, false

	// Bounds how long we wait overall. Once public already has a good
	// answer, this shrinks to a short grace window instead of the full
	// query timeout: otherwise every ordinary public lookup would be
	// stalled by the internal branch's full timeout whenever the internal
	// resolver stays silent for out-of-zone domains (observed in practice).
	deadline := time.After(r.queryTimeout + 200*time.Millisecond)

	for !pubDone || !intrDone {
		select {
		case pub = <-publicCh:
			pubDone = true
			if pub.err == nil && pub.resp != nil && pub.resp.Rcode == dns.RcodeSuccess && !intrDone {
				deadline = time.After(r.graceWindow)
			}
		case intr = <-internalCh:
			intrDone = true
		case <-deadline:
			pubDone, intrDone = true, true
		}

		// Fast path: an internal/private answer is authoritative on its own,
		// no need to wait for the public branch.
		if intrDone && intr.err == nil && isPrivateIP(firstIP(intr.resp)) {
			break
		}
	}

	switch {
	case intr.err == nil && isPrivateIP(firstIP(intr.resp)):
		r.logf("%s -> internal/private %s (socks)", qname(req), firstIP(intr.resp))
		return intr.resp

	case pub.err == nil && pub.resp != nil && pub.resp.Rcode == dns.RcodeSuccess:
		r.logf("%s -> public %s (direct)", qname(req), firstIP(pub.resp))
		return pub.resp

	case intr.err == nil && intr.resp != nil && intr.resp.Rcode == dns.RcodeSuccess:
		r.logf("%s -> internal/non-private %s (socks fallback)", qname(req), firstIP(intr.resp))
		return intr.resp

	default:
		r.logf("%s -> failed (public_err=%v internal_err=%v)", qname(req), pub.err, intr.err)
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		return fail
	}
}

// Start runs the DNS server until ctx is cancelled.
func Start(ctx context.Context, cfg Config) error {
	bindIP := cfg.BindIP
	if bindIP == nil {
		bindIP = func() net.IP { return nil }
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}

	r := &resolver{
		publicAddr:   cfg.PublicDNS,
		bindIP:       bindIP,
		socksAddr:    cfg.SocksAddr,
		internal:     newInternalDNS(ctx, cfg.Servers, cfg.RefreshInterval, logf),
		queryTimeout: cfg.QueryTimeout,
		graceWindow:  cfg.GraceWindow,
		logf:         logf,
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) != 1 {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeFormatError)
			_ = w.WriteMsg(m)
			return
		}
		_ = w.WriteMsg(r.resolve(req))
	})

	server := &dns.Server{Addr: cfg.Listen, Net: "udp", Handler: mux}

	errCh := make(chan error, 1)
	go func() {
		logf("dns: listening on %s (udp), socks=%s", cfg.Listen, cfg.SocksAddr)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.ShutdownContext(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		return fmt.Errorf("dns server: %w", err)
	}
}
