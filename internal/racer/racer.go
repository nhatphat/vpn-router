// Package racer implements tier 2: a local SOCKS5 server that sing-box routes
// "ambiguous" destinations to (public-looking IPs that the DNS-based tier 1
// classifier cannot tell apart from ones that actually need the VPN, e.g. a
// real domain whose IP is only reachable when the traffic originates from
// inside the VPN).
//
// For every new destination it dials "direct" (bound to the physical
// interface, bypassing the TUN) and "socks" (via the VPN container's SOCKS5
// proxy) concurrently. Direct is preferred: it wins as soon as it connects,
// and socks only wins if direct has failed outright or is still pending after
// a head start. The loser is discarded. Because sing-box's TUN already
// completed the local handshake with the calling app before this ever runs,
// the app sees the connection succeed immediately regardless of which path
// wins — it only sees a failure if both do. The winning path is remembered
// per destination so later connections to the same destination skip the
// race entirely.
package racer

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"golang.org/x/net/proxy"

	"vpn-router/internal/netmon"
)

// Config is everything the racer needs. It mirrors the flags the standalone
// host-dns-router binary used to take.
type Config struct {
	Listen      string
	SocksAddr   string
	DialTimeout time.Duration

	// BindIP returns the source address for direct dials, re-read on every
	// dial so a later interface change is picked up.
	BindIP netmon.IPFunc

	// RelayBuffer is how much data one read-write cycle moves; see
	// config.Racer.RelayBuffer for why it decides throughput.
	RelayBuffer int

	// Generation reports which network the machine is currently on. A path
	// learned on one network says nothing about another.
	Generation func() uint64

	// LearnedTTL bounds how long a path is trusted without re-checking, so a
	// change nothing else noticed still expires on its own.
	LearnedTTL time.Duration

	// DirectHeadStart is how long a connected socks dial waits for direct
	// before it is used anyway. Zero makes it a plain first-to-connect race.
	DirectHeadStart time.Duration

	// ProvisionalTTL bounds how long socks is trusted when it won only
	// because direct was slow, not because direct failed. Zero falls back to
	// LearnedTTL.
	ProvisionalTTL time.Duration

	// Logf receives this component's log lines. Defaults to the standard
	// logger, which is what the standalone binary used.
	Logf func(string, ...any)
}

// learnedPath is a decision and the circumstances it was made under.
//
// The decision alone is not enough to reuse. "Direct reached this address"
// was true of the network the machine was on at the time, and a laptop
// changes networks: the office, home, a tunnel coming up. Reusing it blindly
// is how a destination that now needs the VPN keeps going out directly —
// which fails silently rather than loudly, because a public address usually
// still accepts the connection.
type learnedPath struct {
	via string
	gen uint64
	at  time.Time

	// ttl overrides the racer's time limit for this entry; zero means use it.
	// A socks win over a direct dial that was merely slow is set shorter,
	// because on a lossy link "slow" is usually one dropped SYN, and the
	// destination should get another chance to go direct once the link
	// recovers rather than staying on the tunnel for an hour.
	ttl time.Duration
}

type racer struct {
	bindIP      netmon.IPFunc
	socksAddr   string
	dialTimeout time.Duration
	logf        func(string, ...any)
	generation  func() uint64
	ttl         time.Duration
	headStart   time.Duration
	provTTL     time.Duration

	// dialOverride replaces the real dials in tests, so the timing of each
	// path can be set rather than hoped for.
	dialOverride func(ctx context.Context, via, network, addr string) (net.Conn, error)

	learned sync.Map // addr string -> learnedPath
}

// currentGeneration is 0 when nothing tracks network changes, which leaves the
// time limit as the only thing expiring a path.
func (r *racer) currentGeneration() uint64 {
	if r.generation == nil {
		return 0
	}
	return r.generation()
}

// stale reports whether a learned path should be raced again.
func (r *racer) stale(p learnedPath, now time.Time) (bool, string) {
	if p.gen != r.currentGeneration() {
		return true, "the network changed"
	}
	ttl := r.ttl
	if p.ttl > 0 {
		ttl = p.ttl
	}
	if ttl > 0 && now.Sub(p.at) >= ttl {
		return true, fmt.Sprintf("learned %s ago", now.Sub(p.at).Round(time.Second))
	}
	return false, ""
}

func (r *racer) dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: r.dialTimeout}
	if ip := r.bindIP(); ip != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	return dialer.DialContext(ctx, network, addr)
}

func (r *racer) dialSocks(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", r.socksAddr, nil, &net.Dialer{Timeout: r.dialTimeout})
	if err != nil {
		return nil, fmt.Errorf("build socks dialer: %w", err)
	}
	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return dialer.Dial(network, addr)
}

type raceResult struct {
	conn net.Conn
	err  error
	via  string
	took time.Duration
}

func ms(d time.Duration) string { return fmt.Sprintf("%dms", d.Milliseconds()) }

// dial is the entry point wired into the SOCKS5 server as its Dial callback.
//
// It recovers from a panic, which is not the usual advice and is not here to
// make bugs survivable. The library calls this on a per-connection goroutine,
// so a panic anywhere inside it takes down the whole process — and this
// process is what every application on the machine routes through. The blast
// radius of one bad connection must not be the machine's networking. It is
// logged at error level and returned as a failed dial, which is loud in
// exactly the place someone would look.
func (r *racer) dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	defer func() {
		if p := recover(); p != nil {
			r.logf("racer: BUG: panic dialling %s: %v\n%s", addr, p, debug.Stack())
			conn, err = nil, fmt.Errorf("racer: internal error dialling %s", addr)
		}
	}()

	return r.dialLocked(ctx, network, addr)
}

func (r *racer) dialLocked(ctx context.Context, network, addr string) (net.Conn, error) {
	if v, ok := r.learned.Load(addr); ok {
		p := v.(learnedPath)

		if expired, why := r.stale(p, time.Now()); expired {
			// Dropped rather than retried: the reason to re-race is that the
			// old answer may be wrong, and a wrong answer that still connects
			// is the failure mode worth avoiding.
			r.logf("racer: re-racing %s, %s", addr, why)
			r.learned.Delete(addr)
		} else {
			conn, err := r.dialVia(ctx, p.via, network, addr)
			if err == nil {
				return conn, nil
			}
			r.logf("racer: learned path %s for %s failed (%v), re-racing", p.via, addr, err)
			r.learned.Delete(addr)
		}
	}
	return r.race(ctx, network, addr)
}

func (r *racer) dialVia(ctx context.Context, via, network, addr string) (net.Conn, error) {
	if r.dialOverride != nil {
		return r.dialOverride(ctx, via, network, addr)
	}
	switch via {
	case "direct":
		return r.dialDirect(ctx, network, addr)
	case "socks":
		return r.dialSocks(ctx, network, addr)
	default:
		return nil, fmt.Errorf("unknown path %q", via)
	}
}

// race dials both paths at once and prefers direct.
//
// A plain first-to-connect race is wrong on a lossy link. One dropped SYN
// costs the direct dial a second-long retransmit, the tunnel's dial gets
// through in the meantime, and a public destination is pinned to the VPN for
// the whole learned TTL. So direct wins whenever it connects; socks wins at
// once only when direct has failed outright, and otherwise only after
// headStart has passed with direct still pending. That last case is recorded
// with the shorter provisional TTL, because "direct was slow" is a much
// weaker claim than "direct does not work".
//
// The cost lands on the destinations that genuinely need the tunnel but look
// public, where direct tends to hang rather than fail: they pay at most
// headStart on the first connection after each expiry, never after that.
func (r *racer) race(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, r.dialTimeout)
	defer cancel()

	began := time.Now()
	directCh := make(chan raceResult, 1)
	socksCh := make(chan raceResult, 1)

	go func() {
		conn, err := r.dialVia(ctx, "direct", network, addr)
		directCh <- raceResult{conn, err, "direct", time.Since(began)}
	}()
	go func() {
		conn, err := r.dialVia(ctx, "socks", network, addr)
		socksCh <- raceResult{conn, err, "socks", time.Since(began)}
	}()

	var headStart <-chan time.Time
	if r.headStart > 0 {
		t := time.NewTimer(r.headStart)
		defer t.Stop()
		headStart = t.C
	}
	headStartOver := r.headStart <= 0

	var direct, socks *raceResult

	// closeLate closes whatever the losing dial produces, once it does,
	// instead of blocking on it here.
	closeLate := func(ch <-chan raceResult) {
		go func() {
			if res := <-ch; res.err == nil {
				res.conn.Close()
			}
		}()
	}

	win := func(res *raceResult, ttl time.Duration, why string) (net.Conn, error) {
		r.learned.Store(addr, learnedPath{via: res.via, gen: r.currentGeneration(), at: time.Now(), ttl: ttl})
		r.logf("racer: %s -> %s wins (%s)", addr, res.via, why)
		return res.conn, nil
	}

	// socksWins settles on a connected socks dial while direct is still
	// pending: direct has not failed, it just has not answered in time.
	socksWins := func() (net.Conn, error) {
		closeLate(directCh)
		trust := "until the network changes"
		if d := r.provisionalTTL(); d > 0 {
			trust = "for " + d.String()
		}
		return win(socks, r.provTTL, fmt.Sprintf("in %s; direct still pending after %s, trusted %s",
			ms(socks.took), ms(time.Since(began)), trust))
	}

	for {
		select {
		case res := <-directCh:
			direct = &res
			if res.err == nil {
				if socks == nil {
					closeLate(socksCh)
				} else if socks.err == nil {
					socks.conn.Close()
				}
				return win(direct, 0, "in "+ms(res.took))
			}
			if socks == nil {
				continue
			}
			if socks.err == nil {
				return win(socks, 0, fmt.Sprintf("in %s; direct failed after %s: %v",
					ms(socks.took), ms(res.took), res.err))
			}
			return nil, fmt.Errorf("racer: both paths failed for %s: direct: %v; socks: %w", addr, res.err, socks.err)

		case res := <-socksCh:
			socks = &res
			if res.err != nil {
				if direct == nil {
					continue
				}
				return nil, fmt.Errorf("racer: both paths failed for %s: direct: %v; socks: %w", addr, direct.err, res.err)
			}
			if direct != nil {
				return win(socks, 0, fmt.Sprintf("in %s; direct failed after %s: %v",
					ms(res.took), ms(direct.took), direct.err))
			}
			if headStartOver {
				return socksWins()
			}

		case <-headStart:
			headStartOver = true
			headStart = nil
			if socks != nil && socks.err == nil && direct == nil {
				return socksWins()
			}
		}
	}
}

// provisionalTTL is the limit a slow-direct socks win actually gets.
func (r *racer) provisionalTTL() time.Duration {
	if r.provTTL > 0 {
		return r.provTTL
	}
	return r.ttl
}

// Start runs the SOCKS5 racer until ctx is cancelled.
func Start(ctx context.Context, cfg Config) error {
	bindIP := cfg.BindIP
	if bindIP == nil {
		bindIP = func() net.IP { return nil }
	}

	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}

	r := &racer{
		bindIP:      bindIP,
		socksAddr:   cfg.SocksAddr,
		dialTimeout: cfg.DialTimeout,
		logf:        logf,
		generation:  cfg.Generation,
		ttl:         cfg.LearnedTTL,
		headStart:   cfg.DirectHeadStart,
		provTTL:     cfg.ProvisionalTTL,
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("racer listen %s: %w", cfg.Listen, err)
	}

	buffer := cfg.RelayBuffer
	if buffer < 4<<10 {
		buffer = 4 << 10
	}

	server := socks5.NewServer(
		socks5.WithDial(r.dial),
		socks5.WithBufferPool(bufferpool.NewPool(buffer)),
	)

	errCh := make(chan error, 1)
	go func() {
		logf("racer listening on %s (socks5), dial-timeout=%s, direct-head-start=%s, relay-buffer=%dKB",
			cfg.Listen, cfg.DialTimeout, cfg.DirectHeadStart, buffer>>10)
		errCh <- server.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		_ = ln.Close()
		return ctx.Err()
	case err := <-errCh:
		return fmt.Errorf("racer server: %w", err)
	}
}
