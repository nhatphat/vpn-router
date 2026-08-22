// Package racer implements tier 2: a local SOCKS5 server that sing-box routes
// "ambiguous" destinations to (public-looking IPs that the DNS-based tier 1
// classifier cannot tell apart from ones that actually need the VPN, e.g. a
// real domain whose IP is only reachable when the traffic originates from
// inside the VPN).
//
// For every new destination it dials "direct" (bound to the physical
// interface, bypassing the TUN) and "socks" (via the VPN container's SOCKS5
// proxy) concurrently. Whichever connects first wins and is used to relay
// the connection; the loser is discarded. Because sing-box's TUN already
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
}

type racer struct {
	bindIP      netmon.IPFunc
	socksAddr   string
	dialTimeout time.Duration
	logf        func(string, ...any)
	generation  func() uint64
	ttl         time.Duration

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
	if r.ttl > 0 && now.Sub(p.at) >= r.ttl {
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
}

// dial is the entry point wired into the SOCKS5 server as its Dial callback.
func (r *racer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if via, ok := r.learned.Load(addr); ok {
		conn, err := r.dialVia(ctx, via.(string), network, addr)
		if err == nil {
			return conn, nil
		}
		r.logf("racer: learned path %s for %s failed (%v), re-racing", via, addr, err)
		r.learned.Delete(addr)
	}
	return r.race(ctx, network, addr)
}

func (r *racer) dialVia(ctx context.Context, via, network, addr string) (net.Conn, error) {
	switch via {
	case "direct":
		return r.dialDirect(ctx, network, addr)
	case "socks":
		return r.dialSocks(ctx, network, addr)
	default:
		return nil, fmt.Errorf("unknown path %q", via)
	}
}

func (r *racer) race(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, r.dialTimeout)
	defer cancel()

	ch := make(chan raceResult, 2)

	go func() {
		conn, err := r.dialDirect(ctx, network, addr)
		ch <- raceResult{conn, err, "direct"}
	}()
	go func() {
		conn, err := r.dialSocks(ctx, network, addr)
		ch <- raceResult{conn, err, "socks"}
	}()

	var lastErr error
	for i := 0; i < 2; i++ {
		res := <-ch
		if res.err != nil {
			lastErr = res.err
			continue
		}

		r.learned.Store(addr, learnedPath{via: res.via, gen: r.currentGeneration(), at: time.Now()})
		r.logf("racer: %s -> %s wins", addr, res.via)

		// The loser may still complete later; close it when it does instead
		// of blocking on it here.
		go func() {
			other := <-ch
			if other.err == nil {
				other.conn.Close()
			}
		}()

		return res.conn, nil
	}

	return nil, fmt.Errorf("racer: both paths failed for %s: %w", addr, lastErr)
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
		logf("racer listening on %s (socks5), dial-timeout=%s, relay-buffer=%dKB",
			cfg.Listen, cfg.DialTimeout, buffer>>10)
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
