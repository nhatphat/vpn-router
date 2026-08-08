// racer implements tier 2: a local SOCKS5 server that sing-box routes
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
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/things-go/go-socks5"
	"golang.org/x/net/proxy"
)

type racer struct {
	bindIP      net.IP
	socksAddr   string
	dialTimeout time.Duration

	learned sync.Map // addr string -> "direct" | "socks"
}

func (r *racer) dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: r.dialTimeout}
	if r.bindIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: r.bindIP}
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
		log.Printf("racer: learned path %s for %s failed (%v), re-racing", via, addr, err)
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

		r.learned.Store(addr, res.via)
		log.Printf("racer: %s -> %s wins", addr, res.via)

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

func startRacer(listenAddr string, r *racer) error {
	server := socks5.NewServer(socks5.WithDial(r.dial))
	log.Printf("racer listening on %s (socks5), dial-timeout=%s", listenAddr, r.dialTimeout)
	return server.ListenAndServe("tcp", listenAddr)
}
