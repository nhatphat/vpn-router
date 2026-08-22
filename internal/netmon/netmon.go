// netmon resolves and tracks the physical interface that direct traffic must
// be bound to, so it bypasses the TUN's default route.
//
// For now the address is resolved once at startup, which is what the original
// host-dns-router did. The IPFunc indirection exists so a live watcher (route
// socket based) can be dropped in later without touching the DNS router or
// the racer: they already re-read the address on every dial.
package netmon

import (
	"fmt"
	"net"
	"sync/atomic"
)

// IPFunc returns the current source address to bind direct connections to, or
// nil when no interface is configured (dial without binding).
type IPFunc func() net.IP

// InterfaceIPv4 returns the first IPv4 address configured on the named
// interface.
func InterfaceIPv4(name string) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			return ip4, nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on interface %s", name)
}

// Holder stores the current bind address. Set never stores nil, so a
// transient interface flap cannot silently turn binding off: the last known
// good address is kept until a new valid one arrives.
type Holder struct {
	ip atomic.Pointer[net.IP]
}

func (h *Holder) Set(ip net.IP) {
	if ip == nil {
		return
	}
	cp := make(net.IP, len(ip))
	copy(cp, ip)
	h.ip.Store(&cp)
}

func (h *Holder) IP() net.IP {
	p := h.ip.Load()
	if p == nil {
		return nil
	}
	return *p
}

// Static resolves the interface once and returns a holder-backed IPFunc.
// An empty name yields a func that always returns nil (no binding).
func Static(iface string) (IPFunc, net.IP, error) {
	if iface == "" {
		return func() net.IP { return nil }, nil, nil
	}

	ip, err := InterfaceIPv4(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve bind interface %s: %w", iface, err)
	}

	h := &Holder{}
	h.Set(ip)
	return h.IP, ip, nil
}
