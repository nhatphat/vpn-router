package netmon

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHolderKeepsLastGoodAddress(t *testing.T) {
	h := &Holder{}
	h.Set(net.ParseIP("192.168.1.50"))
	h.Set(nil) // an interface flap must not unbind

	if got := h.IP(); !got.Equal(net.ParseIP("192.168.1.50")) {
		t.Fatalf("IP() = %v, want 192.168.1.50", got)
	}
}

func TestHolderCopiesSoCallerCannotMutateIt(t *testing.T) {
	h := &Holder{}
	ip := net.ParseIP("10.0.0.1").To4()
	h.Set(ip)
	ip[0] = 99

	if got := h.IP().To4(); got[0] != 10 {
		t.Fatalf("holder aliased the caller's slice: %v", got)
	}
}

// TestWatchStopsOnContextCancel makes sure the route socket and its reader
// goroutine are released, since the daemon restarts this watcher.
func TestWatchStopsOnContextCancel(t *testing.T) {
	iface := firstUpInterface(t)

	ctx, cancel := context.WithCancel(context.Background())
	h := &Holder{}
	done := make(chan error, 1)
	go func() { done <- Watch(ctx, iface, h, nil, nil) }()

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Watch did not return after context cancel")
	}
}

func firstUpInterface(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot list interfaces: %v", err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if _, err := InterfaceIPv4(i.Name); err == nil {
			return i.Name
		}
	}
	t.Skip("no interface with an IPv4 address")
	return ""
}
