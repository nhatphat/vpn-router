package netmon

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// debounce collapses the burst of route messages the kernel emits for a single
// user-visible event (joining a network produces many).
const debounce = 750 * time.Millisecond

// Watch keeps h pointing at the current IPv4 address of iface, using the
// kernel's routing socket so it reacts to network changes instead of polling.
//
// It deliberately does not parse the routing messages. Any message at all is
// treated as "something about the network changed, re-read the interface":
// the parse is where the fiddly, version-specific work would be, and the
// answer we need is one Getifaddrs away.
//
// onChange is called only when the address actually differs from the one
// already held, so a caller can use it to invalidate per-network state
// without being woken for every unrelated route update.
func Watch(ctx context.Context, iface string, h *Holder, onChange func(old, cur net.IP), logf func(string, ...any)) error {
	if iface == "" {
		<-ctx.Done()
		return ctx.Err()
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}

	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("open route socket: %w", err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("set route socket nonblocking: %w", err)
	}

	// os.NewFile hands the fd to the runtime poller, so Read blocks the
	// goroutine rather than an OS thread, and Close from another goroutine
	// unblocks it.
	f := os.NewFile(uintptr(fd), "route-socket")

	go func() {
		<-ctx.Done()
		f.Close()
	}()

	notify := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := f.Read(buf); err != nil {
				if ctx.Err() == nil {
					logf("netmon: route socket read: %v", err)
				}
				close(notify)
				return
			}
			select {
			case notify <- struct{}{}:
			default: // a re-check is already pending
			}
		}
	}()

	var timer *time.Timer
	var timerC <-chan time.Time

	recheck := func() {
		cur, err := InterfaceIPv4(iface)
		if err != nil {
			// Interface is down or has no address yet. Keep the last known
			// good address: binding to a stale address fails loudly, while
			// silently unbinding would leak traffic into the TUN.
			logf("netmon: %s has no IPv4 address (%v), keeping %s", iface, err, h.IP())
			return
		}

		old := h.IP()
		if old.Equal(cur) {
			return
		}
		h.Set(cur)
		logf("netmon: %s address changed %s -> %s", iface, old, cur)
		if onChange != nil {
			onChange(old, cur)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case _, ok := <-notify:
			if !ok {
				return fmt.Errorf("route socket closed")
			}
			if timer == nil {
				timer = time.NewTimer(debounce)
				timerC = timer.C
			} else {
				timer.Reset(debounce)
			}

		case <-timerC:
			timerC = nil
			recheck()
		}
	}
}
