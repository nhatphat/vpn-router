package racer

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestStaleAfterTheNetworkChanges is the property this exists for: a path is
// only meaningful on the network it was worked out on. Reusing one across a
// change is how a destination that now needs the VPN keeps going out
// directly — and because a public address usually still accepts the
// connection, that failure is silent.
func TestStaleAfterTheNetworkChanges(t *testing.T) {
	gen := uint64(7)
	r := &racer{generation: func() uint64 { return gen }, ttl: time.Hour}

	learned := learnedPath{via: "direct", gen: gen, at: time.Now()}

	if expired, why := r.stale(learned, time.Now()); expired {
		t.Errorf("a fresh path on the same network was called stale: %s", why)
	}

	gen = 8
	expired, why := r.stale(learned, time.Now())
	if !expired {
		t.Fatal("a path from an earlier network generation was reused")
	}
	if why == "" {
		t.Error("no reason was given")
	}
}

func TestStaleAfterTheTimeLimit(t *testing.T) {
	r := &racer{generation: func() uint64 { return 1 }, ttl: 30 * time.Minute}
	learned := learnedPath{via: "socks", gen: 1, at: time.Now().Add(-31 * time.Minute)}

	if expired, _ := r.stale(learned, time.Now()); !expired {
		t.Error("a path older than the limit was reused")
	}

	fresh := learnedPath{via: "socks", gen: 1, at: time.Now().Add(-29 * time.Minute)}
	if expired, why := r.stale(fresh, time.Now()); expired {
		t.Errorf("a path inside the limit was discarded: %s", why)
	}
}

// TestZeroTTLLeavesTheGenerationInCharge covers the configuration that turns
// the time limit off deliberately.
func TestZeroTTLLeavesTheGenerationInCharge(t *testing.T) {
	gen := uint64(3)
	r := &racer{generation: func() uint64 { return gen }, ttl: 0}

	ancient := learnedPath{via: "direct", gen: gen, at: time.Now().Add(-72 * time.Hour)}
	if expired, why := r.stale(ancient, time.Now()); expired {
		t.Errorf("with no time limit an old path should stand: %s", why)
	}

	gen = 4
	if expired, _ := r.stale(ancient, time.Now()); !expired {
		t.Error("the generation must still expire it")
	}
}

// TestWithoutAGenerationSourceOnlyTimeExpires covers "vpnctl run-router",
// which has nothing watching the network.
func TestWithoutAGenerationSourceOnlyTimeExpires(t *testing.T) {
	r := &racer{generation: nil, ttl: time.Minute}

	if r.currentGeneration() != 0 {
		t.Errorf("currentGeneration = %d with no source, want 0", r.currentGeneration())
	}

	learned := learnedPath{via: "direct", gen: 0, at: time.Now()}
	if expired, why := r.stale(learned, time.Now()); expired {
		t.Errorf("a fresh path was discarded: %s", why)
	}

	old := learnedPath{via: "direct", gen: 0, at: time.Now().Add(-2 * time.Minute)}
	if expired, _ := r.stale(old, time.Now()); !expired {
		t.Error("the time limit did not apply")
	}
}

// echoListener is somewhere real to dial, so dial() can be exercised end to
// end rather than through its helpers.
func echoListener(t *testing.T) string {
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

// testRacer dials for real, with the SOCKS side pointed at a closed port so
// that "direct" always wins the race.
func testRacer(gen func() uint64, ttl time.Duration) *racer {
	return &racer{
		bindIP:      func() net.IP { return nil },
		socksAddr:   "127.0.0.1:1",
		dialTimeout: 2 * time.Second,
		logf:        func(string, ...any) {},
		generation:  gen,
		ttl:         ttl,
	}
}

// TestDialReusesALearnedPath is the test that was missing when the learned
// entry changed shape. The first dial races and records a decision; the second
// reads it back. Reading it back was broken for a released version, and every
// unit test still passed, because they all called the helpers directly and
// none of them went through dial().
func TestDialReusesALearnedPath(t *testing.T) {
	addr := echoListener(t)
	r := testRacer(func() uint64 { return 1 }, time.Hour)
	ctx := context.Background()

	first, err := r.dial(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	first.Close()

	stored, ok := r.learned.Load(addr)
	if !ok {
		t.Fatal("the race recorded nothing")
	}
	if p, ok := stored.(learnedPath); !ok || p.via != "direct" {
		t.Fatalf("recorded %#v, want a learnedPath via direct", stored)
	}

	// The one that used to panic and take the process with it.
	second, err := r.dial(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("second dial, on the learned path: %v", err)
	}
	second.Close()
}

func TestDialReRacesAfterTheNetworkChanges(t *testing.T) {
	addr := echoListener(t)
	gen := uint64(1)
	r := testRacer(func() uint64 { return gen }, time.Hour)
	ctx := context.Background()

	c, err := r.dial(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	gen = 2
	c, err = r.dial(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial after the network changed: %v", err)
	}
	c.Close()

	stored, _ := r.learned.Load(addr)
	if p := stored.(learnedPath); p.gen != 2 {
		t.Errorf("the re-raced entry kept generation %d, want 2", p.gen)
	}
}

// TestDialSurvivesAPanic covers the guard that keeps one bad connection from
// taking the machine's routing down with it.
func TestDialSurvivesAPanic(t *testing.T) {
	r := testRacer(func() uint64 { return 1 }, time.Hour)

	// A value of the wrong type is exactly the bug that happened, so it is
	// what the guard is tested against.
	r.learned.Store("10.0.0.1:443", "direct")

	conn, err := r.dial(context.Background(), "tcp", "10.0.0.1:443")
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("expected a failed dial, not a success")
	}
	if conn != nil {
		t.Error("a connection was returned alongside the error")
	}
}
