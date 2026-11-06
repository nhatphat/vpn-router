package racer

import (
	"context"
	"errors"
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

// pathTiming is how one path behaves in a scripted race: it connects, or
// fails, after a delay. A path that never answers is one whose delay is
// longer than the race's dial timeout.
type pathTiming struct {
	after time.Duration
	fail  bool
}

// scriptedRacer races two paths whose timing the test chooses. Connections
// are one end of a pipe, so the test can tell which path's was returned.
func scriptedRacer(t *testing.T, direct, socks pathTiming, headStart time.Duration) (*racer, map[string]net.Conn) {
	t.Helper()
	near := map[string]net.Conn{}
	for _, via := range []string{"direct", "socks"} {
		a, b := net.Pipe()
		near[via] = a
		t.Cleanup(func() { a.Close(); b.Close() })
	}
	timing := map[string]pathTiming{"direct": direct, "socks": socks}

	r := &racer{
		dialTimeout: time.Second,
		logf:        func(f string, a ...any) { t.Logf(f, a...) },
		generation:  func() uint64 { return 1 },
		ttl:         time.Hour,
		headStart:   headStart,
		provTTL:     5 * time.Minute,
		dialOverride: func(ctx context.Context, via, _, _ string) (net.Conn, error) {
			p := timing[via]
			select {
			case <-time.After(p.after):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if p.fail {
				return nil, errors.New(via + " refused")
			}
			return near[via], nil
		},
	}
	return r, near
}

const target = "203.0.113.7:443"

// raceRecorded runs one race and returns the path whose connection came back,
// checking it is also the path that was recorded.
func raceRecorded(t *testing.T, r *racer, near map[string]net.Conn) (string, learnedPath) {
	t.Helper()
	conn, err := r.race(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("race: %v", err)
	}
	got := ""
	for via, c := range near {
		if c == conn {
			got = via
		}
	}
	stored, ok := r.learned.Load(target)
	if !ok {
		t.Fatal("the race recorded nothing")
	}
	p := stored.(learnedPath)
	if p.via != got {
		t.Errorf("returned the %s connection but recorded %s", got, p.via)
	}
	return got, p
}

func TestRaceDirectWinsWhenItConnects(t *testing.T) {
	r, near := scriptedRacer(t, pathTiming{after: 80 * time.Millisecond}, pathTiming{after: 10 * time.Millisecond}, 300*time.Millisecond)
	got, p := raceRecorded(t, r, near)
	if got != "direct" {
		t.Fatalf("a direct dial that connected inside the head start lost to socks (%s)", got)
	}
	if p.ttl != 0 {
		t.Errorf("a direct win got a special ttl %s", p.ttl)
	}
}

// TestRaceSlowDirectIsOnlyProvisional is the weak-network case: socks
// connected, direct is still retrying. Socks is used after the head start,
// and trusted only briefly.
func TestRaceSlowDirectIsOnlyProvisional(t *testing.T) {
	r, near := scriptedRacer(t, pathTiming{after: 900 * time.Millisecond}, pathTiming{after: 10 * time.Millisecond}, 100*time.Millisecond)

	began := time.Now()
	got, p := raceRecorded(t, r, near)
	took := time.Since(began)

	if got != "socks" {
		t.Fatalf("want socks once the head start ran out, got %s", got)
	}
	if took < 100*time.Millisecond || took > 500*time.Millisecond {
		t.Errorf("settled after %s, want shortly after the 100ms head start", took)
	}
	if p.ttl != 5*time.Minute {
		t.Errorf("a slow-direct socks win was trusted for %s, want the provisional 5m", p.ttl)
	}
}

// TestRaceFailedDirectHandsOverAtOnce: when direct has failed, there is
// nothing to wait for, and the decision is a firm one.
func TestRaceFailedDirectHandsOverAtOnce(t *testing.T) {
	r, near := scriptedRacer(t, pathTiming{after: 5 * time.Millisecond, fail: true}, pathTiming{after: 20 * time.Millisecond}, 300*time.Millisecond)

	began := time.Now()
	got, p := raceRecorded(t, r, near)
	if took := time.Since(began); took > 200*time.Millisecond {
		t.Errorf("waited %s for a direct dial that had already failed", took)
	}
	if got != "socks" {
		t.Fatalf("want socks, got %s", got)
	}
	if p.ttl != 0 {
		t.Errorf("a firm socks win got ttl %s, want the normal limit", p.ttl)
	}
}

// TestRaceDirectFailingDuringHeadStart: socks connected first, then direct
// failed before the head start ran out. Socks wins at that moment, firmly.
func TestRaceDirectFailingDuringHeadStart(t *testing.T) {
	r, near := scriptedRacer(t, pathTiming{after: 60 * time.Millisecond, fail: true}, pathTiming{after: 10 * time.Millisecond}, 300*time.Millisecond)

	began := time.Now()
	got, p := raceRecorded(t, r, near)
	if took := time.Since(began); took > 250*time.Millisecond {
		t.Errorf("settled after %s, want as soon as direct failed", took)
	}
	if got != "socks" || p.ttl != 0 {
		t.Errorf("got %s with ttl %s, want a firm socks win", got, p.ttl)
	}
}

// TestRaceZeroHeadStartIsFirstToConnect keeps the old behaviour reachable.
func TestRaceZeroHeadStartIsFirstToConnect(t *testing.T) {
	r, near := scriptedRacer(t, pathTiming{after: 200 * time.Millisecond}, pathTiming{after: 10 * time.Millisecond}, 0)
	if got, _ := raceRecorded(t, r, near); got != "socks" {
		t.Errorf("with no head start the first to connect should win, got %s", got)
	}
}

func TestRaceBothFail(t *testing.T) {
	r, _ := scriptedRacer(t, pathTiming{after: 10 * time.Millisecond, fail: true}, pathTiming{after: 20 * time.Millisecond, fail: true}, 300*time.Millisecond)
	if conn, err := r.race(context.Background(), "tcp", target); err == nil {
		conn.Close()
		t.Fatal("expected an error when both paths fail")
	}
	if _, ok := r.learned.Load(target); ok {
		t.Error("a failed race recorded a path")
	}
}

// TestProvisionalEntryExpiresSooner checks stale() honours the per-entry ttl.
func TestProvisionalEntryExpiresSooner(t *testing.T) {
	r := &racer{generation: func() uint64 { return 1 }, ttl: time.Hour}
	p := learnedPath{via: "socks", gen: 1, at: time.Now().Add(-6 * time.Minute), ttl: 5 * time.Minute}
	if expired, _ := r.stale(p, time.Now()); !expired {
		t.Error("a provisional entry outlived its own ttl")
	}
	p.ttl = 0
	if expired, why := r.stale(p, time.Now()); expired {
		t.Errorf("a normal entry expired early: %s", why)
	}
}
