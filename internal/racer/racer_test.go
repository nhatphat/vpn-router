package racer

import (
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
