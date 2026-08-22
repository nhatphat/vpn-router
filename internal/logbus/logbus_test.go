package logbus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollapsesSingBoxConnectionSpam(t *testing.T) {
	b := New(100)

	// Real lines from the captured logs: identical except for the
	// per-connection id and elapsed time.
	for _, line := range []string{
		"+0700 2026-08-09 00:39:41 ERROR [2878154039 1ms] router: UDP is not supported by outbound: racer",
		"+0700 2026-08-09 00:39:41 ERROR [1961585298 0ms] router: UDP is not supported by outbound: racer",
		"+0700 2026-08-09 00:39:41 ERROR [1841067543 0ms] router: UDP is not supported by outbound: racer",
		"+0700 2026-08-09 00:39:42 ERROR [3437250953 0ms] router: UDP is not supported by outbound: racer",
	} {
		lvl, msg := ClassifySingBox(line)
		b.Publish(SourceSingBox, lvl, msg)
	}

	entries := b.Snapshot(0, "")
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1 collapsed entry:\n%v", len(entries), entries)
	}
	if entries[0].Count != 4 {
		t.Errorf("Count = %d, want 4", entries[0].Count)
	}
	if entries[0].Level != LevelError {
		t.Errorf("Level = %q, want error", entries[0].Level)
	}
	if strings.Contains(entries[0].Msg, "\x1b") {
		t.Error("ANSI escapes survived into the entry")
	}
	if !strings.Contains(entries[0].Msg, "UDP is not supported") {
		t.Errorf("message mangled: %q", entries[0].Msg)
	}
}

func TestDistinctMessagesAreNotCollapsed(t *testing.T) {
	b := New(100)
	b.Publish(SourceDNS, LevelInfo, "example.com. -> public 1.2.3.4 (direct)")
	b.Publish(SourceDNS, LevelInfo, "internal.corp. -> internal/private 10.1.2.3 (socks)")

	if got := len(b.Snapshot(0, "")); got != 2 {
		t.Fatalf("got %d entries, want 2", got)
	}
}

func TestRingEvictsOldestAndSnapshotFiltersBySource(t *testing.T) {
	b := New(3)
	b.Publish(SourceDNS, LevelInfo, "one")
	b.Publish(SourceRacer, LevelInfo, "two")
	b.Publish(SourceDNS, LevelInfo, "three")
	b.Publish(SourceDNS, LevelInfo, "four")

	all := b.Snapshot(0, "")
	if len(all) != 3 || all[0].Msg != "two" {
		t.Fatalf("ring did not evict oldest: %v", all)
	}

	dnsOnly := b.Snapshot(0, SourceDNS)
	if len(dnsOnly) != 2 {
		t.Fatalf("source filter returned %d entries, want 2", len(dnsOnly))
	}

	if got := b.Snapshot(all[1].Seq, ""); len(got) != 1 || got[0].Msg != "four" {
		t.Fatalf("since-filter returned %v", got)
	}
}

func TestSubscriberSeesLiveEntries(t *testing.T) {
	b := New(10)
	ch, release := b.Subscribe(4)
	defer release()

	b.Publish(SourceSupervisor, LevelWarn, "vpn container unhealthy")

	e := <-ch
	if e.Source != SourceSupervisor || e.Level != LevelWarn {
		t.Fatalf("unexpected entry: %+v", e)
	}
}

// TestFoldsAFileOfMixedLines runs the classifier over a committed fixture in
// sing-box's real format, so the folding behaviour is verifiable on any
// machine. The captured logs this was originally developed against hold real
// browsing and are deliberately not in the repository.
func TestFoldsAFileOfMixedLines(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "singbox.log"))
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}

	b := New(10000)
	var lineCount int
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lineCount++
		lvl, msg := ClassifySingBox(line)
		b.Publish(SourceSingBox, lvl, msg)
	}

	entries := b.Snapshot(0, "")
	if len(entries) >= lineCount {
		t.Errorf("no folding happened: %d entries from %d lines", len(entries), lineCount)
	}

	// The repeated per-connection error must end up as one entry with a
	// count, even though unrelated lines arrive between its occurrences.
	var folded *Entry
	for i := range entries {
		if strings.Contains(entries[i].Msg, "UDP is not supported") {
			folded = &entries[i]
		}
	}
	if folded == nil {
		t.Fatal("the repeated error is missing entirely")
	}
	if folded.Count != 12 {
		t.Errorf("folded count = %d, want 12", folded.Count)
	}
	if folded.Level != LevelError {
		t.Errorf("level = %q, want error", folded.Level)
	}

	for _, e := range entries {
		if strings.HasPrefix(e.Msg, "+0700") {
			t.Errorf("timestamp not stripped: %q", e.Msg)
		}
		if strings.Contains(e.Msg, "\x1b") {
			t.Errorf("ANSI escape survived: %q", e.Msg)
		}
	}

	// A fatal line must not be filed as anything softer than an error.
	var sawFatal bool
	for _, e := range entries {
		if strings.Contains(e.Msg, "operation not permitted") {
			sawFatal = true
			if e.Level != LevelError {
				t.Errorf("FATAL line classified as %q", e.Level)
			}
		}
	}
	if !sawFatal {
		t.Error("the FATAL line is missing")
	}
}

// TestClassifyCapturedLogIfPresent uses a real captured log when the developer
// has one locally. It is skipped everywhere else.
func TestClassifyCapturedLogIfPresent(t *testing.T) {
	path := filepath.Join("..", "..", "sing-box-log2.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("captured log not present: %v", err)
	}

	b := New(10000)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lvl, msg := ClassifySingBox(line)
		b.Publish(SourceSingBox, lvl, msg)
	}

	entries := b.Snapshot(0, "")
	if len(entries) == 0 {
		t.Fatal("no entries produced")
	}
	if len(entries) >= len(lines) {
		t.Errorf("no collapsing happened: %d entries from %d lines", len(entries), len(lines))
	}
	t.Logf("%d raw lines -> %d entries", len(lines), len(entries))

	for _, e := range entries {
		if strings.HasPrefix(e.Msg, "+0700") {
			t.Fatalf("timestamp not stripped: %q", e.Msg)
		}
	}
}
