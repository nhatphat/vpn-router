package trace

import (
	"testing"

	"vpn-router/internal/logbus"
)

// The lines below are sing-box 1.13.19's, captured from a real run rather than
// written from the documentation: the shape of these three is the whole
// contract this package depends on, and a hand-written approximation of them
// would pass while the parser was wrong.
const (
	rawInbound  = "+0700 2026-09-18 16:52:18 INFO [4059856821 0ms] inbound/socks[probe-in]: inbound connection to example.com:443"
	rawProcess  = "+0700 2026-09-18 16:52:18 INFO [4059856821 1ms] router: found process path: /usr/bin/curl, user: someone"
	rawOutbound = "+0700 2026-09-18 16:52:18 INFO [4059856821 1ms] outbound/direct[pretend-vpn]: outbound connection to example.com:443"
)

// feed puts a raw sing-box line through the same classification the bus applies
// before a tap sees it, so the test exercises what the collector is actually
// handed.
func feed(c *Collector, raw string) bool {
	lvl, msg := logbus.ClassifySingBox(raw)
	return c.Observe(lvl, msg)
}

func TestConnectionBecomesOneRow(t *testing.T) {
	c := New()
	c.Start()

	for _, line := range []string{rawInbound, rawProcess, rawOutbound} {
		if !feed(c, line) {
			t.Fatalf("line was not consumed: %s", line)
		}
	}

	rows, full := c.Rows()
	if full {
		t.Error("table reports itself full after one row")
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}

	got := rows[0]
	if got.Host != "example.com" {
		t.Errorf("host = %q, want example.com", got.Host)
	}
	if got.Outbound != "pretend-vpn" {
		t.Errorf("outbound = %q, want pretend-vpn", got.Outbound)
	}
	if got.Process != "/usr/bin/curl" {
		t.Errorf("process = %q, want /usr/bin/curl", got.Process)
	}
	if got.Count != 1 {
		t.Errorf("count = %d, want 1", got.Count)
	}
	if got.IsIP {
		t.Error("a domain was marked as an address")
	}
}

// The same destination reached repeatedly is one row with a count. That is the
// whole reason this package exists rather than a log filter: the table has to
// stay the size of the answer, not the size of the traffic.
func TestRepeatsFoldIntoACount(t *testing.T) {
	c := New()
	c.Start()

	for i := 0; i < 50; i++ {
		feed(c, rawProcess)
		feed(c, rawOutbound)
	}

	rows, _ := c.Rows()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Count != 50 {
		t.Errorf("count = %d, want 50", rows[0].Count)
	}
}

func TestAddressLiteralIsMarked(t *testing.T) {
	c := New()
	c.Start()

	feed(c, "+0700 2026-09-18 16:52:18 INFO [77 0ms] outbound/direct[direct]: outbound connection to 93.184.216.34:443")

	rows, _ := c.Rows()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if !rows[0].IsIP {
		t.Error("an address literal was not marked; the page would offer a domain rule for it")
	}
}

// A trace that is not running must leave the log exactly as it was. Consuming
// lines when nobody asked for a trace would silently remove them from the log
// page and the log file.
func TestNothingIsConsumedWhileStopped(t *testing.T) {
	c := New()

	for _, line := range []string{rawInbound, rawProcess, rawOutbound} {
		if feed(c, line) {
			t.Errorf("consumed a line while stopped: %s", line)
		}
	}
	if rows, _ := c.Rows(); len(rows) != 0 {
		t.Errorf("collected %d rows while stopped", len(rows))
	}
}

// Lines without a connection id are the daemon's own story — starting, an
// interface changing — and a trace must not make them disappear. Nor may it
// swallow a warning or an error, even a per-connection one: an outbound
// refusing UDP is exactly what somebody opens the log to find.
func TestUnrelatedLinesArePassedOn(t *testing.T) {
	c := New()
	c.Start()

	for _, line := range []string{
		"+0700 2026-09-18 16:52:18 INFO sing-box started (0.00s)",
		"+0700 2026-09-18 16:52:18 INFO inbound/tun[tun-in]: started at utun225",
		"+0700 2026-09-18 16:52:18 ERROR [1000007919 0ms] router: UDP is not supported by outbound: racer",
		"+0700 2026-09-18 16:52:18 WARN [1000158380 900ms] dns: exchange failed for slow.example.com.: context deadline exceeded",
		"+0700 2026-09-18 16:52:18 INFO network: updated default interface en0, index 13",
	} {
		if feed(c, line) {
			t.Errorf("consumed a line it had no business consuming: %s", line)
		}
	}
}

func TestStopKeepsTheTableAndStartClearsIt(t *testing.T) {
	c := New()
	c.Start()
	feed(c, rawProcess)
	feed(c, rawOutbound)

	c.Stop()
	if rows, _ := c.Rows(); len(rows) != 1 {
		t.Fatalf("stopping lost the table: %d rows", len(rows))
	}
	if c.Active() {
		t.Error("still active after Stop")
	}

	c.Start()
	if rows, _ := c.Rows(); len(rows) != 0 {
		t.Errorf("starting kept %d rows from the previous trace", len(rows))
	}
}

// A connection whose process was never found still produces a row. Traffic
// from the container arrives without one, and dropping those would hide
// exactly the destinations somebody is hunting.
func TestConnectionWithoutAProcessStillCounts(t *testing.T) {
	c := New()
	c.Start()

	feed(c, "+0700 2026-09-18 16:52:18 INFO [99 0ms] outbound/socks[racer]: outbound connection to api.example.com:443")

	rows, _ := c.Rows()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Process != "" {
		t.Errorf("process = %q, want empty", rows[0].Process)
	}
	if rows[0].Host != "api.example.com" {
		t.Errorf("host = %q", rows[0].Host)
	}
}

// Two connections interleaved must not take each other's process: the join is
// by connection id, and getting it wrong would attribute one application's
// destination to another.
func TestInterleavedConnectionsKeepTheirOwnProcess(t *testing.T) {
	c := New()
	c.Start()

	feed(c, "+0700 2026-09-18 16:52:18 INFO [11 0ms] router: found process path: /Applications/A.app/Contents/MacOS/A, user: someone")
	feed(c, "+0700 2026-09-18 16:52:18 INFO [22 0ms] router: found process path: /Applications/B.app/Contents/MacOS/B, user: someone")
	feed(c, "+0700 2026-09-18 16:52:18 INFO [22 1ms] outbound/socks[racer]: outbound connection to b.example.com:443")
	feed(c, "+0700 2026-09-18 16:52:18 INFO [11 1ms] outbound/socks[vpn-direct]: outbound connection to a.example.com:443")

	rows, _ := c.Rows()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(rows), rows)
	}

	byHost := map[string]Row{}
	for _, r := range rows {
		byHost[r.Host] = r
	}
	if got := byHost["a.example.com"]; got.Process != "/Applications/A.app/Contents/MacOS/A" || got.Outbound != "vpn-direct" {
		t.Errorf("a.example.com = %+v", got)
	}
	if got := byHost["b.example.com"]; got.Process != "/Applications/B.app/Contents/MacOS/B" || got.Outbound != "racer" {
		t.Errorf("b.example.com = %+v", got)
	}
}

// Both halves of the inbound pair are consumed. Leaving the "from" line behind
// would still put one line per connection into a log file nothing rotates,
// which is most of what a trace is supposed to save.
func TestBothInboundLinesAreConsumed(t *testing.T) {
	c := New()
	c.Start()

	for _, line := range []string{
		"+0700 2026-09-18 16:52:18 INFO [4059856821 0ms] inbound/socks[probe-in]: inbound connection from 127.0.0.1:50529",
		"+0700 2026-09-18 16:52:18 INFO [1000015838 0ms] inbound/tun[tun-in]: inbound packet connection from 172.19.0.1:40000",
	} {
		if !feed(c, line) {
			t.Errorf("line was not consumed: %s", line)
		}
	}
}

// The case the first version of this package got wrong, and the reason the
// trace runs at debug.
//
// An application behind the TUN resolves the name itself, so every line naming
// the destination names an address; the domain exists only on the line
// sniffing writes. Reading just the destination produced a table of IP
// addresses, which is useless to somebody who needs a domain to write a rule
// about. These lines are sing-box 1.13.19's, captured from a connection made
// the way one through the TUN is made.
func TestSniffedDomainBeatsTheAddress(t *testing.T) {
	c := New()
	c.Start()

	feed(c, "+0700 2026-09-18 18:06:29 INFO [2875738857 4ms] inbound/socks[probe-in]: inbound connection to 104.20.23.154:443")
	feed(c, "+0700 2026-09-18 18:06:29 DEBUG [2875738857 5ms] router: match[0] => sniff(http,tls,quic)")
	feed(c, "+0700 2026-09-18 18:06:29 DEBUG [2875738857 6ms] router: sniffed protocol: tls, domain: example.com")
	feed(c, "+0700 2026-09-18 18:06:29 INFO [2875738857 6ms] outbound/direct[direct-out]: outbound connection to 104.20.23.154:443")

	rows, _ := c.Rows()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Host != "example.com" {
		t.Errorf("host = %q, want example.com — the address was kept over the sniffed name", rows[0].Host)
	}
	if rows[0].IsIP {
		t.Error("the row is marked as an address, so the page would not offer to force it")
	}
}

// Nothing sniffed — a bare address, or a protocol with no name in it — is
// still worth showing, marked so the page does not offer a domain rule for it.
func TestUnsniffedConnectionKeepsTheAddress(t *testing.T) {
	c := New()
	c.Start()

	feed(c, "+0700 2026-09-18 18:06:29 INFO [5 0ms] outbound/direct[direct]: outbound connection to 93.184.216.34:443")

	rows, _ := c.Rows()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Host != "93.184.216.34" || !rows[0].IsIP {
		t.Errorf("row = %+v, want the address marked as one", rows[0])
	}
}

// Traffic that already names its destination — the container, which speaks
// SOCKS — has no sniffed line, and there the destination is the name.
func TestDestinationIsUsedWhenNothingWasSniffed(t *testing.T) {
	c := New()
	c.Start()

	feed(c, "+0700 2026-09-18 18:06:29 INFO [6 0ms] outbound/socks[vpn-direct]: outbound connection to api.internal.example:443")

	rows, _ := c.Rows()
	if len(rows) != 1 || rows[0].Host != "api.internal.example" {
		t.Fatalf("rows = %+v", rows)
	}
}

// The debug chatter a raised log level brings must not reach the log: that
// volume is the whole cost this package exists to avoid, and it is far more
// than the lines the collector reads by name.
func TestDebugChatterIsConsumed(t *testing.T) {
	c := New()
	c.Start()

	for _, line := range []string{
		"+0700 2026-09-18 18:06:29 DEBUG [2875738857 5ms] router: match[0] => sniff(http,tls,quic)",
		"+0700 2026-09-18 18:06:29 DEBUG [2875738857 6ms] dns: lookup domain example.com",
		"+0700 2026-09-18 18:06:29 DEBUG [2875738857 78ms] dns: exchanged A example.com. 300 IN A 172.66.147.243",
		"+0700 2026-09-18 18:06:29 DEBUG [2875738857 286ms] connection: connection upload finished",
		"+0700 2026-09-18 18:06:29 DEBUG [1140944890 6ms] inbound/socks[probe-in]: connection closed: EOF",
	} {
		if !feed(c, line) {
			t.Errorf("this would have flooded the log: %s", line)
		}
	}
}

// Order is by discovery and never changes, because the page appends to a table
// somebody is reading rather than rebuilding it. A row that moves when its
// count changes takes the reader's place in the list with it.
func TestRowOrderIsStableAsCountsChange(t *testing.T) {
	c := New()
	c.Start()

	feed(c, "+0700 2026-09-18 18:06:29 INFO [1 0ms] outbound/direct[direct]: outbound connection to first.example:443")
	feed(c, "+0700 2026-09-18 18:06:30 INFO [2 0ms] outbound/direct[direct]: outbound connection to second.example:443")
	feed(c, "+0700 2026-09-18 18:06:31 INFO [3 0ms] outbound/direct[direct]: outbound connection to third.example:443")

	before, _ := c.Rows()
	if len(before) != 3 || before[0].Host != "first.example" || before[2].Host != "third.example" {
		t.Fatalf("unexpected initial order: %+v", before)
	}

	// The oldest row becomes the busiest; it must not jump.
	for i := 0; i < 10; i++ {
		feed(c, "+0700 2026-09-18 18:06:40 INFO [9 0ms] outbound/direct[direct]: outbound connection to first.example:443")
	}

	after, _ := c.Rows()
	for i := range before {
		if after[i].Host != before[i].Host {
			t.Fatalf("row %d moved from %s to %s", i, before[i].Host, after[i].Host)
		}
	}
	if after[0].Count != 11 {
		t.Errorf("count = %d, want 11", after[0].Count)
	}
}
