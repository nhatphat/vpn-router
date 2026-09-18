// Package trace turns sing-box's per-connection log lines into a table of
// which destinations this machine reached, and by which route.
//
// It exists for one question. A domain has to be in the force-VPN rule-set
// before the application needing it works, and until then nothing says which
// domain that is — the application fails, and the name it failed to reach is
// not written down anywhere. Raising sing-box's log level does write it down,
// but per-connection logging on a machine with a browser open produces tens of
// megabytes a day into a file launchd never rotates, which is a bad trade for
// an answer you want for five minutes.
//
// So the lines are read, folded into a table keyed by what was reached rather
// than by each time it was reached, and then dropped. The collector consumes
// them: they reach neither the log page nor the log file, and what grows is
// bounded by the number of distinct destinations rather than by traffic.
//
// Nothing here is on the data path. These lines arrive on the daemon's log
// pipe, which sing-box writes after a connection has already been routed.
package trace

import (
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"vpn-router/internal/logbus"
)

// Row is one destination, as reached by one process, by one route.
//
// Port is deliberately absent. The same host on 443 and 80 is one thing to
// decide about, and splitting it in two would double a table whose whole
// purpose is to be read quickly.
type Row struct {
	// Process is the executable sing-box attributed the connection to, empty
	// when it could not attribute one. Traffic from the container arrives
	// from the container runtime, so what appears there is the runtime, not
	// the application inside it.
	Process string `json:"process"`
	// Host is the domain, or an address literal when nothing was sniffed.
	Host string `json:"host"`
	// IsIP marks a Host no domain rule can usefully match, so the page can
	// show it without offering to force it through the VPN.
	IsIP bool `json:"is_ip"`
	// Outbound is the sing-box outbound tag the connection was routed to:
	// in this project's document, one of vpn-direct, racer or direct.
	Outbound string    `json:"outbound"`
	Count    int       `json:"count"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
}

// State is a whole answer to "what is the trace doing and what has it seen",
// which is one round trip rather than three.
type State struct {
	Active  bool      `json:"active"`
	Started time.Time `json:"started"`
	// Deadline is when collecting stops by itself. Zero when not collecting.
	Deadline time.Time `json:"deadline"`
	Rows     []Row     `json:"rows"`
	// Truncated says the table stopped taking new destinations, so what is
	// missing from it is missing because of the limit, not because it did not
	// happen.
	Truncated bool `json:"truncated"`
}

// The lines a connection produces, tied together by the id sing-box puts in
// front of each one.
//
// Which of these carries the domain is the subtle part. An application behind
// the TUN resolves the name itself and then connects to an address, so the
// destination sing-box logs is an address — the name only exists because
// sniffing reads it out of the TLS handshake, and sing-box reports that on its
// own line, at debug. Traffic that arrives already naming its destination (the
// container, which speaks SOCKS) has no such line, and there the destination
// on the outbound line is the name. So both are read, and the sniffed name
// wins where there is one.
var (
	connRe = regexp.MustCompile(`^\[(\d+) [^\]]*\]\s*`)
	// outbound/socks[vpn-direct]: outbound connection to 104.20.23.154:443
	outboundRe = regexp.MustCompile(`^outbound/[^\[]+\[([^\]]+)\]: outbound (?:packet )?connection to (.+):(\d+)$`)
	// router: found process path: /usr/bin/curl, user: someone
	processRe = regexp.MustCompile(`^router: found process path: ([^,]+)`)
	// router: sniffed protocol: tls, domain: example.com
	sniffedRe = regexp.MustCompile(`^router: sniffed protocol: [^,]+, domain: (\S+)`)
)

// pendingTTL is how long a connection may sit half-described before it is
// assumed to have been refused or reset. A connection that never reaches an
// outbound produces no row, and without this its process would be held for
// ever.
const pendingTTL = 2 * time.Minute

// maxPending bounds the half-described connections held at once. It is far
// above any real concurrency, and exists so that a burst nothing completes
// cannot grow without limit.
const maxPending = 8192

// maxRows bounds the table. Reaching it stops new destinations being recorded
// rather than evicting old ones: the row somebody is hunting for is as likely
// to be the first as the last, and a table that quietly forgets is worse than
// one that says it is full.
const maxRows = 4000

type pending struct {
	process string
	// domain is what sniffing read out of the handshake, empty when nothing
	// was sniffed.
	domain string
	at     time.Time
}

type Collector struct {
	mu      sync.Mutex
	active  bool
	started time.Time

	pending map[string]pending
	rows    map[string]*Row
	// full records that maxRows was reached, so the page can say the table is
	// no longer complete instead of implying nothing else happened.
	full bool
}

func New() *Collector {
	return &Collector{
		pending: make(map[string]pending),
		rows:    make(map[string]*Row),
	}
}

// Start empties the table and begins collecting. Each session stands alone:
// what a previous one saw says nothing about the application being tested now.
func (c *Collector) Start() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = true
	c.started = time.Now()
	c.pending = make(map[string]pending)
	c.rows = make(map[string]*Row)
	c.full = false
}

// Stop ends collection and keeps the table, which is the half worth reading:
// the point of stopping is to go and act on what was seen.
func (c *Collector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = false
	c.pending = make(map[string]pending)
}

func (c *Collector) Active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (c *Collector) Started() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

// Observe offers one sing-box message to the collector, with sing-box's own
// timestamp and level already stripped. It reports whether the line was
// consumed, which the bus takes as "do not publish this".
//
// What gets consumed is every per-connection line at info or debug, not a list
// of the shapes this package knows how to read. Those lines exist only because
// a trace raised the log level, so dropping them restores exactly the log
// there would have been without one — and a list would have to be extended
// every time sing-box words something differently, silently letting the flood
// back in when it was not.
//
// Warnings and errors are never consumed, whatever they are about. An outbound
// refusing UDP is per-connection too, and it is the kind of line somebody
// opens the log to find.
func (c *Collector) Observe(lvl logbus.Level, msg string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.active {
		return false
	}

	m := connRe.FindStringSubmatch(msg)
	if m == nil {
		// No connection id: sing-box starting, an interface changing. Nothing
		// a trace has any business hiding.
		return false
	}
	id, rest := m[1], msg[len(m[0]):]

	switch {
	case sniffedRe.MatchString(rest):
		p := c.pending[id]
		p.domain = strings.TrimSuffix(sniffedRe.FindStringSubmatch(rest)[1], ".")
		p.at = time.Now()
		c.prunePendingLocked()
		c.pending[id] = p

	case processRe.MatchString(rest):
		p := c.pending[id]
		p.process = strings.TrimSpace(processRe.FindStringSubmatch(rest)[1])
		p.at = time.Now()
		c.prunePendingLocked()
		c.pending[id] = p

	case outboundRe.MatchString(rest):
		o := outboundRe.FindStringSubmatch(rest)
		p := c.pending[id]
		host := o[2]
		if p.domain != "" {
			host = p.domain
		}
		c.record(p.process, host, o[1])
		delete(c.pending, id)
	}

	return lvl == logbus.LevelInfo || lvl == logbus.LevelDebug
}

func (c *Collector) record(process, host, outbound string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	// sing-box brackets IPv6 literals in the host:port form these lines use.
	bare := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")

	key := process + "\x00" + host + "\x00" + outbound
	now := time.Now()

	if row, ok := c.rows[key]; ok {
		row.Count++
		row.Last = now
		return
	}
	if len(c.rows) >= maxRows {
		c.full = true
		return
	}

	c.rows[key] = &Row{
		Process:  process,
		Host:     host,
		IsIP:     net.ParseIP(bare) != nil,
		Outbound: outbound,
		Count:    1,
		First:    now,
		Last:     now,
	}
}

// prunePendingLocked drops connections that never reached an outbound. It runs
// only once the map has outgrown what any real concurrency would need, so the
// common case does no scanning.
func (c *Collector) prunePendingLocked() {
	if len(c.pending) < maxPending {
		return
	}
	cutoff := time.Now().Add(-pendingTTL)
	for id, p := range c.pending {
		if p.at.Before(cutoff) {
			delete(c.pending, id)
		}
	}
	// Still full: everything in there is recent, which means a burst rather
	// than a leak. Dropping it all loses the process on connections in
	// flight, and that is better than growing without bound.
	if len(c.pending) >= maxPending {
		c.pending = make(map[string]pending)
	}
}

// Rows returns the table in the order destinations were first seen, and
// whether it stopped recording new destinations.
//
// Discovery order, not most-recent-first, because the table is read while it
// is filling. Sorting by the last packet reshuffles it under whoever is
// reading, and makes every redraw a reordering rather than an append — so a
// row, once placed, stays where it was put and only its count moves.
func (c *Collector) Rows() ([]Row, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]Row, 0, len(c.rows))
	for _, r := range c.rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].First.Equal(out[j].First) {
			return out[i].First.Before(out[j].First)
		}
		return out[i].Host < out[j].Host
	})
	return out, c.full
}
