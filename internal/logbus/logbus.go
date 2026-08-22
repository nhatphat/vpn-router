// Package logbus is the in-memory fan-in for everything vpnctl supervises.
//
// The three processes this project used to run by hand wrote to three
// terminals, and the interesting line was usually buried under repetitions of
// an uninteresting one (sing-box's per-connection errors, for example, ran to
// hundreds of identical lines in the captured logs). So the bus does two
// things beyond buffering: it tags every line with the component it came
// from, and it collapses consecutive repeats of the same normalised message
// into a single entry with a count.
package logbus

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Source string

const (
	SourceSupervisor Source = "supervisor"
	SourceSingBox    Source = "singbox"
	SourceVPN        Source = "vpn"
	SourceDNS        Source = "dns"
	SourceRacer      Source = "racer"
)

type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

type Entry struct {
	Seq    uint64    `json:"seq"`
	TS     time.Time `json:"ts"`
	Source Source    `json:"source"`
	Level  Level     `json:"level"`
	Msg    string    `json:"msg"`
	// Count is how many consecutive occurrences this entry represents. It
	// grows in place while repeats keep arriving, so a subscriber that saw
	// Count==1 may later see the same Seq with a higher Count.
	Count int `json:"count"`
}

// dedupeWindow bounds how long repeats collapse into one entry, so a slow
// drip of the same error still leaves a visible trail over time.
const dedupeWindow = 30 * time.Second

type Bus struct {
	mu   sync.Mutex
	ring []Entry
	cap  int
	seq  uint64

	// recent maps a normalised message to the Seq of the entry counting it.
	// Repeats do not have to be consecutive to collapse: in real logs the
	// same error arrives interleaved with unrelated lines, so consecutive-only
	// folding suppressed almost nothing.
	recent   map[string]uint64
	recentAt map[string]time.Time

	subs   map[int]chan Entry
	nextID int
}

func New(capacity int) *Bus {
	if capacity <= 0 {
		capacity = 5000
	}
	return &Bus{
		ring:     make([]Entry, 0, capacity),
		cap:      capacity,
		recent:   make(map[string]uint64),
		recentAt: make(map[string]time.Time),
		subs:     make(map[int]chan Entry),
	}
}

var (
	ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	// sing-box prefixes most lines with a per-connection id and elapsed
	// time, e.g. "[2878154039 1ms]". Two lines differing only in that token
	// are the same event as far as an operator is concerned.
	connIDRe = regexp.MustCompile(`\[\d+ \d+(?:\.\d+)?[a-zµ]*s?\]`)
	// Leading timestamp sing-box emits when log.timestamp is on.
	tsRe = regexp.MustCompile(`^[+\-]\d{4} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*`)
)

// StripANSI removes colour escapes, which sing-box emits when it thinks it is
// attached to a terminal.
func StripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

func dedupeKey(src Source, lvl Level, msg string) string {
	return string(src) + "\x00" + string(lvl) + "\x00" + connIDRe.ReplaceAllString(msg, "[]")
}

func (b *Bus) Publish(src Source, lvl Level, msg string) {
	msg = strings.TrimRight(StripANSI(msg), "\r\n")
	if msg == "" {
		return
	}

	now := time.Now()
	key := dedupeKey(src, lvl, msg)

	b.mu.Lock()

	if e := b.find(key, now); e != nil {
		e.Count++
		e.TS = now
		e.Msg = msg
		entry := *e
		b.recentAt[key] = now
		b.mu.Unlock()
		b.broadcast(entry)
		return
	}

	b.seq++
	entry := Entry{Seq: b.seq, TS: now, Source: src, Level: lvl, Msg: msg, Count: 1}

	if len(b.ring) == b.cap {
		copy(b.ring, b.ring[1:])
		b.ring[len(b.ring)-1] = entry
	} else {
		b.ring = append(b.ring, entry)
	}
	b.recent[key] = entry.Seq
	b.recentAt[key] = now
	b.pruneRecent(now)
	b.mu.Unlock()

	b.broadcast(entry)
}

// find returns the live entry currently counting key, or nil. Seq is
// contiguous across the ring (a collapsed repeat does not consume one), so the
// position is a subtraction rather than a scan.
func (b *Bus) find(key string, now time.Time) *Entry {
	seq, ok := b.recent[key]
	if !ok || now.Sub(b.recentAt[key]) >= dedupeWindow {
		return nil
	}
	if len(b.ring) == 0 {
		return nil
	}
	idx := int(seq - b.ring[0].Seq)
	if idx < 0 || idx >= len(b.ring) || b.ring[idx].Seq != seq {
		// Evicted from the ring; start counting afresh.
		delete(b.recent, key)
		delete(b.recentAt, key)
		return nil
	}
	return &b.ring[idx]
}

// pruneRecent drops expired keys. It runs only once the map has outgrown the
// ring, so the common case stays allocation-free.
func (b *Bus) pruneRecent(now time.Time) {
	if len(b.recent) <= b.cap {
		return
	}
	for k, at := range b.recentAt {
		if now.Sub(at) >= dedupeWindow {
			delete(b.recent, k)
			delete(b.recentAt, k)
		}
	}
}

func (b *Bus) Publishf(src Source, lvl Level, format string, args ...any) {
	b.Publish(src, lvl, fmt.Sprintf(format, args...))
}

// Logf returns a printf-style logger bound to one source, for handing to
// components that would otherwise write to the standard logger.
func (b *Bus) Logf(src Source, lvl Level) func(string, ...any) {
	return func(format string, args ...any) {
		b.Publishf(src, lvl, format, args...)
	}
}

func (b *Bus) broadcast(e Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default: // slow subscriber: drop rather than stall a producer
		}
	}
}

// Snapshot returns buffered entries with Seq > since, optionally filtered to
// one source ("" for all).
func (b *Bus) Snapshot(since uint64, src Source) []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]Entry, 0, len(b.ring))
	for _, e := range b.ring {
		if e.Seq <= since {
			continue
		}
		if src != "" && e.Source != src {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Subscribe returns a channel of future entries and a function to release it.
func (b *Bus) Subscribe(buffer int) (<-chan Entry, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan Entry, buffer)

	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.subs[id] = ch
	b.mu.Unlock()

	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
	}
}

// Attach consumes r line by line until EOF, classifying each line and
// publishing it under src. Used for a supervised process's stdout/stderr.
func (b *Bus) Attach(src Source, r io.Reader, classify func(string) (Level, string)) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lvl, msg := classify(scanner.Text())
		b.Publish(src, lvl, msg)
	}
}

// ClassifySingBox extracts sing-box's own level from a log line and strips
// the leading timestamp, which the bus records separately.
func ClassifySingBox(line string) (Level, string) {
	clean := tsRe.ReplaceAllString(StripANSI(line), "")

	lvl := LevelInfo
	for prefix, l := range map[string]Level{
		"ERROR": LevelError,
		"FATAL": LevelError,
		"PANIC": LevelError,
		"WARN":  LevelWarn,
		"INFO":  LevelInfo,
		"DEBUG": LevelDebug,
		"TRACE": LevelDebug,
	} {
		if strings.HasPrefix(clean, prefix) {
			lvl = l
			clean = strings.TrimSpace(strings.TrimPrefix(clean, prefix))
			break
		}
	}
	return lvl, clean
}

// ClassifyPlain is the classifier for components that do not label their own
// lines; it guesses from wording only.
func ClassifyPlain(line string) (Level, string) {
	clean := StripANSI(line)
	lower := strings.ToLower(clean)
	switch {
	case strings.Contains(lower, "error"), strings.Contains(lower, "failed"), strings.Contains(lower, "fatal"):
		return LevelError, clean
	case strings.Contains(lower, "warn"):
		return LevelWarn, clean
	default:
		return LevelInfo, clean
	}
}
