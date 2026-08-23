package ipc

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vpn-router/internal/logbus"
	"vpn-router/internal/status"
)

type stubBackend struct {
	mu        sync.Mutex
	restarted []string
	retried   int
	reloaded  int
	paused    bool
	bus       *logbus.Bus
	statusCh  chan status.Snapshot
}

func newStub() *stubBackend {
	return &stubBackend{bus: logbus.New(100), statusCh: make(chan status.Snapshot, 4)}
}

func (b *stubBackend) Snapshot() status.Snapshot {
	comps := []status.Component{
		{Name: status.CompVPN, Phase: status.PhaseRunning, Detail: "tunnel up"},
		{Name: status.CompSingBox, Phase: status.PhaseRunning, Detail: "utun225 up"},
	}
	overall, reason := status.Aggregate(comps)
	return status.Snapshot{Overall: overall, Reason: reason, Components: comps, Generation: 7, Version: "test"}
}

func (b *stubBackend) Restart(component string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.restarted = append(b.restarted, component)
	return nil
}

func (b *stubBackend) Retry() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.retried++
}

func (b *stubBackend) Logs(since uint64, source logbus.Source) []logbus.Entry {
	return b.bus.Snapshot(since, source)
}

func (b *stubBackend) SubscribeLogs(n int) (<-chan logbus.Entry, func()) { return b.bus.Subscribe(n) }

func (b *stubBackend) SubscribeStatus(n int) (<-chan status.Snapshot, func()) {
	return b.statusCh, func() {}
}

func (b *stubBackend) Reload() (*status.ReloadResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reloaded++
	return &status.ReloadResult{ConfigPath: "/tmp/config.yaml", Restarted: []string{status.CompSingBox}, Disruptive: true}, nil
}

func (b *stubBackend) SetPaused(paused bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.paused = paused
	return nil
}

func (b *stubBackend) Version() string { return "test" }

func serve(t *testing.T, backend Backend) *Client {
	t.Helper()

	// Not t.TempDir(): it embeds the test name, and a unix socket path has a
	// hard 104-byte limit that long test names blow past.
	dir, err := os.MkdirTemp("", "vpnctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	done := make(chan struct{})
	srv := &Server{Path: sock, Backend: backend}

	go func() {
		if err := srv.Serve(done); err != nil {
			t.Logf("serve: %v", err)
		}
	}()
	t.Cleanup(func() { close(done) })

	c := &Client{Path: sock, Timeout: 2 * time.Second}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.Do(Request{Op: OpVersion}); err == nil {
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server never became reachable")
	return nil
}

func TestStatusAndVersion(t *testing.T) {
	c := serve(t, newStub())

	resp, err := c.Do(Request{Op: OpStatus})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if resp.Status == nil || resp.Status.Generation != 7 {
		t.Fatalf("unexpected snapshot: %+v", resp.Status)
	}
	if resp.Status.Overall != status.OverallGreen {
		t.Errorf("overall = %q, want green", resp.Status.Overall)
	}
}

func TestRestartAndRetryReachTheBackend(t *testing.T) {
	b := newStub()
	c := serve(t, b)

	if _, err := c.Do(Request{Op: OpRestart, Component: status.CompVPN}); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if _, err := c.Do(Request{Op: OpRetry}); err != nil {
		t.Fatalf("retry: %v", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.restarted) != 1 || b.restarted[0] != status.CompVPN {
		t.Errorf("restarted = %v", b.restarted)
	}
	if b.retried != 1 {
		t.Errorf("retried = %d, want 1", b.retried)
	}
}

func TestUnknownOpIsRejected(t *testing.T) {
	c := serve(t, newStub())
	if _, err := c.Do(Request{Op: "rm -rf /"}); err == nil {
		t.Fatal("expected an error for an unknown op")
	}
}

func TestLogsSnapshotAndFollow(t *testing.T) {
	b := newStub()
	b.bus.Publish(logbus.SourceDNS, logbus.LevelInfo, "first")
	c := serve(t, b)

	resp, err := c.Do(Request{Op: OpLogs})
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].Msg != "first" {
		t.Fatalf("entries = %+v", resp.Entries)
	}

	got := make(chan string, 1)
	go func() {
		_ = c.Stream(Request{Op: OpLogs, Follow: true, Source: logbus.SourceRacer}, func(r *Response) bool {
			if r.Entry != nil {
				got <- r.Entry.Msg
				return false
			}
			return true
		})
	}()

	// Give the stream time to subscribe, then publish one matching and one
	// non-matching entry to check the source filter.
	time.Sleep(200 * time.Millisecond)
	b.bus.Publish(logbus.SourceDNS, logbus.LevelInfo, "ignored")
	b.bus.Publish(logbus.SourceRacer, logbus.LevelInfo, "wanted")

	select {
	case msg := <-got:
		if msg != "wanted" {
			t.Errorf("streamed %q, want \"wanted\"", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no streamed entry arrived")
	}
}

func TestOverlongSocketPathIsRejectedClearly(t *testing.T) {
	long := "/tmp/" + strings.Repeat("x", 120) + ".sock"
	srv := &Server{Path: long, Backend: newStub()}

	err := srv.Serve(make(chan struct{}))
	if err == nil {
		t.Fatal("expected an error for an overlong socket path")
	}
	if !strings.Contains(err.Error(), "exceeds the") {
		t.Errorf("error does not explain the limit: %v", err)
	}
}
