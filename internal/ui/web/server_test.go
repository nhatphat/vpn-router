package web

import (
	"bufio"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpn-router/internal/ipc"
	"vpn-router/internal/logbus"
	"vpn-router/internal/status"
)

// fakeDaemon is the smallest thing that satisfies the control protocol.
type fakeDaemon struct{ bus *logbus.Bus }

func (f *fakeDaemon) Snapshot() status.Snapshot {
	comps := []status.Component{
		{Name: status.CompVPN, Phase: status.PhaseRunning, Detail: "tunnel up"},
		{Name: status.CompSingBox, Phase: status.PhaseRunning, Detail: "utun225 up"},
	}
	overall, reason := status.Aggregate(comps)
	return status.Snapshot{Overall: overall, Reason: reason, Components: comps, Version: "test"}
}

func (f *fakeDaemon) Restart(string) error                  { return nil }
func (f *fakeDaemon) Retry()                                {}
func (f *fakeDaemon) Reload() (*status.ReloadResult, error) { return &status.ReloadResult{}, nil }
func (f *fakeDaemon) Logs(since uint64, s logbus.Source) []logbus.Entry {
	return f.bus.Snapshot(since, s)
}
func (f *fakeDaemon) SubscribeLogs(n int) (<-chan logbus.Entry, func()) { return f.bus.Subscribe(n) }
func (f *fakeDaemon) SubscribeStatus(int) (<-chan status.Snapshot, func()) {
	return make(chan status.Snapshot), func() {}
}
func (f *fakeDaemon) SetPaused(bool) error { return nil }
func (f *fakeDaemon) Version() string      { return "test" }

func serve(t *testing.T) (*Server, string) {
	t.Helper()

	// Not t.TempDir(): a unix socket path has a hard 104-byte limit and test
	// names blow past it.
	dir, err := os.MkdirTemp("", "vpnctlweb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")

	daemon := &fakeDaemon{bus: logbus.New(100)}
	daemon.bus.Publish(logbus.SourceDNS, logbus.LevelInfo, "example.com. -> public 1.2.3.4 (direct)")

	done := make(chan struct{})
	go func() {
		if err := (&ipc.Server{Path: sock, Backend: daemon}).Serve(done); err != nil {
			t.Logf("ipc serve: %v", err)
		}
	}()
	t.Cleanup(func() { close(done) })

	client := &ipc.Client{Path: sock, Timeout: 2 * time.Second}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Do(ipc.Request{Op: ipc.OpVersion}); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	s := &Server{Addr: "127.0.0.1:0", Client: client}
	url, err := s.URL()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return s, url
}

func TestPageServesAndCarriesItsToken(t *testing.T) {
	s, url := serve(t)

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %s", resp.Status)
	}

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, s.token) {
		t.Error("the page does not carry the token its own requests need")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("no CSP header; the page is supposed to load nothing remote")
	}
}

// TestURLIsStableAcrossCalls matters because the menu bar may open the page
// more than once, and a fresh token each time would invalidate an open tab.
func TestURLIsStableAcrossCalls(t *testing.T) {
	s, first := serve(t)
	second, err := s.URL()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("URL changed between calls:\n %s\n %s", first, second)
	}
}

// TestWithoutTheTokenNothingIsReachable covers the reason the token exists: a
// loopback listener is reachable by every local process, including other
// users'.
func TestWithoutTheTokenNothingIsReachable(t *testing.T) {
	_, url := serve(t)
	base := url[:strings.Index(url, "/?t=")]

	for _, path := range []string{"/", "/events/logs", "/events/status", "/?t=wrong"} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s returned %s, want 404", path, resp.Status)
		}
	}
}

func TestLogStreamDeliversTheBacklogThenLiveEntries(t *testing.T) {
	_, url := serve(t)
	base := url[:strings.Index(url, "/?t=")]
	token := url[strings.Index(url, "t=")+2:]

	req, err := http.NewRequest(http.MethodGet, base+"/events/logs?t="+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("Content-Type = %q", got)
	}

	reader := bufio.NewReader(resp.Body)
	deadline := time.Now().Add(5 * time.Second)
	var sawBatch, sawData bool

	for time.Now().Before(deadline) && !(sawBatch && sawData) {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "event: batch") {
			sawBatch = true
		}
		if strings.Contains(line, "example.com") {
			sawData = true
		}
	}

	if !sawBatch {
		t.Error("no batch event; the page would open empty")
	}
	if !sawData {
		t.Error("the buffered entry never arrived")
	}
}
