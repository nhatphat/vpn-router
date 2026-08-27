package web

import (
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestClosedTabReleasesItsStream is about what a shut browser tab costs.
//
// The status stream only carries a message when something changes, which on a
// working machine can be hours. A viewer that closes its tab has to be noticed
// straight away all the same: otherwise the handler sits blocked on the
// daemon, holding a socket to it, a socket to nobody, and a subscription the
// daemon keeps feeding — once per visit, for as long as the menu bar lives.
func TestClosedTabReleasesItsStream(t *testing.T) {
	_, url := serve(t)
	base := strings.Replace(url, "/?t=", "/events/status?t=", 1)

	settle()
	before := runtime.NumGoroutine()

	resp, err := http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	// Read the first snapshot, so the stream is certainly running.
	buf := make([]byte, 512)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatalf("first status: %v", err)
	}

	resp.Body.Close()

	// Generous: this should happen as soon as the socket closes, and the test
	// is about whether it happens at all.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	settle()
	t.Errorf("goroutines %d -> %d after the viewer left; the stream is still held",
		before, runtime.NumGoroutine())
}

func settle() {
	for i := 0; i < 5; i++ {
		runtime.Gosched()
		time.Sleep(20 * time.Millisecond)
	}
}

// TestThePageClosesWhenNobodyIsWatching is the other half of the same idea:
// the listener exists because somebody asked to look at something, and when
// they stop looking it has no reason to be there.
func TestThePageClosesWhenNobodyIsWatching(t *testing.T) {
	s, first := serve(t)
	s.IdleTimeout = 150 * time.Millisecond

	resp, err := http.Get(first)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	addr := strings.TrimPrefix(strings.Split(first, "/?")[0], "http://")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			// Gone, which is the point. Asking again has to bring it back,
			// with an address and a token of its own.
			second, err := s.URL()
			if err != nil {
				t.Fatalf("the page would not reopen: %v", err)
			}
			if second == first {
				t.Errorf("reopened with the closed page's URL: %s", second)
			}
			return
		}
		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}

	t.Error("the listener is still there with nobody connected to it")
}

// A tab left open is somebody watching, however quiet they are: the streams
// stay connected, and the page must not close under them.
func TestAnOpenTabKeepsThePage(t *testing.T) {
	s, url := serve(t)
	s.IdleTimeout = 150 * time.Millisecond

	stream, err := http.Get(strings.Replace(url, "/?t=", "/events/status?t=", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()

	buf := make([]byte, 512)
	if _, err := stream.Body.Read(buf); err != nil {
		t.Fatalf("first status: %v", err)
	}

	time.Sleep(600 * time.Millisecond)

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("the page closed while a tab was still watching it: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %s", resp.Status)
	}
}
