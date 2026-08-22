package dockerctl

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDemuxLinesFramed(t *testing.T) {
	var buf bytes.Buffer
	write := func(stream byte, payload string) {
		h := make([]byte, 8)
		h[0] = stream
		binary.BigEndian.PutUint32(h[4:], uint32(len(payload)))
		buf.Write(h)
		buf.WriteString(payload)
	}
	// A line split across two frames must still arrive once, whole.
	write(1, "first line\nsecond ")
	write(1, "half\n")
	write(2, "an error\n")

	var got []string
	if err := DemuxLines(&buf, func(s StdStream, line string) {
		got = append(got, string(rune('0'+s))+":"+line)
	}); err != nil {
		t.Fatalf("demux: %v", err)
	}

	want := []string{"1:first line", "1:second half", "2:an error"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDemuxLinesRawFallback(t *testing.T) {
	// A TTY container emits unframed text; the first byte is not a stream id.
	raw := bytes.NewBufferString("plain line one\nplain line two\n")
	var got []string
	if err := DemuxLines(raw, func(_ StdStream, line string) { got = append(got, line) }); err != nil {
		t.Fatalf("demux: %v", err)
	}
	if len(got) != 2 || got[0] != "plain line one" {
		t.Errorf("raw fallback produced %v", got)
	}
}

// TestLiveDaemon exercises the client against the real daemon. It skips when
// no socket is present, which is the normal case in CI and before login on
// this platform.
func TestLiveDaemon(t *testing.T) {
	if _, err := os.Stat(DefaultSocket); err != nil {
		t.Skipf("no docker socket at %s", DefaultSocket)
	}

	c, err := New("")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := c.Ping(ctx); err != nil {
		t.Skipf("daemon not reachable: %v", err)
	}

	ct, err := c.FindByComposeProject(ctx, "vpn-router", "vpn")
	if err != nil {
		t.Skipf("vpn-router project not running: %v", err)
	}
	t.Logf("container %s (%s) state=%s status=%q", ct.Name(), ct.ID[:12], ct.State, ct.Status)

	ins, err := c.Inspect(ctx, ct.ID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	t.Logf("running=%v health=%s", ins.State.Running, ins.HealthStatus())

	// Reading a file needs a live container to exec in. A stopped one is a
	// legitimate state of the machine, not a failure of this client.
	if ins.State.Running {
		dns, err := c.ReadFile(ctx, ct.ID, "/run/vpn-dns")
		if err != nil {
			t.Errorf("read /run/vpn-dns: %v", err)
		} else {
			t.Logf("vpn-dns = %q", strings.TrimSpace(string(dns)))
		}
	} else {
		t.Logf("container is not running; skipped the exec-based file read")
	}

	rc, err := c.Logs(ctx, ct.ID, false, 3)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	defer rc.Close()
	n := 0
	if err := DemuxLines(rc, func(_ StdStream, line string) {
		n++
		t.Logf("log: %s", line)
	}); err != nil {
		t.Errorf("demux logs: %v", err)
	}
	if n == 0 {
		t.Error("no log lines returned")
	}
}

// TestImagePathKeepsTheSlashUnescaped guards a mistake that only shows up
// against a real daemon: percent-encoding the slash in an image name makes the
// Engine reject the reference as "must be lowercase", which points nowhere
// near the actual cause.
func TestImagePathKeepsTheSlashUnescaped(t *testing.T) {
	c, err := New("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}

	got := c.url("/images/vpnctl/vpn:af0a1f4f0ab9/json", nil)

	if strings.Contains(got, "%2F") || strings.Contains(got, "%2f") {
		t.Errorf("image path is percent-encoded: %s", got)
	}
	if !strings.Contains(got, "/images/vpnctl/vpn:af0a1f4f0ab9/json") {
		t.Errorf("unexpected url: %s", got)
	}
}
