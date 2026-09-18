package supervisor

import (
	"encoding/json"
	"strings"
	"testing"

	"vpn-router/internal/config"
	"vpn-router/internal/trace"
)

// docLogLevel pulls the level back out of the generated document, so the test
// asserts on what sing-box will actually be started with rather than on the
// input that was meant to produce it.
func docLogLevel(t *testing.T, doc []byte) string {
	t.Helper()
	var parsed struct {
		Log struct {
			Level string `json:"level"`
		} `json:"log"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("generated document is not readable: %v", err)
	}
	return parsed.Log.Level
}

// A trace only works because sing-box is logging every connection, so the
// document has to say so while one is collecting — and has to stop saying so
// when it is not, since that log level is what makes a trace expensive.
func TestDocumentRaisesTheLogLevelOnlyWhileTracing(t *testing.T) {
	s := &Supervisor{o: Options{RouterProcess: "vpnctl"}, trace: trace.New()}
	cfg := base()
	cfg.SingBox.LogLevel = "warn"

	quiet, err := s.document(cfg)
	if err != nil {
		t.Fatalf("document: %v", err)
	}
	if got := docLogLevel(t, quiet); got != "warn" {
		t.Errorf("log level = %q with no trace, want warn", got)
	}

	s.trace.Start()
	loud, err := s.document(cfg)
	if err != nil {
		t.Fatalf("document while tracing: %v", err)
	}
	if got := docLogLevel(t, loud); got != traceLogLevel {
		t.Errorf("log level = %q while tracing, want %s", got, traceLogLevel)
	}

	s.trace.Stop()
	again, err := s.document(cfg)
	if err != nil {
		t.Fatalf("document after tracing: %v", err)
	}
	if got := docLogLevel(t, again); got != "warn" {
		t.Errorf("log level = %q after the trace, want warn back", got)
	}
}

// A reload during a trace goes through the same builder, so the configured
// level must not win over the trace and leave it collecting nothing.
func TestReloadDuringATraceKeepsTheRaisedLevel(t *testing.T) {
	s := &Supervisor{o: Options{RouterProcess: "vpnctl"}, trace: trace.New()}
	s.trace.Start()

	edited := base()
	edited.SingBox.LogLevel = "error"
	edited.Racer.DialTimeout = config.Duration(0)

	doc, err := s.document(edited)
	if err != nil {
		t.Fatalf("document: %v", err)
	}
	if got := docLogLevel(t, doc); got != traceLogLevel {
		t.Errorf("a reload dropped the trace to %q", got)
	}
}

// Tracing a paused stack collects nothing: sing-box is not running and will
// not be started, so the honest answer is to refuse and say what to do,
// rather than to report a trace that is waiting for something that is never
// coming.
func TestTraceRefusesWhilePaused(t *testing.T) {
	s := &Supervisor{o: Options{RouterProcess: "vpnctl"}, trace: trace.New(), pause: newPauseState()}
	s.pause.Set(true)

	st, err := s.StartTrace()
	if err == nil {
		t.Fatalf("a paused stack started a trace: %+v", st)
	}
	if !strings.Contains(err.Error(), "vpnctl start") {
		t.Errorf("the error does not say how to fix it: %v", err)
	}
	if s.trace.Active() {
		t.Error("the collector was left running after the refusal")
	}
}
