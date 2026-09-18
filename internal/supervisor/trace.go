package supervisor

import (
	"fmt"
	"time"

	"vpn-router/internal/config"
	"vpn-router/internal/logbus"
	"vpn-router/internal/singbox"
	"vpn-router/internal/trace"
)

// traceLogLevel is what sing-box is run at while a trace is collecting.
//
// It has to be debug, not info. Info names the destination, but for anything
// behind the TUN that destination is an address: the application resolved the
// name itself before connecting, so the name reaches sing-box only through
// sniffing, and sniffing reports what it read on a debug line. Collecting at
// info therefore produces a table of addresses — which is no use at all to
// somebody who needs a domain to write a rule about.
//
// The extra volume debug brings costs nothing downstream, because the
// collector consumes those lines before they reach the log or the log file.
const traceLogLevel = "debug"

// traceMaxDuration is the longest a trace runs without being stopped.
//
// A trace costs a sing-box restart to start and another to stop, so it must
// not be left on by accident — and the ways it gets left on are ordinary: a
// closed laptop, a browser tab closed on the way to a meeting. The page also
// stops a trace when nobody is watching it any more, but the page is in the
// menu bar process and that process can be killed, so the daemon keeps its own
// limit rather than trusting a caller to come back.
const traceMaxDuration = 30 * time.Minute

// document renders the sing-box configuration for cfg, at the log level the
// current trace state calls for.
//
// Reload uses this too, so that reloading during a trace does not quietly drop
// the configuration back to its usual log level and end the trace's supply of
// lines while the trace still says it is running.
func (s *Supervisor) document(cfg *config.Config) ([]byte, error) {
	in, err := singbox.FromConfig(cfg, s.o.RouterProcess)
	if err != nil {
		return nil, err
	}
	if s.trace.Active() {
		in.LogLevel = traceLogLevel
	}
	return singbox.Generate(in)
}

// StartTrace raises sing-box's log level and begins folding its per-connection
// lines into a table of destinations.
//
// Starting restarts sing-box, which resets every connection through the TUN.
// That is unavoidable — the log level is part of the configuration sing-box
// reads at startup — and it is also why the caller is told, rather than being
// left to notice that the application it was about to test lost its
// connections at the moment tracing began.
func (s *Supervisor) StartTrace() (*trace.State, error) {
	if s.trace.Active() {
		return s.TraceState(), nil
	}

	// A paused stack routes nothing, so sing-box would never start and the
	// trace would sit collecting from a process that is not running. Refusing
	// says why; starting would leave a button waiting for something that is
	// never going to happen.
	if s.pause.Paused() {
		return nil, fmt.Errorf("the stack is paused, so there is no traffic to trace:\n  vpnctl start")
	}

	// Active before the document is rendered, so that document picks up the
	// trace log level. Undone if anything below refuses.
	s.trace.Start()

	doc, err := s.document(s.cfg())
	if err != nil {
		s.trace.Stop()
		return nil, fmt.Errorf("the trace was not started: %w", err)
	}
	if err := singbox.Validate(s.o.SingBoxBinary, doc); err != nil {
		s.trace.Stop()
		return nil, fmt.Errorf("the trace was not started: %w", err)
	}

	s.mu.Lock()
	if s.traceTimer != nil {
		s.traceTimer.Stop()
	}
	s.traceTimer = time.AfterFunc(traceMaxDuration, func() {
		if _, err := s.StopTrace(); err != nil {
			s.logf(logbus.LevelWarn, "trace: could not stop at the time limit: %v", err)
		}
	})
	s.mu.Unlock()

	s.sb.SetDocument(doc)
	s.sb.Restart()

	s.logf(logbus.LevelInfo, "trace: collecting destinations; sing-box restarting at log level %s", traceLogLevel)
	return s.TraceState(), nil
}

// StopTrace puts the log level back and stops collecting. The table is kept:
// stopping is what somebody does before acting on what they saw.
func (s *Supervisor) StopTrace() (*trace.State, error) {
	if !s.trace.Active() {
		return s.TraceState(), nil
	}

	s.mu.Lock()
	if s.traceTimer != nil {
		s.traceTimer.Stop()
		s.traceTimer = nil
	}
	s.mu.Unlock()

	s.trace.Stop()

	doc, err := s.document(s.cfg())
	if err != nil {
		// The collector has stopped, so nothing is being recorded, but
		// sing-box is still running verbosely. Saying so is better than
		// reporting a clean stop.
		return nil, fmt.Errorf("collecting stopped, but sing-box is still at %s: %w", traceLogLevel, err)
	}

	s.sb.SetDocument(doc)
	s.sb.Restart()

	s.logf(logbus.LevelInfo, "trace: stopped; sing-box restarting at its configured log level")
	return s.TraceState(), nil
}

// TraceState is the table and whether it is still filling.
func (s *Supervisor) TraceState() *trace.State {
	rows, full := s.trace.Rows()
	return &trace.State{
		Active:  s.trace.Active(),
		Started: s.trace.Started(),
		// Deadline is shown so the page can say when collecting will stop by
		// itself rather than appearing to run for ever.
		Deadline:  s.traceDeadline(),
		Rows:      rows,
		Truncated: full,
	}
}

func (s *Supervisor) traceDeadline() time.Time {
	if !s.trace.Active() {
		return time.Time{}
	}
	started := s.trace.Started()
	if started.IsZero() {
		return time.Time{}
	}
	return started.Add(traceMaxDuration)
}
