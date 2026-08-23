// Package ipc is the control channel between the root daemon and the
// unprivileged clients that display it: the menu bar and the CLI.
//
// The protocol is newline-delimited JSON over a unix socket. It is
// deliberately narrow. Every request names an operation from a closed set and
// carries nothing but enumerated values — no paths, no command strings, no
// arguments that become part of anything the daemon executes. The daemon runs
// as root and the socket is reachable by an ordinary user, so anything richer
// would turn this into a way to ask root to run things.
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpn-router/internal/logbus"
	"vpn-router/internal/status"
)

// DefaultSocket is under /var/run, which the daemon can write and clients can
// reach without depending on any user's home directory.
const DefaultSocket = "/var/run/vpnctl.sock"

// maxSocketPath is the size of sun_path in Darwin's sockaddr_un. Exceeding it
// fails as a bare "invalid argument" from bind(2), which is worth turning into
// a message that says what is actually wrong.
const maxSocketPath = 104

type Op string

const (
	OpStatus       Op = "status"
	OpStatusStream Op = "status-stream"
	OpLogs         Op = "logs"
	OpRestart      Op = "restart"
	OpRetry        Op = "retry"
	OpReload       Op = "reload"
	OpPause        Op = "pause"
	OpResume       Op = "resume"
	OpVersion      Op = "version"
)

// Request is the whole client vocabulary.
type Request struct {
	Op Op `json:"op"`
	// Component is one of the status.Comp* names, for OpRestart.
	Component string `json:"component,omitempty"`
	// Source filters logs; empty means all sources.
	Source logbus.Source `json:"source,omitempty"`
	// Since returns only log entries newer than this sequence number.
	Since uint64 `json:"since,omitempty"`
	// Follow keeps the response open and streams new entries.
	Follow bool `json:"follow,omitempty"`
}

// Response is one line of reply. Streaming operations send many.
type Response struct {
	OK      bool                 `json:"ok"`
	Error   string               `json:"error,omitempty"`
	Status  *status.Snapshot     `json:"status,omitempty"`
	Entries []logbus.Entry       `json:"entries,omitempty"`
	Entry   *logbus.Entry        `json:"entry,omitempty"`
	Reload  *status.ReloadResult `json:"reload,omitempty"`
	Version string               `json:"version,omitempty"`
}

// Backend is what the daemon implements for the server to expose.
type Backend interface {
	Snapshot() status.Snapshot
	Restart(component string) error
	Retry()
	Reload() (*status.ReloadResult, error)
	SetPaused(paused bool) error
	Logs(since uint64, source logbus.Source) []logbus.Entry
	SubscribeLogs(buffer int) (<-chan logbus.Entry, func())
	SubscribeStatus(buffer int) (<-chan status.Snapshot, func())
	Version() string
}

type Server struct {
	Path string
	// PeerGID, when non-zero, is granted access via group ownership. The
	// daemon derives it from the owner of the config file, which is the user
	// whose menu bar needs to connect.
	PeerGID int
	Backend Backend
	Logf    func(string, ...any)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Serve listens until ctx-driven closure of the listener.
func (s *Server) Serve(done <-chan struct{}) error {
	path := s.Path
	if path == "" {
		path = DefaultSocket
	}

	if len(path) >= maxSocketPath {
		return fmt.Errorf("socket path is %d bytes, which exceeds the %d-byte limit for unix sockets: %s",
			len(path), maxSocketPath-1, path)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// A leftover socket file from a previous run would make Listen fail;
	// removing it is safe because a live daemon holds the lock on the port,
	// not the inode.
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen %s: %w", path, err)
	}

	if s.PeerGID > 0 {
		if err := os.Chown(path, 0, s.PeerGID); err != nil {
			s.logf("ipc: chown socket to gid %d: %v", s.PeerGID, err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		s.logf("ipc: chmod socket: %v", err)
	}

	go func() {
		<-done
		ln.Close()
		os.Remove(path)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logf("ipc: accept: %v", err)
			continue
		}
		go s.handle(conn, done)
	}
}

func (s *Server) handle(conn net.Conn, done <-chan struct{}) {
	defer conn.Close()

	dec := json.NewDecoder(bufio.NewReader(conn))
	enc := json.NewEncoder(conn)

	var req Request
	if err := dec.Decode(&req); err != nil {
		_ = enc.Encode(Response{Error: "malformed request"})
		return
	}

	switch req.Op {
	case OpStatus:
		snap := s.Backend.Snapshot()
		_ = enc.Encode(Response{OK: true, Status: &snap})

	case OpVersion:
		_ = enc.Encode(Response{OK: true, Version: s.Backend.Version()})

	case OpRetry:
		s.Backend.Retry()
		_ = enc.Encode(Response{OK: true})

	case OpPause, OpResume:
		if err := s.Backend.SetPaused(req.Op == OpPause); err != nil {
			_ = enc.Encode(Response{Error: err.Error()})
			return
		}
		snap := s.Backend.Snapshot()
		_ = enc.Encode(Response{OK: true, Status: &snap})

	case OpReload:
		result, err := s.Backend.Reload()
		if err != nil {
			_ = enc.Encode(Response{Error: err.Error()})
			return
		}
		_ = enc.Encode(Response{OK: true, Reload: result})

	case OpRestart:
		if err := s.Backend.Restart(req.Component); err != nil {
			_ = enc.Encode(Response{Error: err.Error()})
			return
		}
		_ = enc.Encode(Response{OK: true})

	case OpLogs:
		entries := s.Backend.Logs(req.Since, req.Source)
		if err := enc.Encode(Response{OK: true, Entries: entries}); err != nil {
			return
		}
		if !req.Follow {
			return
		}
		ch, release := s.Backend.SubscribeLogs(256)
		defer release()
		for {
			select {
			case <-done:
				return
			case e, ok := <-ch:
				if !ok {
					return
				}
				if req.Source != "" && e.Source != req.Source {
					continue
				}
				entry := e
				if err := enc.Encode(Response{OK: true, Entry: &entry}); err != nil {
					return
				}
			}
		}

	case OpStatusStream:
		snap := s.Backend.Snapshot()
		if err := enc.Encode(Response{OK: true, Status: &snap}); err != nil {
			return
		}
		ch, release := s.Backend.SubscribeStatus(16)
		defer release()
		for {
			select {
			case <-done:
				return
			case sn, ok := <-ch:
				if !ok {
					return
				}
				cur := sn
				if err := enc.Encode(Response{OK: true, Status: &cur}); err != nil {
					return
				}
			}
		}

	default:
		_ = enc.Encode(Response{Error: fmt.Sprintf("unknown op %q", req.Op)})
	}
}

// Client talks to the daemon.
type Client struct {
	Path    string
	Timeout time.Duration
}

func (c *Client) path() string {
	if c.Path == "" {
		return DefaultSocket
	}
	return c.Path
}

func (c *Client) dial() (net.Conn, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.DialTimeout("unix", c.path(), timeout)
	if err != nil {
		return nil, fmt.Errorf("%w\n\nIs the daemon running? Check with:\n  sudo launchctl print system/vpnctl", err)
	}
	return conn, nil
}

// Do sends one request and returns the first response.
func (c *Client) Do(req Request) (*Response, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return &resp, errors.New(strings.TrimSpace(resp.Error))
	}
	return &resp, nil
}

// Stream sends one request and calls onResponse for every reply until the
// connection closes or onResponse returns false.
func (c *Client) Stream(req Request, onResponse func(*Response) bool) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}

	dec := json.NewDecoder(bufio.NewReader(conn))
	for {
		var resp Response
		if err := dec.Decode(&resp); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if !resp.OK {
			return errors.New(strings.TrimSpace(resp.Error))
		}
		if !onResponse(&resp) {
			return nil
		}
	}
}
