// Package web serves a live status and log page.
//
// It runs in the menu bar process, not in the daemon, and that is deliberate.
// The daemon is root; an HTTP listener has no natural way to authenticate a
// local caller, so putting one there would hand every process on the machine a
// window into a root service. Running it as the user means the page can only
// expose what that user could already read through the control socket, which
// the daemon restricts to their group.
//
// A random token in the URL closes the remaining gap: a loopback listener is
// still reachable by any local process, including other users' processes.
package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"vpn-router/internal/ipc"
	"vpn-router/internal/logbus"
)

//go:embed index.html
var pages embed.FS

type Server struct {
	// Addr is the loopback address to listen on.
	Addr string
	// Client talks to the daemon on the viewer's behalf.
	Client *ipc.Client
	Logf   func(string, ...any)

	mu    sync.Mutex
	url   string
	token string
	tmpl  *template.Template
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// URL starts the server if it is not running yet and returns the address to
// open. Starting lazily keeps a listener off the machine until someone asks
// to look at something.
func (s *Server) URL() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.url != "" {
		return s.url, nil
	}

	tmpl, err := template.ParseFS(pages, "index.html")
	if err != nil {
		return "", err
	}
	s.tmpl = tmpl

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	s.token = hex.EncodeToString(buf)

	addr := s.Addr
	if addr == "" {
		addr = "127.0.0.1:15900"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("listen %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.guard(s.handleIndex))
	mux.HandleFunc("/events/logs", s.guard(s.handleLogEvents))
	mux.HandleFunc("/events/status", s.guard(s.handleStatusEvents))

	srv := &http.Server{
		Handler: mux,
		// No write timeout: the event streams are meant to stay open.
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.Serve(ln); err != nil {
			s.logf("web: %v", err)
		}
	}()

	s.url = fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), s.token)
	s.logf("web: serving on %s", ln.Addr().String())
	return s.url, nil
}

// guard rejects a request without the token. It compares in constant time out
// of habit rather than necessity; the token is single-use-per-session and not
// worth an oracle either way.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !equalConstantTime(r.URL.Query().Get("t"), s.token) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		next(w, r)
	}
}

func equalConstantTime(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Nothing here loads anything remote, and saying so keeps it that way.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")

	data := struct {
		Token   string
		Sources []logbus.Source
	}{
		Token: s.token,
		Sources: []logbus.Source{
			logbus.SourceSupervisor, logbus.SourceSingBox,
			logbus.SourceVPN, logbus.SourceDNS, logbus.SourceRacer,
		},
	}

	if err := s.tmpl.Execute(w, data); err != nil {
		s.logf("web: render: %v", err)
	}
}

// sseWriter prepares a response for server-sent events and returns a function
// that sends one.
func sseWriter(w http.ResponseWriter) (func(event string, v any) error, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming unsupported")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	return func(event string, v any) error {
		payload, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}, nil
}

func (s *Server) handleLogEvents(w http.ResponseWriter, r *http.Request) {
	send, err := sseWriter(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var since uint64
	if v := r.URL.Query().Get("since"); v != "" {
		since, _ = strconv.ParseUint(v, 10, 64)
	}

	req := ipc.Request{
		Op:     ipc.OpLogs,
		Since:  since,
		Source: logbus.Source(r.URL.Query().Get("source")),
		Follow: true,
	}

	done := r.Context().Done()

	err = s.Client.Stream(req, func(resp *ipc.Response) bool {
		select {
		case <-done:
			return false
		default:
		}

		if len(resp.Entries) > 0 {
			if send("batch", resp.Entries) != nil {
				return false
			}
		}
		if resp.Entry != nil {
			if send("entry", resp.Entry) != nil {
				return false
			}
		}
		return true
	})
	if err != nil {
		_ = send("error", map[string]string{"error": err.Error()})
	}
}

func (s *Server) handleStatusEvents(w http.ResponseWriter, r *http.Request) {
	send, err := sseWriter(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	done := r.Context().Done()

	err = s.Client.Stream(ipc.Request{Op: ipc.OpStatusStream}, func(resp *ipc.Response) bool {
		select {
		case <-done:
			return false
		default:
		}
		if resp.Status == nil {
			return true
		}
		return send("status", resp.Status) == nil
	})
	if err != nil {
		_ = send("error", map[string]string{"error": err.Error()})
	}
}
