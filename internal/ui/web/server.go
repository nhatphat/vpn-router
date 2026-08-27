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
//
// Two things here write rather than read: the force-VPN rules and the scoped
// resolver domains. Both change how this machine routes and resolves, so they
// are held to more than the token — POST only, and only from this page,
// checked by origin. A GET a browser can be tricked into making must never be
// able to reach either.
package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"vpn-router/internal/config"
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
	// RulesPath is the force-VPN rule-set the page edits. Empty means the
	// page shows the domains it cannot find and offers no editing.
	RulesPath string
	// ConfigPath is the config file whose resolver domains the page edits.
	// Empty means the same: shown, not editable.
	ConfigPath string
	// IdleTimeout is how long the page waits, with nobody looking at it,
	// before closing its listener. Zero means defaultIdleTimeout.
	IdleTimeout time.Duration
	Logf        func(string, ...any)

	mu    sync.Mutex
	url   string
	token string
	tmpl  *template.Template
	srv   *http.Server
	idle  *time.Timer
	// active is the connections with a request in flight, and watching is how
	// many. The map is what makes the count survive a connection that goes
	// from active to idle and back.
	active   map[net.Conn]bool
	watching int
}

// defaultIdleTimeout is long enough that reloading the page, or a laptop
// coming back from sleep, does not count as leaving — and short enough that
// one look at the logs in the morning does not leave a port open all day.
const defaultIdleTimeout = 5 * time.Minute

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
	mux.HandleFunc("/rules", s.guard(s.handleRules))
	mux.HandleFunc("/resolvers", s.guard(s.handleResolvers))

	srv := &http.Server{
		Handler: mux,
		// No write timeout: the event streams are meant to stay open.
		ReadHeaderTimeout: 10 * time.Second,
		ConnState:         s.trackConn,
	}
	s.srv = srv

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logf("web: %v", err)
		}
	}()

	// Armed before anyone has connected: a page that was opened and never
	// looked at should not hold the port either.
	s.armIdleLocked()

	s.url = fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), s.token)
	s.logf("web: serving on %s", ln.Addr().String())
	return s.url, nil
}

// trackConn counts requests in flight, which for this page is the same thing
// as people looking at it: a tab holds its two streams open for as long as it
// is open, and lets go of them the moment it is not.
//
// Connections rather than requests would count the wrong thing. A browser
// keeps a spare connection pooled after the tab that made it has gone, so an
// open socket proves nothing; a request that is still being answered does.
func (s *Server) trackConn(conn net.Conn, state http.ConnState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch state {
	case http.StateActive:
		if s.active[conn] {
			return
		}
		if s.active == nil {
			s.active = map[net.Conn]bool{}
		}
		s.active[conn] = true
		s.watching++

		if s.idle != nil {
			s.idle.Stop()
			s.idle = nil
		}

	case http.StateIdle, http.StateClosed, http.StateHijacked:
		if s.active[conn] {
			delete(s.active, conn)
			s.watching--
		}
		if s.watching == 0 {
			s.armIdleLocked()
		}
	}
}

func (s *Server) armIdleLocked() {
	// Already counting down. Restarting it here would mean anything that
	// touches the port without asking it for anything — a probe, a stale tab
	// retrying a dead stream — could hold the page open indefinitely.
	if s.idle != nil {
		return
	}

	wait := s.IdleTimeout
	if wait <= 0 {
		wait = defaultIdleTimeout
	}
	s.idle = time.AfterFunc(wait, s.closeIfUnwatched)
}

// closeIfUnwatched gives the port back.
//
// The token goes with it. The next open is a new page with a new URL, which is
// the honest thing: the old one names a server that no longer exists, and a
// link that outlives what it points at is worse than one that plainly ends.
func (s *Server) closeIfUnwatched() {
	s.mu.Lock()
	if s.watching > 0 || s.srv == nil {
		s.mu.Unlock()
		return
	}

	srv := s.srv
	s.srv, s.url, s.token, s.idle = nil, "", "", nil
	s.active = nil
	s.mu.Unlock()

	// Close rather than Shutdown: there is nothing in flight to drain, and a
	// stream that is still open is precisely what watching == 0 rules out.
	if err := srv.Close(); err != nil {
		s.logf("web: close: %v", err)
	}
	s.logf("web: nobody watching; the page is closed until it is asked for again")
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
	// form-action too: the page posts with fetch, so a form that submits
	// anywhere is somebody else's idea rather than this page's.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'")

	data := struct {
		Token string
		// EditResolvers decides whether the resolver pills offer editing.
		// The list itself comes from the status stream either way.
		EditResolvers bool
		Sources       []logbus.Source
	}{
		Token:         s.token,
		EditResolvers: s.ConfigPath != "",
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

	err = s.Client.Stream(r.Context(), req, func(resp *ipc.Response) bool {
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

	err = s.Client.Stream(r.Context(), ipc.Request{Op: ipc.OpStatusStream}, func(resp *ipc.Response) bool {
		if resp.Status == nil {
			return true
		}
		return send("status", resp.Status) == nil
	})
	if err != nil {
		_ = send("error", map[string]string{"error": err.Error()})
	}
}

// ruleOp is what the page sends to change the force-VPN rules. One endpoint
// rather than three keeps the surface that can write small enough to read.
type ruleOp struct {
	Op    string `json:"op"`
	Type  string `json:"type"`
	Value string `json:"value"`
	To    string `json:"to"`
}

// handleRules lists the force-VPN matchers, and changes them on POST.
//
// Every reply carries the whole list, including the failures: the file is the
// truth and the page should not have to reconstruct it from what it hoped
// happened.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.sendRules(w, "")
	case http.MethodPost:
		if !writable(w, r) {
			return
		}
		s.applyRuleOp(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) applyRuleOp(w http.ResponseWriter, r *http.Request) {
	if s.RulesPath == "" {
		s.sendRules(w, "no force-VPN rules file is configured")
		return
	}

	var op ruleOp
	// Bounded because this is the one body the server reads, and it holds a
	// matcher.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&op); err != nil {
		s.sendRules(w, "unreadable request")
		return
	}

	var err error
	switch op.Op {
	case "add":
		_, err = config.AddForceVPNRule(s.RulesPath, op.Type, op.Value)
	case "remove":
		_, err = config.RemoveForceVPNRule(s.RulesPath, op.Type, op.Value)
	case "edit":
		_, err = config.EditForceVPNRule(s.RulesPath, op.Type, op.Value, op.To)
	default:
		s.sendRules(w, "unknown operation")
		return
	}

	if err != nil {
		s.sendRules(w, err.Error())
		return
	}
	s.logf("web: force-VPN rules: %s %s %s", op.Op, op.Type, op.Value)
	s.sendRules(w, "")
}

func (s *Server) sendRules(w http.ResponseWriter, problem string) {
	body := struct {
		Rules []config.ForceVPNRule `json:"rules"`
		// Advanced are the rules vpnctl will not edit, shown as they are so
		// the page never implies the file holds less than it does.
		Advanced []string `json:"advanced"`
		Types    []string `json:"types"`
		Editable bool     `json:"editable"`
		Error    string   `json:"error,omitempty"`
	}{
		Rules:    []config.ForceVPNRule{},
		Advanced: []string{},
		Types:    config.ForceVPNTypes(),
		Editable: s.RulesPath != "",
		Error:    problem,
	}

	if s.RulesPath != "" {
		rules, advanced, err := config.ForceVPNRules(s.RulesPath)
		if err != nil {
			// Reading failed, so the list is unknown rather than empty, and
			// saying "nothing is forced" here would be a lie.
			body.Editable = false
			if body.Error == "" {
				body.Error = err.Error()
			}
		} else {
			if rules != nil {
				body.Rules = rules
			}
			if advanced != nil {
				body.Advanced = advanced
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.logf("web: rules: %v", err)
	}
}

// handleResolvers changes the scoped resolver domains. There is nothing to GET:
// the list is already on the status stream, notes and all, and a second copy
// served from here would be a second answer to the same question.
//
// A change means writing the config and asking the daemon to apply it, so the
// reply says only whether that worked; the stream reports what it did.
func (s *Server) handleResolvers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !writable(w, r) {
		return
	}
	if s.ConfigPath == "" {
		sendResult(w, "no config file is known")
		return
	}

	var op resolverOp
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&op); err != nil {
		sendResult(w, "unreadable request")
		return
	}

	var err error
	switch op.Op {
	case "toggle":
		_, err = config.ToggleResolverDomain(s.ConfigPath, op.Domain, op.Enabled)
	case "add":
		_, err = config.AddResolverDomain(s.ConfigPath, op.Domain)
	case "remove":
		_, err = config.RemoveResolverDomain(s.ConfigPath, op.Domain)
	default:
		sendResult(w, "unknown operation")
		return
	}
	if err != nil {
		sendResult(w, err.Error())
		return
	}

	// Written but not applied is worth saying out loud: the file now claims
	// something about this machine that is not true of it yet.
	if _, err := s.Client.Do(ipc.Request{Op: ipc.OpReload}); err != nil {
		sendResult(w, "saved, but not applied: "+err.Error())
		return
	}

	s.logf("web: resolver domains: %s %s", op.Op, op.Domain)
	sendResult(w, "")
}

// resolverOp is what the page sends to change the scoped resolver domains.
type resolverOp struct {
	Op      string `json:"op"`
	Domain  string `json:"domain"`
	Enabled bool   `json:"enabled"`
}

func sendResult(w http.ResponseWriter, problem string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error,omitempty"`
	}{problem})
}

// writable reports whether a request may change anything, and answers it if
// not. Another origin's script cannot read the reply, but it could still have
// made the request, and with a write the request is the damage.
func writable(w http.ResponseWriter, r *http.Request) bool {
	if sameOrigin(r) {
		return true
	}
	http.Error(w, "cross-origin write", http.StatusForbidden)
	return false
}

// sameOrigin reports whether a write came from the page itself.
//
// It is the defence against a script on some other site posting here: the
// listener is on loopback, but every browser on this machine can reach it, and
// a name that resolves to 127.0.0.1 would otherwise turn any web page into a
// route editor. Fetch sends Origin on every POST, so a missing one is a
// non-browser caller that already had to know the token.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return origin == "http://"+r.Host
}
