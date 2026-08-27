package web

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vpn-router/internal/ipc"
	"vpn-router/internal/logbus"
	"vpn-router/internal/status"
)

// fakeDaemon is the smallest thing that satisfies the control protocol.
type fakeDaemon struct {
	bus *logbus.Bus
	// reloads counts what the resolver edits are supposed to trigger, and
	// reloadErr makes the daemon refuse one.
	reloads   atomic.Int32
	reloadErr error
}

func (f *fakeDaemon) Snapshot() status.Snapshot {
	comps := []status.Component{
		{Name: status.CompVPN, Phase: status.PhaseRunning, Detail: "tunnel up"},
		{Name: status.CompSingBox, Phase: status.PhaseRunning, Detail: "utun225 up"},
	}
	overall, reason := status.Aggregate(comps)
	return status.Snapshot{Overall: overall, Reason: reason, Components: comps, Version: "test"}
}

func (f *fakeDaemon) Restart(string) error { return nil }
func (f *fakeDaemon) Retry()               {}
func (f *fakeDaemon) Reload() (*status.ReloadResult, error) {
	f.reloads.Add(1)
	if f.reloadErr != nil {
		return nil, f.reloadErr
	}
	return &status.ReloadResult{}, nil
}
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
	s, _, url := serveFull(t)
	return s, url
}

// serveFull is serve for the tests that also have to look at the daemon.
func serveFull(t *testing.T) (*Server, *fakeDaemon, string) {
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
	return s, daemon, url
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

// rulesFile gives a server something to edit and returns its path.
func rulesFile(t *testing.T, s *Server, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "force-vpn.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s.RulesPath = path
	return path
}

func post(t *testing.T, url, body string, header ...string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

type rulesBody struct {
	Rules []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"rules"`
	Advanced []string `json:"advanced"`
	Types    []string `json:"types"`
	Editable bool     `json:"editable"`
	Error    string   `json:"error"`
}

// values pulls out one matcher's values, which is what most of these tests
// want to assert on.
func (b rulesBody) values(field string) []string {
	var out []string
	for _, r := range b.Rules {
		if r.Type == field {
			out = append(out, r.Value)
		}
	}
	return out
}

func rulesReply(t *testing.T, resp *http.Response) rulesBody {
	t.Helper()
	defer resp.Body.Close()

	var body rulesBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

func TestRulesEditEveryMatcherType(t *testing.T) {
	s, url := serve(t)
	rulesFile(t, s, `{"version":4,"rules":[{"domain_suffix":["a.example"],"process_name":["App"]}]}`)
	rules := strings.Replace(url, "/?t=", "/rules?t=", 1)

	got := rulesReply(t, post(t, rules, `{"op":"add","type":"domain_suffix","value":"https://Customer.Example/x"}`))
	if got.Error != "" {
		t.Fatalf("add: %s", got.Error)
	}
	if v := got.values("domain_suffix"); len(v) != 1 || v[0] != "customer.example" {
		t.Fatalf("after add: %v", v)
	}

	got = rulesReply(t, post(t, rules, `{"op":"add","type":"process_name","value":"CustomerApp"}`))
	if v := got.values("process_name"); len(v) != 1 || v[0] != "CustomerApp" {
		t.Fatalf("after adding a process: %v (%s)", v, got.Error)
	}

	got = rulesReply(t, post(t, rules,
		`{"op":"edit","type":"domain_suffix","value":"customer.example","to":"partner.example"}`))
	if v := got.values("domain_suffix"); got.Error != "" || len(v) != 1 || v[0] != "partner.example" {
		t.Fatalf("after edit: %v %q", v, got.Error)
	}

	got = rulesReply(t, post(t, rules, `{"op":"remove","type":"process_name","value":"CustomerApp"}`))
	if v := got.values("process_name"); got.Error != "" || len(v) != 0 {
		t.Fatalf("after remove: %v %q", v, got.Error)
	}

	// The hand-written rule is reported, not edited, and is still in the file.
	if len(got.Advanced) != 1 || !strings.Contains(got.Advanced[0], "process_name") {
		t.Errorf("advanced = %v, want the mixed rule", got.Advanced)
	}
	body, err := os.ReadFile(s.RulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"App"`) {
		t.Errorf("the mixed rule was lost:\n%s", body)
	}
}

// The page builds its type menu from this, so an empty or partial list would
// silently take matchers away from whoever is looking at it.
func TestRulesReportTheTypesTheyAccept(t *testing.T) {
	s, url := serve(t)
	rulesFile(t, s, `{"version":4,"rules":[]}`)

	resp, err := http.Get(strings.Replace(url, "/?t=", "/rules?t=", 1))
	if err != nil {
		t.Fatal(err)
	}
	got := rulesReply(t, resp)

	if !got.Editable {
		t.Error("a writable rules file reported as not editable")
	}
	for _, want := range []string{"domain_suffix", "domain_regex", "process_name", "process_path_regex"} {
		if !strings.Contains(strings.Join(got.Types, " "), want) {
			t.Errorf("types = %v, want %s among them", got.Types, want)
		}
	}
}

// A refused edit still reports the file's contents: the page shows what is
// true, not what was asked for.
func TestRulesRejectsRubbishAndSaysWhy(t *testing.T) {
	s, url := serve(t)
	rulesFile(t, s, `{"version":4,"rules":[{"domain_suffix":["a.example"]}]}`)
	rules := strings.Replace(url, "/?t=", "/rules?t=", 1)

	for _, body := range []string{
		`{"op":"add","type":"domain_suffix","value":"two words"}`,
		`{"op":"add","type":"domain_suffix","value":""}`,
		`{"op":"add","type":"ip_cidr","value":"10.0.0.0/8"}`,
		`{"op":"add","type":"domain_regex","value":"[unclosed"}`,
		`{"op":"edit","type":"domain_suffix","value":"missing.example","to":"b.example"}`,
		`{"op":"jump","type":"domain_suffix","value":"a.example"}`,
		`not json`,
	} {
		got := rulesReply(t, post(t, rules, body))
		if got.Error == "" {
			t.Errorf("%s was accepted", body)
		}
		if v := got.values("domain_suffix"); len(v) != 1 || v[0] != "a.example" {
			t.Errorf("%s: rules = %v, want the file unchanged", body, v)
		}
	}
}

// The token alone does not authorise a write: any page in this browser can be
// made to send one, and a name resolving to 127.0.0.1 would otherwise turn the
// whole web into a route editor.
func TestRulesRefusesCrossOriginWrites(t *testing.T) {
	s, url := serve(t)
	path := rulesFile(t, s, `{"version":4,"rules":[]}`)
	rules := strings.Replace(url, "/?t=", "/rules?t=", 1)

	cases := [][]string{
		{"Origin", "http://evil.example"},
		{"Sec-Fetch-Site", "cross-site"},
	}
	for _, header := range cases {
		resp := post(t, rules, `{"op":"add","type":"domain_suffix","value":"evil.example"}`, header...)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %s, want 403", header[0], resp.Status)
		}
	}

	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), "evil.example") {
		t.Errorf("a cross-origin request changed the rules:\n%s", body)
	}

	// The page's own fetch sends this, and it has to keep working.
	resp := post(t, rules, `{"op":"add","type":"domain_suffix","value":"good.example"}`,
		"Origin", strings.Split(url, "/?")[0],
		"Sec-Fetch-Site", "same-origin")
	if got := rulesReply(t, resp); len(got.values("domain_suffix")) != 1 {
		t.Errorf("the page's own write was refused: %v %q", got.Rules, got.Error)
	}
}

// A GET is what a browser can be tricked into making without any script, so
// the write must not be reachable that way.
func TestRulesReadsButDoesNotWriteOnGet(t *testing.T) {
	s, url := serve(t)
	rulesFile(t, s, `{"version":4,"rules":[{"domain_suffix":["a.example"]}]}`)
	rules := strings.Replace(url, "/?t=", "/rules?t=", 1)

	resp, err := http.Get(rules + "&op=remove&type=domain_suffix&value=a.example")
	if err != nil {
		t.Fatal(err)
	}
	got := rulesReply(t, resp)
	if len(got.values("domain_suffix")) != 1 || !got.Editable {
		t.Errorf("GET returned %v editable=%v", got.Rules, got.Editable)
	}

	req, _ := http.NewRequest(http.MethodDelete, rules, nil)
	del, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	del.Body.Close()
	if del.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE returned %s, want 405", del.Status)
	}
}

// Without a rules file the page must say so rather than showing an empty list
// that looks like "nothing is forced".
func TestRulesWithoutAFileIsNotEditable(t *testing.T) {
	_, url := serve(t)
	rules := strings.Replace(url, "/?t=", "/rules?t=", 1)

	got := rulesReply(t, post(t, rules, `{"op":"add","type":"domain_suffix","value":"a.example"}`))
	if got.Editable {
		t.Error("editable with no rules file configured")
	}
	if got.Error == "" {
		t.Error("no reason given for refusing the edit")
	}
}

// configFile gives a server a config to edit and returns its path.
func configFile(t *testing.T, s *Server, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s.ConfigPath = path
	return path
}

func resultError(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()

	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body.Error
}

const resolverConfig = "dns_router:\n  resolver_domains:\n    - corp.example\n"

func TestResolverEditsWriteTheConfigAndReload(t *testing.T) {
	s, daemon, url := serveFull(t)
	path := configFile(t, s, resolverConfig)
	endpoint := strings.Replace(url, "/?t=", "/resolvers?t=", 1)

	if got := resultError(t, post(t, endpoint, `{"op":"toggle","domain":"corp.example","enabled":false}`)); got != "" {
		t.Fatalf("toggle: %s", got)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "enabled: false") {
		t.Errorf("the domain was not switched off:\n%s", body)
	}

	if got := resultError(t, post(t, endpoint, `{"op":"add","domain":"https://Staging.Example/"}`)); got != "" {
		t.Fatalf("add: %s", got)
	}
	body, _ = os.ReadFile(path)
	if !strings.Contains(string(body), "staging.example") {
		t.Errorf("the added domain is not in the file:\n%s", body)
	}

	if got := resultError(t, post(t, endpoint, `{"op":"remove","domain":"corp.example"}`)); got != "" {
		t.Fatalf("remove: %s", got)
	}
	body, _ = os.ReadFile(path)
	if strings.Contains(string(body), "corp.example") {
		t.Errorf("the removed domain is still there:\n%s", body)
	}

	// A resolver domain does nothing until the daemon acts on it, so every
	// edit has to be applied rather than merely saved.
	if got := daemon.reloads.Load(); got != 3 {
		t.Errorf("the daemon was asked to reload %d times, want 3", got)
	}
}

// Saved-but-not-applied is its own answer: the file now claims something about
// this machine that is not true of it yet.
func TestResolverEditSaysWhenTheDaemonRefuses(t *testing.T) {
	s, daemon, url := serveFull(t)
	path := configFile(t, s, resolverConfig)
	daemon.reloadErr = errors.New("sing-box rejected the config")
	endpoint := strings.Replace(url, "/?t=", "/resolvers?t=", 1)

	got := resultError(t, post(t, endpoint, `{"op":"toggle","domain":"corp.example","enabled":false}`))
	if !strings.Contains(got, "saved, but not applied") {
		t.Errorf("error = %q, want it to say the edit was saved but not applied", got)
	}
	if body, _ := os.ReadFile(path); !strings.Contains(string(body), "enabled: false") {
		t.Errorf("the edit was not saved:\n%s", body)
	}
}

func TestResolverEditRefusesRubbish(t *testing.T) {
	s, daemon, url := serveFull(t)
	path := configFile(t, s, resolverConfig)
	endpoint := strings.Replace(url, "/?t=", "/resolvers?t=", 1)

	for _, body := range []string{
		`{"op":"add","domain":"two words"}`,
		`{"op":"add","domain":"corp.example"}`,
		`{"op":"remove","domain":"missing.example"}`,
		`{"op":"toggle","domain":"missing.example","enabled":true}`,
		`{"op":"jump","domain":"corp.example"}`,
		`not json`,
	} {
		if got := resultError(t, post(t, endpoint, body)); got == "" {
			t.Errorf("%s was accepted", body)
		}
	}

	if after, _ := os.ReadFile(path); after != nil && string(after) != resolverConfig {
		t.Errorf("a refused edit changed the file:\n%s", after)
	}
	if got := daemon.reloads.Load(); got != 0 {
		t.Errorf("the daemon was reloaded %d times for edits that never happened", got)
	}
}

func TestResolverEditsAreWritesToo(t *testing.T) {
	s, _, url := serveFull(t)
	path := configFile(t, s, resolverConfig)
	endpoint := strings.Replace(url, "/?t=", "/resolvers?t=", 1)

	resp := post(t, endpoint, `{"op":"remove","domain":"corp.example"}`, "Origin", "http://evil.example")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin: status %s, want 403", resp.Status)
	}

	get, err := http.Get(endpoint + "&op=remove&domain=corp.example")
	if err != nil {
		t.Fatal(err)
	}
	get.Body.Close()
	if get.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET returned %s, want 405", get.Status)
	}

	if body, _ := os.ReadFile(path); !strings.Contains(string(body), "corp.example") {
		t.Errorf("a refused request changed the config:\n%s", body)
	}
}

// Without a config path the page must not offer editing, and must refuse it if
// asked anyway.
func TestResolverEditsNeedAConfigPath(t *testing.T) {
	s, url := serve(t)
	endpoint := strings.Replace(url, "/?t=", "/resolvers?t=", 1)

	if got := resultError(t, post(t, endpoint, `{"op":"add","domain":"a.example"}`)); got == "" {
		t.Error("an edit was accepted with no config file")
	}

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	page, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "EDIT_RESOLVERS = false") {
		t.Error("the page offers resolver editing with no config file to edit")
	}
	if s.ConfigPath != "" {
		t.Errorf("this test needs a server with no config path, got %q", s.ConfigPath)
	}
}
