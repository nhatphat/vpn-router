// Package dockerctl is a minimal Docker Engine API client, speaking HTTP over
// the daemon's unix socket.
//
// It is hand-written rather than using the official SDK for two reasons. The
// operations vpnctl needs are few — find the container, inspect its health,
// restart it, stream its events and logs, and read one file out of it — and
// the SDK would pull in a very large dependency tree for them. More
// importantly, vpnctl's daemon runs as root, and a verified property of this
// setup is that the `docker` CLI is a user-owned symlink into an application
// bundle: shelling out to it would mean root executing a binary an
// unprivileged writer controls. Talking to the socket avoids that entirely.
package dockerctl

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// apiVersion is pinned below the daemon's advertised version so a newer
// daemon does not change response shapes underneath us. The verified daemon
// here advertises 1.54 with a minimum of 1.40.
const apiVersion = "v1.44"

// DefaultSocket is a system-wide path, deliberately not the per-user one:
// the daemon has no user session and no HOME to resolve it from.
const DefaultSocket = "/var/run/docker.sock"

type Client struct {
	http *http.Client
	// host is the value used in request URLs; irrelevant for unix sockets
	// but required to form a valid URL.
	host   string
	scheme string
}

// New builds a client for a DOCKER_HOST-style address. An empty addr means
// the default unix socket.
func New(addr string) (*Client, error) {
	if addr == "" {
		addr = "unix://" + DefaultSocket
	}

	switch {
	case strings.HasPrefix(addr, "unix://"):
		path := strings.TrimPrefix(addr, "unix://")
		return &Client{
			scheme: "http",
			host:   "docker",
			http: &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, "unix", path)
					},
				},
			},
		}, nil

	case strings.HasPrefix(addr, "tcp://"), strings.HasPrefix(addr, "http://"):
		u, err := url.Parse(addr)
		if err != nil {
			return nil, err
		}
		return &Client{
			scheme: "http",
			host:   u.Host,
			http:   &http.Client{Transport: &http.Transport{}},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported docker host %q (want unix:// or tcp://)", addr)
	}
}

func (c *Client) url(path string, q url.Values) string {
	u := url.URL{Scheme: c.scheme, Host: c.host, Path: "/" + apiVersion + path}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.url(path, q), rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("docker %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.do(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// Ping reports whether the daemon is reachable. A failure here is expected
// and non-fatal: on this platform the container runtime only exists once a
// user is logged in, so the supervisor has to run without it.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		(&url.URL{Scheme: c.scheme, Host: c.host, Path: "/_ping"}).String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker ping: %s", resp.Status)
	}
	return nil
}

type Container struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
}

// Name returns the container's primary name without the leading slash.
func (c Container) Name() string {
	if len(c.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// FindByComposeProject locates the container compose created for a project,
// which is more durable than matching a generated container name.
func (c *Client) FindByComposeProject(ctx context.Context, project, service string) (*Container, error) {
	labels := []string{"com.docker.compose.project=" + project}
	if service != "" {
		labels = append(labels, "com.docker.compose.service="+service)
	}
	filters, err := json.Marshal(map[string][]string{"label": labels})
	if err != nil {
		return nil, err
	}

	q := url.Values{"all": {"1"}, "filters": {string(filters)}}

	var list []Container
	if err := c.getJSON(ctx, "/containers/json", q, &list); err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no container for compose project %q", project)
	}
	return &list[0], nil
}

// FindByName is the fallback for a container that compose did not create.
func (c *Client) FindByName(ctx context.Context, name string) (*Container, error) {
	filters, err := json.Marshal(map[string][]string{"name": {"^/" + name + "$"}})
	if err != nil {
		return nil, err
	}

	var list []Container
	if err := c.getJSON(ctx, "/containers/json",
		url.Values{"all": {"1"}, "filters": {string(filters)}}, &list); err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no container named %q", name)
	}
	return &list[0], nil
}

type State struct {
	Status     string `json:"Status"` // created running paused restarting removing exited dead
	Running    bool   `json:"Running"`
	ExitCode   int    `json:"ExitCode"`
	StartedAt  string `json:"StartedAt"`
	FinishedAt string `json:"FinishedAt"`
	Health     *struct {
		Status        string `json:"Status"` // starting healthy unhealthy
		FailingStreak int    `json:"FailingStreak"`
	} `json:"Health"`
}

type Inspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	State  State  `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func (c *Client) Inspect(ctx context.Context, id string) (*Inspect, error) {
	var out Inspect
	if err := c.getJSON(ctx, "/containers/"+id+"/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HealthStatus reports the container's healthcheck verdict, or "none" when the
// image declares no healthcheck.
func (i *Inspect) HealthStatus() string {
	if i.State.Health == nil {
		return "none"
	}
	return i.State.Health.Status
}

func (c *Client) Restart(ctx context.Context, id string, timeout time.Duration) error {
	q := url.Values{"t": {strconv.Itoa(int(timeout.Seconds()))}}
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/restart", q, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *Client) Start(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *Client) Stop(ctx context.Context, id string, timeout time.Duration) error {
	q := url.Values{"t": {strconv.Itoa(int(timeout.Seconds()))}}
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/stop", q, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time int64 `json:"time"`
}

// Events streams container events for one compose project until ctx is
// cancelled or the connection drops. The caller is expected to reconnect;
// a dropped stream usually means the daemon went away, which is itself
// information the supervisor wants.
func (c *Client) Events(ctx context.Context, project string) (<-chan Event, <-chan error, error) {
	filters, err := json.Marshal(map[string][]string{
		"type":  {"container"},
		"label": {"com.docker.compose.project=" + project},
	})
	if err != nil {
		return nil, nil, err
	}

	resp, err := c.do(ctx, http.MethodGet, "/events", url.Values{"filters": {string(filters)}}, nil)
	if err != nil {
		return nil, nil, err
	}

	events := make(chan Event, 16)
	errs := make(chan error, 1)

	go func() {
		defer resp.Body.Close()
		defer close(events)
		defer close(errs)

		dec := json.NewDecoder(resp.Body)
		for {
			var e Event
			if err := dec.Decode(&e); err != nil {
				if ctx.Err() == nil {
					errs <- err
				}
				return
			}
			select {
			case events <- e:
			case <-ctx.Done():
				return
			}
		}
	}()

	return events, errs, nil
}

// Logs opens the container's log stream. The returned reader is in Docker's
// multiplexed frame format; pass it to DemuxLines.
func (c *Client) Logs(ctx context.Context, id string, follow bool, tail int) (io.ReadCloser, error) {
	q := url.Values{
		"stdout": {"1"},
		"stderr": {"1"},
		"tail":   {strconv.Itoa(tail)},
	}
	if follow {
		q.Set("follow", "1")
	}

	resp, err := c.do(ctx, http.MethodGet, "/containers/"+id+"/logs", q, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// StdStream identifies which of the container's streams a frame came from.
type StdStream byte

const (
	StreamStdin  StdStream = 0
	StreamStdout StdStream = 1
	StreamStderr StdStream = 2
)

// DemuxLines reads Docker's 8-byte-header stream format and calls onLine for
// every complete line. Docker only uses this framing when the container has
// no TTY; with a TTY the payload is raw, which is detected by an implausible
// header and handled by falling back to plain line reading.
func DemuxLines(r io.Reader, onLine func(stream StdStream, line string)) error {
	header := make([]byte, 8)
	var carry [3][]byte

	flush := func(s StdStream, chunk []byte) {
		buf := append(carry[s], chunk...)
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			onLine(s, strings.TrimRight(string(buf[:i]), "\r"))
			buf = buf[i+1:]
		}
		carry[s] = append(carry[s][:0], buf...)
	}

	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}

		stream := StdStream(header[0])
		if stream > StreamStderr || header[1] != 0 || header[2] != 0 || header[3] != 0 {
			// Not framed: treat what we have plus the rest as raw text.
			rest, _ := io.ReadAll(r)
			flush(StreamStdout, append(header, rest...))
			return nil
		}

		size := binary.BigEndian.Uint32(header[4:8])
		if size == 0 {
			continue
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			return err
		}
		flush(stream, payload)
	}
}

// ReadFile returns the contents of one file inside the container, used for
// the VPN-pushed DNS server list when the shared bind mount is unavailable.
func (c *Client) ReadFile(ctx context.Context, id, path string) ([]byte, error) {
	create := map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          []string{"cat", path},
	}

	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/exec", nil, create)
	if err != nil {
		return nil, err
	}
	var created struct {
		ID string `json:"Id"`
	}
	err = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	start, err := c.do(ctx, http.MethodPost, "/exec/"+created.ID+"/start", nil,
		map[string]any{"Detach": false, "Tty": false})
	if err != nil {
		return nil, err
	}
	defer start.Body.Close()

	var out bytes.Buffer
	err = DemuxLines(start.Body, func(s StdStream, line string) {
		if s == StreamStdout {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
