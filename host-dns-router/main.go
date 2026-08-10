// host-dns-router is a small DNS server meant to sit behind sing-box's TUN
// (as its configured dns.servers upstream) on the macOS host.
//
// For every query it races two lookups in parallel:
//   - "public"   -> a normal public DNS resolver, dialed directly off the
//     physical interface so it bypasses the TUN's default route.
//   - "internal" -> the corporate DNS server pushed by the VPN, reached over
//     the container's SOCKS5 proxy using UDP ASSOCIATE.
//
// If the internal branch answers with a private/CGNAT IP, that answer wins
// immediately: sing-box's existing "private IP -> SOCKS" route rule then
// takes care of routing without ever needing a per-domain rule. Otherwise the
// public answer is used, falling back to a non-private internal answer, and
// finally to SERVFAIL if both branches fail.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// internalDNS tracks the VPN-pushed internal DNS server IPs (a VPN commonly
// pushes more than one, e.g. a primary/secondary pair), refreshed
// periodically by reading /run/vpn-dns from inside the VPN container.
type internalDNS struct {
	mu        sync.RWMutex
	addrs     []string
	container string
}

func newInternalDNS(container string, interval time.Duration) *internalDNS {
	d := &internalDNS{container: container}
	d.refresh()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			d.refresh()
		}
	}()

	return d
}

func (d *internalDNS) refresh() {
	out, err := exec.Command("docker", "exec", d.container, "cat", "/run/vpn-dns").Output()
	if err != nil {
		log.Printf("internal-dns: refresh failed: %v", err)
		return
	}

	addrs := strings.Fields(string(out))

	d.mu.Lock()
	defer d.mu.Unlock()

	if !equalStrings(addrs, d.addrs) {
		log.Printf("internal-dns: servers changed %v -> %v", d.addrs, addrs)
		d.addrs = addrs
	}
}

func (d *internalDNS) get() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, len(d.addrs))
	copy(out, d.addrs)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// resolver implements the dual-lookup + decision logic for one query.
type resolver struct {
	publicAddr   string
	bindIP       net.IP
	socksAddr    string
	internal     *internalDNS
	queryTimeout time.Duration
	graceWindow  time.Duration
}

var privateBlocks = mustParseCIDRs(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10", // CGNAT, also used by some corporate VPNs
	"fc00::/7",      // IPv6 ULA
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	blocks := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, block, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		blocks = append(blocks, block)
	}
	return blocks
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func firstIP(m *dns.Msg) net.IP {
	if m == nil {
		return nil
	}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			return v.A
		case *dns.AAAA:
			return v.AAAA
		}
	}
	return nil
}

func qname(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return "?"
	}
	return m.Question[0].Name
}

// queryPublic resolves m against the public resolver, binding the local
// source address to the physical interface so the query never gets recaptured
// by the TUN it is meant to bypass.
func (r *resolver) queryPublic(m *dns.Msg) (*dns.Msg, error) {
	dialer := &net.Dialer{Timeout: r.queryTimeout}
	if r.bindIP != nil {
		dialer.LocalAddr = &net.UDPAddr{IP: r.bindIP}
	}

	conn, err := dialer.Dial("udp", r.publicAddr)
	if err != nil {
		return nil, fmt.Errorf("dial public dns: %w", err)
	}
	defer conn.Close()

	client := &dns.Client{Timeout: r.queryTimeout}
	resp, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
	return resp, err
}

// queryInternal resolves m against every VPN-pushed DNS server in parallel,
// tunneled over the container's SOCKS5 proxy using DNS-over-UDP. A VPN
// commonly pushes more than one server (primary/secondary); a private-IP
// answer from any of them wins immediately, otherwise the first successful
// answer is used.
func (r *resolver) queryInternal(m *dns.Msg) (*dns.Msg, error) {
	ips := r.internal.get()
	if len(ips) == 0 {
		return nil, fmt.Errorf("internal dns server not known yet")
	}

	type branch struct {
		resp *dns.Msg
		err  error
	}

	results := make(chan branch, len(ips))
	for _, ip := range ips {
		ip := ip
		go func() {
			resp, err := r.queryInternalAt(ip, m.Copy())
			results <- branch{resp, err}
		}()
	}

	var firstOK *branch
	var lastErr error
	for range ips {
		b := <-results
		if b.err != nil {
			lastErr = b.err
			continue
		}
		if isPrivateIP(firstIP(b.resp)) {
			return b.resp, nil
		}
		if firstOK == nil {
			bCopy := b
			firstOK = &bCopy
		}
	}

	if firstOK != nil {
		return firstOK.resp, nil
	}
	return nil, lastErr
}

func (r *resolver) queryInternalAt(ip string, m *dns.Msg) (*dns.Msg, error) {
	target := &net.UDPAddr{IP: net.ParseIP(ip), Port: 53}

	conn, err := socksUDPAssociate(r.socksAddr, target, r.queryTimeout)
	if err != nil {
		return nil, fmt.Errorf("udp associate to %s via socks: %w", ip, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(r.queryTimeout))

	client := &dns.Client{Timeout: r.queryTimeout}
	resp, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, fmt.Errorf("exchange with %s: %w", ip, err)
	}
	return resp, nil
}

type branchResult struct {
	resp *dns.Msg
	err  error
}

// resolve races both branches and applies the decision rules described in
// the file header comment.
func (r *resolver) resolve(req *dns.Msg) *dns.Msg {
	publicCh := make(chan branchResult, 1)
	internalCh := make(chan branchResult, 1)

	go func() {
		resp, err := r.queryPublic(req.Copy())
		publicCh <- branchResult{resp, err}
	}()
	go func() {
		resp, err := r.queryInternal(req.Copy())
		internalCh <- branchResult{resp, err}
	}()

	var pub, intr branchResult
	pubDone, intrDone := false, false

	// Bounds how long we wait overall. Once public already has a good
	// answer, this shrinks to a short grace window instead of the full
	// query timeout: otherwise every ordinary public lookup would be
	// stalled by the internal branch's full timeout whenever the internal
	// resolver stays silent for out-of-zone domains (observed in practice).
	deadline := time.After(r.queryTimeout + 200*time.Millisecond)

	for !pubDone || !intrDone {
		select {
		case pub = <-publicCh:
			pubDone = true
			if pub.err == nil && pub.resp != nil && pub.resp.Rcode == dns.RcodeSuccess && !intrDone {
				deadline = time.After(r.graceWindow)
			}
		case intr = <-internalCh:
			intrDone = true
		case <-deadline:
			pubDone, intrDone = true, true
		}

		// Fast path: an internal/private answer is authoritative on its own,
		// no need to wait for the public branch.
		if intrDone && intr.err == nil && isPrivateIP(firstIP(intr.resp)) {
			break
		}
	}

	switch {
	case intr.err == nil && isPrivateIP(firstIP(intr.resp)):
		log.Printf("%s -> internal/private %s (socks)", qname(req), firstIP(intr.resp))
		return intr.resp

	case pub.err == nil && pub.resp != nil && pub.resp.Rcode == dns.RcodeSuccess:
		log.Printf("%s -> public %s (direct)", qname(req), firstIP(pub.resp))
		return pub.resp

	case intr.err == nil && intr.resp != nil && intr.resp.Rcode == dns.RcodeSuccess:
		log.Printf("%s -> internal/non-private %s (socks fallback)", qname(req), firstIP(intr.resp))
		return intr.resp

	default:
		log.Printf("%s -> failed (public_err=%v internal_err=%v)", qname(req), pub.err, intr.err)
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		return fail
	}
}

func interfaceIPv4(name string) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			return ip4, nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on interface %s", name)
}

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:15353", "address to listen on for DNS queries from sing-box")
	publicDNS := flag.String("public-dns", "1.1.1.1:53", "upstream public DNS server")
	bindInterface := flag.String("bind-interface", "en0", "physical interface to bind public DNS queries to, bypassing the TUN's default route")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy address exposed by the VPN container")
	container := flag.String("container", "vpn-router-vpn-1", "docker container name/id running the VPN")
	refreshInterval := flag.Duration("dns-refresh-interval", 30*time.Second, "how often to re-read the internal DNS server IP from the container")
	queryTimeout := flag.Duration("query-timeout", 900*time.Millisecond, "timeout for each lookup branch")
	graceWindow := flag.Duration("grace-window", 200*time.Millisecond, "extra time to wait for the internal branch after public already succeeded, in case internal wins with a private-IP answer")
	racerListenAddr := flag.String("racer-listen", "127.0.0.1:15080", "address for the tier-2 race-dial SOCKS5 server (for ambiguous public-IP destinations that might need the VPN)")
	dialTimeout := flag.Duration("dial-timeout", 1500*time.Millisecond, "timeout for each side of the tier-2 direct-vs-socks race")
	flag.Parse()

	var bindIP net.IP
	if *bindInterface != "" {
		ip, err := interfaceIPv4(*bindInterface)
		if err != nil {
			log.Fatalf("resolve bind interface %s: %v", *bindInterface, err)
		}
		bindIP = ip
		log.Printf("binding public DNS queries to %s (%s)", *bindInterface, ip)
	}

	r := &resolver{
		publicAddr:   *publicDNS,
		bindIP:       bindIP,
		socksAddr:    *socksAddr,
		internal:     newInternalDNS(*container, *refreshInterval),
		queryTimeout: *queryTimeout,
		graceWindow:  *graceWindow,
	}

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) != 1 {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeFormatError)
			_ = w.WriteMsg(m)
			return
		}
		_ = w.WriteMsg(r.resolve(req))
	})

	rc := &racer{
		bindIP:      bindIP,
		socksAddr:   *socksAddr,
		dialTimeout: *dialTimeout,
	}

	errCh := make(chan error, 2)

	go func() {
		server := &dns.Server{Addr: *listenAddr, Net: "udp"}
		log.Printf("dns: listening on %s (udp), socks=%s, container=%s", *listenAddr, *socksAddr, *container)
		errCh <- fmt.Errorf("dns server: %w", server.ListenAndServe())
	}()

	go func() {
		errCh <- fmt.Errorf("racer server: %w", startRacer(*racerListenAddr, rc))
	}()

	log.Fatal(<-errCh)
}
