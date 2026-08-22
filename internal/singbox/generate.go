// Package singbox generates sing-box's config.json from vpnctl's config.
//
// The generated document is a faithful reproduction of the hand-written
// singbox/config.json that this project ran before vpnctl existed: the
// routing and DNS behaviour is deliberately unchanged, and a golden test
// asserts that. Only values that were previously duplicated between the
// JSON and the router's command-line flags (ports, interface, paths) now
// come from a single place.
package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"vpn-router/internal/config"
)

// Input is the minimal set of values the document depends on. It is kept
// separate from config.Config so tests can pin exact values (including
// repo-relative paths) without going through path resolution.
type Input struct {
	LogLevel string

	DNSRouterHost string
	DNSRouterPort int

	TUNInterfaceName string
	TUNAddress       []string
	TUNMTU           int
	TUNStrictRoute   bool
	TUNStack         string

	SocksHost string
	SocksPort int

	RacerHost string
	RacerPort int

	ForceVPNRulesPath string

	// RouterProcessName keeps the DNS router's own direct traffic from being
	// recaptured by the TUN. It must match the name of the process that owns
	// the router's sockets: "host-dns-router" historically, "vpnctl" now.
	RouterProcessName string

	RawOverrides map[string]any
}

// FromConfig maps a loaded config onto the generator input. routerProcess is
// the running executable's name, which the caller resolves.
func FromConfig(cfg *config.Config, routerProcess string) (Input, error) {
	dnsHost, dnsPort, err := splitHostPort(cfg.DNSRouter.Listen, "dns_router.listen")
	if err != nil {
		return Input{}, err
	}
	socksHost, socksPort, err := splitHostPort(cfg.Docker.Socks, "docker.socks")
	if err != nil {
		return Input{}, err
	}
	racerHost, racerPort, err := splitHostPort(cfg.Racer.Listen, "racer.listen")
	if err != nil {
		return Input{}, err
	}

	name := cfg.SingBox.RouterProcessName
	if name == "" {
		name = routerProcess
	}

	return Input{
		LogLevel:          cfg.SingBox.LogLevel,
		DNSRouterHost:     dnsHost,
		DNSRouterPort:     dnsPort,
		TUNInterfaceName:  cfg.SingBox.TUN.InterfaceName,
		TUNAddress:        cfg.SingBox.TUN.Address,
		TUNMTU:            cfg.SingBox.TUN.MTU,
		TUNStrictRoute:    cfg.SingBox.TUN.StrictRoute,
		TUNStack:          cfg.SingBox.TUN.Stack,
		SocksHost:         socksHost,
		SocksPort:         socksPort,
		RacerHost:         racerHost,
		RacerPort:         racerPort,
		ForceVPNRulesPath: cfg.SingBox.ForceVPNRules,
		RouterProcessName: name,
		RawOverrides:      cfg.SingBox.RawOverrides,
	}, nil
}

func splitHostPort(addr, field string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%s: %w", field, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("%s: bad port %q", field, portStr)
	}
	return host, port, nil
}

// Field order in these structs is the JSON key order of the generated
// document; it matches the hand-written original so diffs stay readable.

type doc struct {
	Log       logSection `json:"log"`
	DNS       dnsSection `json:"dns"`
	Inbounds  []any      `json:"inbounds"`
	Outbounds []any      `json:"outbounds"`
	Route     route      `json:"route"`
}

type logSection struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type dnsSection struct {
	Servers []dnsServer `json:"servers"`
	Final   string      `json:"final"`
}

type dnsServer struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

type tunInbound struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	InterfaceName string   `json:"interface_name"`
	Address       []string `json:"address"`
	MTU           int      `json:"mtu"`
	AutoRoute     bool     `json:"auto_route"`
	StrictRoute   bool     `json:"strict_route"`
	Stack         string   `json:"stack"`
}

type directOutbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

type socksOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Version    string `json:"version"`
	Network    string `json:"network,omitempty"`
}

type route struct {
	AutoDetectInterface bool      `json:"auto_detect_interface"`
	RuleSet             []ruleSet `json:"rule_set"`
	Rules               []any     `json:"rules"`
	Final               string    `json:"final"`
}

type ruleSet struct {
	Type   string `json:"type"`
	Tag    string `json:"tag"`
	Format string `json:"format"`
	Path   string `json:"path"`
}

type processRule struct {
	ProcessName []string `json:"process_name"`
	Action      string   `json:"action"`
	Outbound    string   `json:"outbound"`
}

type portRule struct {
	Port   int    `json:"port"`
	Action string `json:"action"`
}

type sniffRule struct {
	Action  string   `json:"action"`
	Sniffer []string `json:"sniffer"`
}

type ruleSetRule struct {
	RuleSet  []string `json:"rule_set"`
	Action   string   `json:"action"`
	Outbound string   `json:"outbound"`
}

type cidrRule struct {
	IPCIDR   []string `json:"ip_cidr"`
	Outbound string   `json:"outbound"`
}

type networkRule struct {
	Network  string `json:"network"`
	Outbound string `json:"outbound"`
}

// Build assembles the document. The rule order is load-bearing: the
// process_name rule must precede hijack-dns (or the router's own queries
// loop back into the TUN), and the fail-closed rules (force-vpn, private
// CIDRs) must precede anything that can send traffic out directly.
func Build(in Input) doc {
	return doc{
		Log: logSection{Level: in.LogLevel, Timestamp: true},
		DNS: dnsSection{
			Servers: []dnsServer{{
				Type:       "udp",
				Tag:        "host-dns-router",
				Server:     in.DNSRouterHost,
				ServerPort: in.DNSRouterPort,
			}},
			Final: "host-dns-router",
		},
		Inbounds: []any{tunInbound{
			Type:          "tun",
			Tag:           "tun-in",
			InterfaceName: in.TUNInterfaceName,
			Address:       in.TUNAddress,
			MTU:           in.TUNMTU,
			AutoRoute:     true,
			StrictRoute:   in.TUNStrictRoute,
			Stack:         in.TUNStack,
		}},
		Outbounds: []any{
			directOutbound{Type: "direct", Tag: "direct"},
			socksOutbound{
				Type:       "socks",
				Tag:        "vpn-direct",
				Server:     in.SocksHost,
				ServerPort: in.SocksPort,
				Version:    "5",
			},
			socksOutbound{
				Type:       "socks",
				Tag:        "racer",
				Server:     in.RacerHost,
				ServerPort: in.RacerPort,
				Version:    "5",
				Network:    "tcp",
			},
		},
		Route: route{
			AutoDetectInterface: true,
			RuleSet: []ruleSet{{
				Type:   "local",
				Tag:    "force-vpn",
				Format: "source",
				Path:   in.ForceVPNRulesPath,
			}},
			Rules: []any{
				processRule{
					ProcessName: []string{in.RouterProcessName},
					Action:      "route",
					Outbound:    "direct",
				},
				portRule{Port: 53, Action: "hijack-dns"},
				sniffRule{Action: "sniff", Sniffer: []string{"http", "tls", "quic"}},
				ruleSetRule{
					RuleSet:  []string{"force-vpn"},
					Action:   "route",
					Outbound: "vpn-direct",
				},
				cidrRule{
					IPCIDR:   []string{"192.168.0.0/16", "172.16.0.0/12"},
					Outbound: "direct",
				},
				cidrRule{
					IPCIDR:   []string{"10.0.0.0/8", "100.64.0.0/10", "fc00::/7"},
					Outbound: "vpn-direct",
				},
				networkRule{Network: "udp", Outbound: "direct"},
			},
			Final: "racer",
		},
	}
}

// Generate renders the document as JSON, applying raw_overrides if any.
//
// Without overrides the typed structs are marshalled directly, preserving
// the field order above. With overrides the document must round-trip through
// a generic map to be merged, which reorders keys alphabetically; the
// document stays semantically identical either way.
func Generate(in Input) ([]byte, error) {
	d := Build(in)

	if len(in.RawOverrides) == 0 {
		out, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(out, '\n'), nil
	}

	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	deepMerge(generic, in.RawOverrides)

	out, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// deepMerge overlays src onto dst, recursing into nested objects. Any
// non-object value in src replaces dst's value outright, so an override can
// swap a whole rules array without having to describe it element by element.
func deepMerge(dst, src map[string]any) {
	for k, sv := range src {
		if sm, ok := sv.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, sm)
				continue
			}
		}
		dst[k] = sv
	}
}

// Validate asks sing-box itself whether a generated document is acceptable.
//
// It runs before a reload swaps anything in, so a configuration sing-box would
// reject never reaches disk and never causes a restart. Validating with the
// real binary rather than a schema of our own is the point: the binary is the
// authority on what it accepts, and it changes between versions.
func Validate(binary string, doc []byte) error {
	if binary == "" {
		return fmt.Errorf("no sing-box binary to validate with")
	}

	tmp, err := os.CreateTemp("", "vpnctl-check-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(doc); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	out, err := exec.Command(binary, "check", "-c", tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box rejected the configuration: %v\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
