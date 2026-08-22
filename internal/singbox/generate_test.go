package singbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// historicalInput is the exact set of values the project ran by hand before
// vpnctl existed: singbox/config.json plus the host-dns-router flags.
func historicalInput() Input {
	return Input{
		LogLevel:          "warn",
		DNSRouterHost:     "127.0.0.1",
		DNSRouterPort:     15353,
		TUNInterfaceName:  "utun225",
		TUNAddress:        []string{"172.19.0.1/30"},
		TUNMTU:            9000,
		TUNStrictRoute:    true,
		TUNStack:          "gvisor",
		SocksHost:         "127.0.0.1",
		SocksPort:         1080,
		RacerHost:         "127.0.0.1",
		RacerPort:         15080,
		ForceVPNRulesPath: "singbox/rules/force-vpn.json",
		RouterProcessName: "host-dns-router",
	}
}

// TestGeneratedMatchesCommitted is the guarantee that vpnctl did not change
// the data path: the generated document must be identical to the config.json
// this project has been running.
//
// If this test fails, either the generator drifted or somebody intentionally
// changed routing/DNS behaviour. The latter is a decision, not a refactor:
// update singbox/config.json in the same commit and say so.
func TestGeneratedMatchesCommitted(t *testing.T) {
	committedPath := filepath.Join("..", "..", "singbox", "config.json")
	committed, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("read %s: %v", committedPath, err)
	}

	generated, err := Generate(historicalInput())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var want, got any
	if err := json.Unmarshal(committed, &want); err != nil {
		t.Fatalf("parse committed config: %v", err)
	}
	if err := json.Unmarshal(generated, &got); err != nil {
		t.Fatalf("parse generated config: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		wantPretty, _ := json.MarshalIndent(want, "", "  ")
		gotPretty, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("generated config differs semantically from %s\n--- committed ---\n%s\n--- generated ---\n%s",
			committedPath, wantPretty, gotPretty)
	}

	if string(committed) != string(generated) {
		t.Errorf("generated config differs byte-for-byte from %s (semantics may still match; "+
			"check key order and whitespace)\n--- committed (%d bytes) ---\n%s\n--- generated (%d bytes) ---\n%s",
			committedPath, len(committed), committed, len(generated), generated)
	}
}

// TestOverridesMergeWithoutBreakingBase checks that raw_overrides replaces
// only what it names.
func TestOverridesMergeWithoutBreakingBase(t *testing.T) {
	in := historicalInput()
	in.RawOverrides = map[string]any{
		"log": map[string]any{"level": "debug"},
	}

	generated, err := Generate(in)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(generated, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}

	logSec := doc["log"].(map[string]any)
	if logSec["level"] != "debug" {
		t.Errorf("log.level = %v, want debug", logSec["level"])
	}
	if logSec["timestamp"] != true {
		t.Errorf("override dropped log.timestamp; got %v", logSec["timestamp"])
	}
	if doc["route"].(map[string]any)["final"] != "racer" {
		t.Errorf("override clobbered route.final")
	}
}

// TestRouterProcessNameIsLoadBearing documents why the first route rule
// exists: without a correct process_name the router's own DNS queries are
// recaptured by the TUN and loop forever.
func TestRouterProcessNameIsLoadBearing(t *testing.T) {
	in := historicalInput()
	in.RouterProcessName = "vpnctl"

	d := Build(in)
	first, ok := d.Route.Rules[0].(processRule)
	if !ok {
		t.Fatalf("first route rule is %T, want processRule", d.Route.Rules[0])
	}
	if len(first.ProcessName) != 1 || first.ProcessName[0] != "vpnctl" {
		t.Errorf("process_name = %v, want [vpnctl]", first.ProcessName)
	}
	if first.Outbound != "direct" {
		t.Errorf("loop-breaker rule must route direct, got %q", first.Outbound)
	}

	second, ok := d.Route.Rules[1].(portRule)
	if !ok || second.Action != "hijack-dns" {
		t.Fatalf("hijack-dns must be the rule right after the loop breaker, got %#v", d.Route.Rules[1])
	}
}
