package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeRules(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "force-vpn.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// domains is the old shape of this file's tests: the domain suffixes, in
// order, with everything else ignored.
func domains(t *testing.T, path string) []string {
	t.Helper()
	return valuesOfType(t, path, "domain_suffix")
}

func valuesOfType(t *testing.T, path, field string) []string {
	t.Helper()
	rules, _, err := ForceVPNRules(path)
	if err != nil {
		t.Fatal(err)
	}

	var out []string
	for _, r := range rules {
		if r.Type == field {
			out = append(out, r.Value)
		}
	}
	return out
}

// TestAddKeepsProcessRulesIntact is the whole point of decoding into generic
// rules: the menu bar only knows about domains, and everything else in the
// file belongs to whoever wrote it.
func TestAddKeepsProcessRulesIntact(t *testing.T) {
	path := writeRules(t, `{
  "version": 4,
  "rules": [
    { "domain_suffix": ["customer.example"] },
    { "process_name": ["CustomerApp"], "invert": false }
  ]
}
`)

	if _, err := AddForceVPNRule(path, "domain_suffix", "jira.corp.example"); err != nil {
		t.Fatal(err)
	}

	if got, want := domains(t, path), []string{"customer.example", "jira.corp.example"}; !reflect.DeepEqual(got, want) {
		t.Errorf("domains = %v, want %v", got, want)
	}

	var doc struct {
		Version int              `json:"version"`
		Rules   []map[string]any `json:"rules"`
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}

	if doc.Version != 4 {
		t.Errorf("version = %d, want 4", doc.Version)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("rules = %d, want the process rule to be left alone: %+v", len(doc.Rules), doc.Rules)
	}
	if got := doc.Rules[1]["process_name"]; !reflect.DeepEqual(got, []any{"CustomerApp"}) {
		t.Errorf("process_name = %v, want it untouched", got)
	}
	if _, ok := doc.Rules[1]["invert"]; !ok {
		t.Error("invert was dropped from a rule this code does not understand")
	}
}

// A suffix must never join a rule that names something else: fields inside one
// rule object are ANDed, so it would only match that domain in that process.
func TestAddDoesNotJoinAMixedRule(t *testing.T) {
	path := writeRules(t, `{"version":4,"rules":[{"domain_suffix":["a.example"],"process_name":["App"]}]}`)

	if _, err := AddForceVPNRule(path, "domain_suffix", "b.example"); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Rules []map[string]any `json:"rules"`
	}
	body, _ := os.ReadFile(path)
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("rules = %+v, want the new suffix in a rule of its own", doc.Rules)
	}
	if got := doc.Rules[1]; !reflect.DeepEqual(got, map[string]any{"domain_suffix": []any{"b.example"}}) {
		t.Errorf("new rule = %v", got)
	}
}

func TestAddIsIdempotent(t *testing.T) {
	path := writeRules(t, `{"version":4,"rules":[{"domain_suffix":["a.example"]}]}`)

	changed, err := AddForceVPNRule(path, "domain_suffix", "A.Example")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("adding a domain that is already forced reported a change")
	}
	if got := domains(t, path); len(got) != 1 {
		t.Errorf("domains = %v, want one", got)
	}
}

// An emptied rule object is not valid sing-box input — it is rejected with
// "missing conditions" — so removing the last suffix must remove the object.
func TestRemoveDropsAnEmptiedRule(t *testing.T) {
	path := writeRules(t, `{"version":4,"rules":[{"domain_suffix":["a.example"]},{"process_name":["App"]}]}`)

	changed, err := RemoveForceVPNRule(path, "domain_suffix", "a.example")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("removing a present domain reported no change")
	}

	var doc struct {
		Rules []map[string]any `json:"rules"`
	}
	body, _ := os.ReadFile(path)
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 1 || doc.Rules[0]["process_name"] == nil {
		t.Errorf("rules = %+v, want only the process rule left", doc.Rules)
	}
}

// A rule that ANDs several fields means something no row in a table can say,
// so vpnctl reports it rather than editing it — and leaves it alone even when
// one of its values is asked for by name.
func TestMixedRulesAreReportedNotEdited(t *testing.T) {
	body := `{"version":4,"rules":[{"domain_suffix":["a.example"],"process_name":["App"]}]}`
	path := writeRules(t, body)

	rules, advanced, err := ForceVPNRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("editable rules = %v, want none", rules)
	}
	if len(advanced) != 1 || !strings.Contains(advanced[0], "process_name") {
		t.Fatalf("advanced = %v, want the mixed rule", advanced)
	}

	changed, err := RemoveForceVPNRule(path, "domain_suffix", "a.example")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("a value inside a mixed rule was removed")
	}
	if after, _ := os.ReadFile(path); string(after) != body {
		t.Errorf("the file was rewritten:\n%s", after)
	}
}

// Every matcher vpnctl offers has to survive a round trip, since each one is a
// different field in the file.
func TestEveryTypeAddsAndRemoves(t *testing.T) {
	values := map[string]string{
		"domain_suffix":      "customer.example",
		"domain":             "exact.example",
		"domain_keyword":     "-stg.",
		"domain_regex":       `^api\\..*\\.example$`,
		"process_name":       "CustomerApp",
		"process_path":       "/Applications/CustomerApp.app/Contents/MacOS/CustomerApp",
		"process_path_regex": `^/Applications/CustomerApp\\.app/.*`,
	}

	for _, field := range ForceVPNTypes() {
		value, ok := values[field]
		if !ok {
			t.Fatalf("%s is offered but not covered by this test", field)
		}

		t.Run(field, func(t *testing.T) {
			path := writeRules(t, `{"version":4,"rules":[]}`)

			if _, err := AddForceVPNRule(path, field, value); err != nil {
				t.Fatal(err)
			}
			if got := valuesOfType(t, path, field); len(got) != 1 || got[0] != value {
				t.Fatalf("after add: %v, want [%s]", got, value)
			}

			changed, err := RemoveForceVPNRule(path, field, value)
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatal("remove reported no change")
			}
			if got := valuesOfType(t, path, field); len(got) != 0 {
				t.Errorf("after remove: %v", got)
			}
		})
	}
}

// Each matcher is checked the way that matcher is used: a regex is left
// exactly as typed but must compile, a path must be one, a process name must
// not be.
func TestValuesAreCheckedPerType(t *testing.T) {
	path := writeRules(t, `{"version":4,"rules":[]}`)

	bad := map[string]string{
		"domain_suffix":      "two words",
		"domain_regex":       "[unclosed",
		"process_path_regex": "*",
		"process_path":       "CustomerApp",
		"process_name":       "/Applications/CustomerApp",
		"domain_keyword":     "with space",
	}
	for field, value := range bad {
		if _, err := AddForceVPNRule(path, field, value); err == nil {
			t.Errorf("%s accepted %q", field, value)
		}
	}

	if _, err := AddForceVPNRule(path, "ip_cidr", "10.0.0.0/8"); err == nil {
		t.Error("a matcher vpnctl does not edit was accepted")
	}

	// A regex is not a domain: it must reach the file with its own characters
	// intact, uppercase and all.
	pattern := `^API\\.Customer\\.example$`
	if _, err := AddForceVPNRule(path, "domain_regex", pattern); err != nil {
		t.Fatal(err)
	}
	if got := valuesOfType(t, path, "domain_regex"); len(got) != 1 || got[0] != pattern {
		t.Errorf("regex stored as %v, want %q unchanged", got, pattern)
	}
}

func TestRemoveMissingDomainLeavesTheFileAlone(t *testing.T) {
	body := `{"version":4,"rules":[{"domain_suffix":["a.example"]}]}`
	path := writeRules(t, body)

	changed, err := RemoveForceVPNRule(path, "domain_suffix", "b.example")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("removing an absent domain reported a change")
	}

	after, _ := os.ReadFile(path)
	if string(after) != body {
		t.Errorf("file was rewritten:\n%s", after)
	}
}

// sing-box accepts a bare string where a list is allowed, and a file somebody
// wrote by hand is where that turns up.
func TestSuffixWrittenAsAString(t *testing.T) {
	path := writeRules(t, `{"version":4,"rules":[{"domain_suffix":"a.example"}]}`)

	if got, want := domains(t, path), []string{"a.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
	if _, err := RemoveForceVPNRule(path, "domain_suffix", "a.example"); err != nil {
		t.Fatal(err)
	}
	if got := domains(t, path); len(got) != 0 {
		t.Errorf("domains = %v, want none", got)
	}
}

// A missing file is not an error: the first domain added creates it, which is
// what happens on an install that never wrote one.
func TestAddCreatesAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "force-vpn.json")

	if got := domains(t, path); len(got) != 0 {
		t.Errorf("domains = %v, want none for a missing file", got)
	}
	if _, err := AddForceVPNRule(path, "domain_suffix", "a.example"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644 as an install creates it", info.Mode().Perm())
	}
	if got, want := domains(t, path), []string{"a.example"}; !reflect.DeepEqual(got, want) {
		t.Errorf("domains = %v, want %v", got, want)
	}
}

func TestNormaliseDomain(t *testing.T) {
	ok := map[string]string{
		"customer.example":                  "customer.example",
		"  Customer.Example  ":              "customer.example",
		"*.customer.example":                "customer.example",
		".customer.example.":                "customer.example",
		"https://customer.example/":         "customer.example",
		"http://customer.example:8443/path": "customer.example",
		"intranet":                          "intranet",
	}
	for in, want := range ok {
		got, err := NormaliseDomain(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q normalised to %q, want %q", in, got, want)
		}
	}

	bad := []string{"", "   ", "*.", "a..b", "two words.example", "under_score.example"}
	for _, in := range bad {
		if got, err := NormaliseDomain(in); err == nil {
			t.Errorf("%q was accepted as %q", in, got)
		}
	}
}

// Renaming in place is the point: a list somebody ordered by environment
// should not shuffle because a typo was fixed.
func TestRenameKeepsThePosition(t *testing.T) {
	path := writeRules(t, `{"version":4,"rules":[{"domain_suffix":["a.example","typo.exmaple","c.example"]}]}`)

	changed, err := EditForceVPNRule(path, "domain_suffix", "typo.exmaple", "b.example")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("rename reported no change")
	}

	want := []string{"a.example", "b.example", "c.example"}
	if got := domains(t, path); !reflect.DeepEqual(got, want) {
		t.Errorf("domains = %v, want %v", got, want)
	}
}

func TestRenameOntoAnExistingDomainLeavesOne(t *testing.T) {
	path := writeRules(t, `{"version":4,"rules":[{"domain_suffix":["a.example"]},{"domain_suffix":["b.example"]}]}`)

	if _, err := EditForceVPNRule(path, "domain_suffix", "b.example", "a.example"); err != nil {
		t.Fatal(err)
	}

	if got, want := domains(t, path), []string{"a.example"}; !reflect.DeepEqual(got, want) {
		t.Errorf("domains = %v, want %v", got, want)
	}
}

func TestRenameOfSomethingAbsentIsAnError(t *testing.T) {
	body := `{"version":4,"rules":[{"domain_suffix":["a.example"]}]}`
	path := writeRules(t, body)

	if _, err := EditForceVPNRule(path, "domain_suffix", "b.example", "c.example"); err == nil {
		t.Error("renaming a domain that is not there was accepted")
	}
	if after, _ := os.ReadFile(path); string(after) != body {
		t.Errorf("the file was rewritten:\n%s", after)
	}
}
