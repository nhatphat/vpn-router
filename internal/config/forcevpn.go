package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The force-VPN rule-set is sing-box's own file, not vpnctl's, and people
// write matchers into it by hand. vpnctl edits one shape and one shape only: a
// rule object holding a single matcher field. Everything else — a rule that
// ANDs a domain with a process, a field this code has never heard of — is read
// back out as it was and written back untouched.
type forceVPNRuleSet struct {
	Version int              `json:"version"`
	Rules   []map[string]any `json:"rules"`
}

// ForceVPNRule is one matcher: the sing-box field, and one value for it.
type ForceVPNRule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ForceVPNTypes are the matchers vpnctl will write, in the order a person is
// likely to want them. The list is deliberately shorter than sing-box's: these
// are the ones that mean something on a Mac routing a corporate VPN.
func ForceVPNTypes() []string {
	return []string{
		"domain_suffix", "domain", "domain_keyword", "domain_regex",
		"process_name", "process_path", "process_path_regex",
	}
}

func supportedType(name string) bool {
	for _, t := range ForceVPNTypes() {
		if t == name {
			return true
		}
	}
	return false
}

// ruleSetVersion is what a file created here declares. It matches the version
// in installer.EmptyRuleSet, which is what a fresh install gets; an existing
// file keeps whatever version it already has.
const ruleSetVersion = 4

// ForceVPNRules returns the matchers vpnctl can edit, and the rules it cannot.
//
// The second list is the honest half: a rule that ANDs several fields means
// something no row in a table can say, so it is handed back as the JSON it is
// rather than flattened into something editable and wrong.
func ForceVPNRules(path string) (rules []ForceVPNRule, advanced []string, err error) {
	doc, err := loadRuleSet(path)
	if err != nil {
		return nil, nil, err
	}

	for _, rule := range doc.Rules {
		field, ok := soleField(rule)
		if !ok {
			advanced = append(advanced, describe(rule))
			continue
		}
		for _, value := range values(rule, field) {
			rules = append(rules, ForceVPNRule{Type: field, Value: value})
		}
	}
	return rules, advanced, nil
}

// AddForceVPNRule adds one matcher and reports whether the file changed.
//
// It joins the first rule object that holds nothing but this field, because
// fields within one object are ANDed: appending a domain to a rule that also
// names a process would quietly narrow both.
func AddForceVPNRule(path, field, value string) (bool, error) {
	field, value, err := normaliseRule(field, value)
	if err != nil {
		return false, err
	}

	doc, err := loadRuleSet(path)
	if err != nil {
		return false, err
	}

	for _, rule := range doc.Rules {
		if only, ok := soleField(rule); ok && only == field {
			for _, existing := range values(rule, field) {
				if existing == value {
					return false, nil
				}
			}
		}
	}

	added := false
	for _, rule := range doc.Rules {
		if only, ok := soleField(rule); ok && only == field {
			rule[field] = append(anySlice(values(rule, field)), value)
			added = true
			break
		}
	}
	if !added {
		doc.Rules = append(doc.Rules, map[string]any{field: []any{value}})
	}

	return true, writeRuleSet(path, doc)
}

// RemoveForceVPNRule drops one matcher, and drops the rule object with it if
// that was all it held — sing-box rejects a rule with no conditions, so an
// emptied object would break the file it is in.
func RemoveForceVPNRule(path, field, value string) (bool, error) {
	if !supportedType(field) {
		return false, fmt.Errorf("%q is not a matcher vpnctl edits", field)
	}

	doc, err := loadRuleSet(path)
	if err != nil {
		return false, err
	}

	changed := false
	kept := make([]map[string]any, 0, len(doc.Rules))

	for _, rule := range doc.Rules {
		if only, ok := soleField(rule); ok && only == field {
			list := values(rule, field)
			remaining := make([]string, 0, len(list))
			for _, entry := range list {
				if entry == value {
					changed = true
					continue
				}
				remaining = append(remaining, entry)
			}

			if len(remaining) == 0 {
				delete(rule, field)
			} else if len(remaining) != len(list) {
				rule[field] = anySlice(remaining)
			}
		}
		if len(rule) > 0 {
			kept = append(kept, rule)
		}
	}

	if !changed {
		return false, nil
	}

	doc.Rules = kept
	return true, writeRuleSet(path, doc)
}

// EditForceVPNRule replaces a matcher's value where it stands, so correcting a
// typo does not move the entry to the end of a list somebody has ordered on
// purpose. Editing onto a value that is already there leaves one, not two.
func EditForceVPNRule(path, field, value, to string) (bool, error) {
	field, to, err := normaliseRule(field, to)
	if err != nil {
		return false, err
	}
	if value == to {
		return false, nil
	}

	doc, err := loadRuleSet(path)
	if err != nil {
		return false, err
	}

	edited := false
	for _, rule := range doc.Rules {
		only, ok := soleField(rule)
		if !ok || only != field {
			continue
		}

		list := values(rule, field)
		out := make([]string, 0, len(list))
		changed := false

		for _, entry := range list {
			if entry == value && !edited {
				edited, changed = true, true
				out = append(out, to)
				continue
			}
			out = append(out, entry)
		}
		if changed {
			rule[field] = anySlice(out)
		}
	}

	if !edited {
		return false, fmt.Errorf("%s is not in the rules", value)
	}

	// The new value may already have been in the file, in which case the edit
	// has just made a second copy of it.
	doc.Rules = dropDuplicates(doc.Rules, field, to)
	return true, writeRuleSet(path, doc)
}

// normaliseRule checks a matcher and tidies its value.
//
// What counts as tidy depends on the matcher: a domain typed as a URL means
// the host, while a regex means exactly the characters given and must not be
// touched at all — only checked that it compiles, since a rule-set sing-box
// rejects takes the whole file down with it.
func normaliseRule(field, value string) (string, string, error) {
	if !supportedType(field) {
		return "", "", fmt.Errorf("%q is not a matcher vpnctl edits", field)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Errorf("no value given")
	}

	switch field {
	case "domain", "domain_suffix":
		clean, err := NormaliseDomain(value)
		return field, clean, err

	case "domain_keyword":
		// A keyword is a substring of a name, not a name: "customer" and
		// "-stg." are both reasonable, so only the obvious rubbish is refused.
		value = strings.ToLower(value)
		if strings.ContainsAny(value, " \t/") {
			return "", "", fmt.Errorf("%q is not a keyword", value)
		}
		return field, value, nil

	case "domain_regex", "process_path_regex":
		if _, err := regexp.Compile(value); err != nil {
			return "", "", fmt.Errorf("that is not a valid regular expression: %w", err)
		}
		return field, value, nil

	case "process_path":
		if !strings.HasPrefix(value, "/") {
			return "", "", fmt.Errorf("a process path has to be absolute, like /Applications/App.app/Contents/MacOS/App")
		}
		return field, value, nil

	default: // process_name
		if strings.ContainsAny(value, "/") {
			return "", "", fmt.Errorf("%q looks like a path; use process_path for that", value)
		}
		return field, value, nil
	}
}

// soleField returns a rule's only field, and whether it has exactly one that
// vpnctl knows how to edit.
func soleField(rule map[string]any) (string, bool) {
	if len(rule) != 1 {
		return "", false
	}
	for field := range rule {
		return field, supportedType(field)
	}
	return "", false
}

// values reads one field, which sing-box accepts as either a single string or
// a list of them.
func values(rule map[string]any, field string) []string {
	switch v := rule[field].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// describe renders a rule this code will not edit, for the page to show as it
// is. Key order is whatever the map iterates, which is why it is shown as one
// line of JSON rather than pretending to be the file's own text.
func describe(rule map[string]any) string {
	body, err := json.Marshal(rule)
	if err != nil {
		return "<unreadable rule>"
	}
	return string(body)
}

// dropDuplicates leaves the first occurrence of a value and removes the rest,
// dropping any rule object it empties.
func dropDuplicates(rules []map[string]any, field, value string) []map[string]any {
	seen := false
	kept := make([]map[string]any, 0, len(rules))

	for _, rule := range rules {
		if only, ok := soleField(rule); ok && only == field {
			list := values(rule, field)
			out := make([]string, 0, len(list))

			for _, entry := range list {
				if entry == value {
					if seen {
						continue
					}
					seen = true
				}
				out = append(out, entry)
			}

			if len(out) == 0 {
				delete(rule, field)
			} else if len(out) != len(list) {
				rule[field] = anySlice(out)
			}
		}
		if len(rule) > 0 {
			kept = append(kept, rule)
		}
	}
	return kept
}

func anySlice(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

func loadRuleSet(path string) (*forceVPNRuleSet, error) {
	if path == "" {
		return nil, fmt.Errorf("no force-VPN rules file is configured")
	}

	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &forceVPNRuleSet{Version: ruleSetVersion}, nil
	}
	if err != nil {
		return nil, err
	}

	doc := &forceVPNRuleSet{}
	dec := json.NewDecoder(bytes.NewReader(body))
	// Numbers stay as written: a port re-encoded through float64 would come
	// back as 1e+03 in somebody else's rule.
	dec.UseNumber()
	if err := dec.Decode(doc); err != nil {
		return nil, fmt.Errorf("%s is not a readable rule-set: %w", filepath.Base(path), err)
	}
	if doc.Version == 0 {
		doc.Version = ruleSetVersion
	}
	return doc, nil
}

// writeRuleSet replaces the file atomically, so a crash mid-write cannot leave
// sing-box with a rule-set it refuses to load.
func writeRuleSet(path string, doc *forceVPNRuleSet) error {
	if doc.Rules == nil {
		doc.Rules = []map[string]any{}
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	// 0644 is what an install creates: the daemon reads it as root, and it
	// holds no secrets.
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".vpnctl-rules-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
