package resolver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateDomainRejectsAnythingThatIsNotAName is the security-relevant
// test here: the domain becomes a filename in a root-owned directory, and it
// comes from a config file an unprivileged user can edit.
func TestValidateDomainRejectsAnythingThatIsNotAName(t *testing.T) {
	bad := []string{
		"",
		".",
		".example.com",
		"example.com.",
		"../../etc/sudoers",
		"corp.example.com/../../../etc/hosts",
		"/etc/hosts",
		"corp example com",
		"corp.example.com\nnameserver 8.8.8.8",
		"corp..example.com",
		"-corp.example.com",
		"corp.example.com-",
		"localhost", // single label: a scoped resolver is per suffix
		strings.Repeat("a", 300) + ".example.com",
	}

	for _, d := range bad {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("ValidateDomain(%q) accepted it", d)
		}
	}

	good := []string{
		"corp.example.com",
		"dev.example.asia",
		"example.local",
		"a.b.c.d.example.com",
		"x1.example-corp.com",
	}
	for _, d := range good {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("ValidateDomain(%q) rejected it: %v", d, err)
		}
	}
}

func TestApplyWritesRemovesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	res, err := Apply(dir, []string{"corp.example.com", "other.example.com"}, "127.0.0.1", 15353, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 2 {
		t.Fatalf("added %v, want two domains", res.Added)
	}

	body, err := os.ReadFile(filepath.Join(dir, "corp.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{marker, "nameserver 127.0.0.1", "port 15353"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the file is missing %q:\n%s", want, body)
		}
	}

	// Running again must change nothing, or every daemon start would flush
	// the machine's DNS cache.
	again, err := Apply(dir, []string{"corp.example.com", "other.example.com"}, "127.0.0.1", 15353, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed() {
		t.Errorf("second Apply reported %s, want no change", again)
	}

	// Dropping a domain from the list removes its file.
	shrunk, err := Apply(dir, []string{"corp.example.com"}, "127.0.0.1", 15353, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(shrunk.Removed) != 1 || shrunk.Removed[0] != "other.example.com" {
		t.Errorf("removed %v, want [other.example.com]", shrunk.Removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "other.example.com")); !os.IsNotExist(err) {
		t.Error("the file for the dropped domain is still there")
	}
}

// TestApplyLeavesSomebodyElsesResolverAlone is the case that matters most:
// taking over a file we did not write would silently redirect a machine's DNS.
func TestApplyLeavesSomebodyElsesResolverAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corp.example.com")
	theirs := "nameserver 10.0.0.53\nsearch_order 1\n"
	if err := os.WriteFile(path, []byte(theirs), 0o644); err != nil {
		t.Fatal(err)
	}

	var warnings []string
	res, err := Apply(dir, []string{"corp.example.com"}, "127.0.0.1", 15353,
		func(f string, a ...any) { warnings = append(warnings, f) })
	if err != nil {
		t.Fatal(err)
	}

	body, _ := os.ReadFile(path)
	if string(body) != theirs {
		t.Errorf("the existing resolver was overwritten:\n%s", body)
	}
	if res.Changed() {
		t.Errorf("reported %s, want no change", res)
	}
	if len(warnings) == 0 {
		t.Error("nothing was said about the file being skipped")
	}

	// And it is not ours to delete, either.
	if got := Managed(dir); len(got) != 0 {
		t.Errorf("Managed = %v, want none", got)
	}
	if res := RemoveAll(dir, nil); res.Changed() {
		t.Error("RemoveAll deleted a file it did not write")
	}
}

// TestApplyAdoptsAnEquivalentResolver covers a file written by hand that
// already points where we would point it. Adopting changes nothing about where
// DNS goes, and puts the domain under the config's control.
func TestApplyAdoptsAnEquivalentResolver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev.example.asia")
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.1\nport 15353\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Apply(dir, []string{"dev.example.asia"}, "127.0.0.1", 15353, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Updated) != 1 {
		t.Fatalf("updated %v, want the adopted domain", res.Updated)
	}
	if got := Managed(dir); len(got) != 1 || got[0] != "dev.example.asia" {
		t.Errorf("Managed = %v after adoption", got)
	}
}

func TestEquivalenceIsNarrow(t *testing.T) {
	cases := map[string]bool{
		"nameserver 127.0.0.1\nport 15353\n":                     true,
		"# a comment\n\nnameserver 127.0.0.1\nport 15353\n":      true,
		"nameserver 127.0.0.1\n":                                 false, // implies port 53
		"nameserver 127.0.0.1\nport 15354\n":                     false,
		"nameserver 127.0.0.1\nnameserver 8.8.8.8\nport 15353\n": false,
		"nameserver 127.0.0.1\nport 15353\ndomain other\n":       false,
		"nameserver 127.0.0.1\nport 15353\ntimeout 1\n":          false,
	}

	for body, want := range cases {
		if got := equivalent(body, "127.0.0.1", 15353); got != want {
			t.Errorf("equivalent(%q) = %v, want %v", body, got, want)
		}
	}
}

func TestApplyRefusesABadDomainBeforeWritingAnything(t *testing.T) {
	dir := t.TempDir()

	_, err := Apply(dir, []string{"good.example.com", "../escape"}, "127.0.0.1", 15353, nil)
	if err == nil {
		t.Fatal("expected Apply to refuse the bad domain")
	}

	// Nothing at all should have been written: a partial application would
	// leave the machine's DNS in a state the config does not describe.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("Apply wrote %d file(s) before failing", len(entries))
	}
}
