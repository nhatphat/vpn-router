// Package resolver manages macOS scoped resolvers, the /etc/resolver files
// that send one DNS suffix to a particular server.
//
// While sing-box is running its TUN already captures every port-53 packet, so
// a scoped resolver is redundant for routing. What it adds is a guarantee that
// does not depend on the TUN: the system resolver is told, explicitly and per
// suffix, where those names are answered. That matters for internal suffixes
// which must never be asked of a public resolver, even briefly, and even if
// something bypasses the tunnel.
//
// The files outlive a failure, and that is deliberate. If the daemon crashes,
// a scoped resolver pointing at a listener that is not running makes those
// names fail rather than leak to a public resolver — the same fail-closed
// choice the rest of this project makes for corporate traffic.
//
// They do not outlive a decision. Being asked to stop is not a failure: it
// means the machine should go back to resolving names the way it would if
// this program had never been installed, so the supervisor removes them on
// pause and writes them again on resume. Leaving them behind would turn "stop
// vpnctl" into "these suffixes no longer resolve at all", including on a
// network where they resolve perfectly well without us. "vpnctl uninstall"
// removes them for good.
package resolver

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Dir is where macOS looks for scoped resolvers.
const Dir = "/etc/resolver"

// marker identifies files this package wrote. Without it there is no way to
// tell our file from one an administrator put there by hand, and deleting
// somebody else's resolver would silently redirect their DNS.
const marker = "# managed by vpnctl"

// domainPattern is deliberately strict. The domain becomes a filename in a
// root-owned directory, and the config it comes from is writable by an
// unprivileged user, so anything that could escape the directory or name an
// unexpected file has to be impossible rather than unlikely.
var domainPattern = regexp.MustCompile(
	`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)

// ValidateDomain reports why a domain cannot be used, or nil.
func ValidateDomain(domain string) error {
	switch {
	case domain == "":
		return fmt.Errorf("empty domain")
	case len(domain) > 253:
		return fmt.Errorf("domain %q is longer than 253 characters", domain)
	case strings.HasPrefix(domain, "."), strings.HasSuffix(domain, "."):
		return fmt.Errorf("domain %q must not start or end with a dot", domain)
	case !domainPattern.MatchString(domain):
		return fmt.Errorf("domain %q is not a plain dotted name; "+
			"scoped resolvers are per suffix, e.g. corp.example.com", domain)
	}
	return nil
}

// content is the file a scoped resolver needs: which server answers this
// suffix, and on which port.
func content(host string, port int) string {
	return fmt.Sprintf("%s\n# Delete this file, or run \"sudo vpnctl uninstall\", to hand these\n"+
		"# names back to the system's normal resolvers.\nnameserver %s\nport %d\n",
		marker, host, port)
}

// isManaged reports whether a file was written by this package.
func isManaged(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(data), marker)
}

// equivalent reports whether an existing resolver file already sends this
// suffix to the same place, whoever wrote it. resolver(5) has more directives
// than these two, so anything else present means the file is doing something
// we do not understand and must not touch.
func equivalent(body, host string, port int) bool {
	gotHost, gotPort := "", 53

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, " ")
		if !found {
			return false
		}
		value = strings.TrimSpace(value)

		switch key {
		case "nameserver":
			if gotHost != "" && gotHost != value {
				return false // more than one server; not a simple redirect
			}
			gotHost = value
		case "port":
			n, err := strconv.Atoi(value)
			if err != nil {
				return false
			}
			gotPort = n
		default:
			return false
		}
	}

	return gotHost == host && gotPort == port
}

// Managed lists the domains currently configured by this package.
func Managed(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if isManaged(filepath.Join(dir, e.Name())) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// Result describes what Apply did.
type Result struct {
	Added   []string
	Updated []string
	Removed []string
}

// Changed reports whether the system resolver configuration moved at all,
// which is what decides whether mDNSResponder needs to be told.
func (r Result) Changed() bool {
	return len(r.Added)+len(r.Updated)+len(r.Removed) > 0
}

func (r Result) String() string {
	var parts []string
	if len(r.Added) > 0 {
		parts = append(parts, "added "+strings.Join(r.Added, ", "))
	}
	if len(r.Updated) > 0 {
		parts = append(parts, "updated "+strings.Join(r.Updated, ", "))
	}
	if len(r.Removed) > 0 {
		parts = append(parts, "removed "+strings.Join(r.Removed, ", "))
	}
	if len(parts) == 0 {
		return "no change"
	}
	return strings.Join(parts, "; ")
}

// Apply makes dir hold exactly the given domains, pointed at host:port.
//
// Only files carrying the marker are ever removed or overwritten. A resolver
// an administrator wrote by hand for the same suffix is left alone and
// reported, because silently taking over where a machine sends its DNS is not
// a decision this program gets to make.
func Apply(dir string, domains []string, host string, port int, logf func(string, ...any)) (Result, error) {
	var result Result

	for _, d := range domains {
		if err := ValidateDomain(d); err != nil {
			return result, err
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return result, fmt.Errorf("create %s: %w", dir, err)
	}

	want := content(host, port)
	wanted := make(map[string]bool, len(domains))

	for _, domain := range domains {
		wanted[domain] = true
		path := filepath.Join(dir, domain)

		existing, err := os.ReadFile(path)
		switch {
		case err == nil && string(existing) == want:
			continue // already right

		case err == nil && !strings.HasPrefix(string(existing), marker):
			// Somebody else's file. If it already sends this suffix to the
			// same place, adopting it changes nothing about where DNS goes
			// and puts the domain under the config's control — removing the
			// line later will remove the file. If it points elsewhere, taking
			// it over would silently redirect a machine's DNS, which is not
			// a decision this program gets to make.
			if !equivalent(string(existing), host, port) {
				if logf != nil {
					logf("resolver: %s already sends %s somewhere else and was not written by vpnctl; leaving it alone",
						path, domain)
				}
				continue
			}
			if err := write(path, want); err != nil {
				return result, err
			}
			if logf != nil {
				logf("resolver: adopted the existing %s; it already pointed at %s:%d", path, host, port)
			}
			result.Updated = append(result.Updated, domain)

		case err == nil:
			if err := write(path, want); err != nil {
				return result, err
			}
			result.Updated = append(result.Updated, domain)

		default:
			if err := write(path, want); err != nil {
				return result, err
			}
			result.Added = append(result.Added, domain)
		}
	}

	// Anything we manage that is no longer configured goes, so removing a
	// line from the config is as effective as adding one.
	for _, domain := range Managed(dir) {
		if wanted[domain] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, domain)); err != nil {
			return result, fmt.Errorf("remove %s: %w", domain, err)
		}
		result.Removed = append(result.Removed, domain)
	}

	return result, nil
}

// RemoveAll deletes every resolver this package manages, for uninstall.
func RemoveAll(dir string, logf func(string, ...any)) Result {
	var result Result
	for _, domain := range Managed(dir) {
		if err := os.Remove(filepath.Join(dir, domain)); err == nil {
			result.Removed = append(result.Removed, domain)
		} else if logf != nil {
			logf("resolver: could not remove %s: %v", domain, err)
		}
	}
	return result
}

func write(path, body string) error {
	// Written via a temporary file in the same directory so mDNSResponder can
	// never read a half-written resolver.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vpnctl-resolver-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Reload tells the system resolver to re-read /etc/resolver.
//
// Called only when something actually changed: a HUP flushes the machine's
// whole DNS cache, so doing it on every daemon start would throw away every
// cached answer on the machine for no reason.
func Reload() error {
	// Absolute paths: a daemon's PATH is minimal, and these are system
	// binaries rather than anything a user can replace.
	if out, err := exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").CombinedOutput(); err != nil {
		return fmt.Errorf("reload mDNSResponder: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// Best effort: the HUP is what matters, this just drops stale answers
	// sooner.
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	return nil
}
