package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ResolverDomain is one suffix macOS should resolve through the DNS router,
// and whether that is currently switched on.
//
// Off means the scoped resolver file is removed, not merely ignored: while it
// exists, the system resolver sends those names to us, so leaving it in place
// would make "off" untrue.
type ResolverDomain struct {
	Domain  string `yaml:"domain"`
	Enabled bool   `yaml:"enabled"`
}

// UnmarshalYAML accepts either a bare name or a mapping:
//
//	resolver_domains:
//	  - corp.example.com
//	  - domain: staging.example.com
//	    enabled: false
//
// The shorthand exists because most entries are on, and a file where every
// line reads "domain: x, enabled: true" hides the one line that says false.
func (d *ResolverDomain) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var name string
		if err := n.Decode(&name); err != nil {
			return err
		}
		d.Domain, d.Enabled = name, true
		return nil
	}

	// A mapping without "enabled" means on, so adding a domain by hand does
	// not silently do nothing.
	type raw struct {
		Domain  string `yaml:"domain"`
		Enabled *bool  `yaml:"enabled"`
	}
	var r raw
	if err := n.Decode(&r); err != nil {
		return err
	}
	if r.Domain == "" {
		return fmt.Errorf("resolver domain entry has no domain")
	}

	d.Domain = r.Domain
	d.Enabled = r.Enabled == nil || *r.Enabled
	return nil
}

// MarshalYAML writes the shorthand for an enabled domain and the mapping for a
// disabled one, so the file stays readable after the menu bar edits it.
func (d ResolverDomain) MarshalYAML() (any, error) {
	if d.Enabled {
		return d.Domain, nil
	}
	return map[string]any{"domain": d.Domain, "enabled": false}, nil
}

// ResolverDomains is the configured list.
type ResolverDomains []ResolverDomain

// Enabled returns just the names that are switched on, which is what gets
// written to /etc/resolver.
func (list ResolverDomains) Enabled() []string {
	out := make([]string, 0, len(list))
	for _, d := range list {
		if d.Enabled {
			out = append(out, d.Domain)
		}
	}
	return out
}

// Find returns the entry for a domain, and whether it is configured at all.
func (list ResolverDomains) Find(domain string) (ResolverDomain, bool) {
	for _, d := range list {
		if d.Domain == domain {
			return d, true
		}
	}
	return ResolverDomain{}, false
}

// WithAdded returns a copy with one more domain, switched on: adding a suffix
// and then having to switch it on would be two steps for one intention.
func (list ResolverDomains) WithAdded(domain string) (ResolverDomains, error) {
	domain, err := NormaliseDomain(domain)
	if err != nil {
		return nil, err
	}
	if _, found := list.Find(domain); found {
		return nil, fmt.Errorf("%s is already in the list", domain)
	}

	out := make(ResolverDomains, len(list), len(list)+1)
	copy(out, list)
	return append(out, ResolverDomain{Domain: domain, Enabled: true}), nil
}

// WithRemoved returns a copy without one domain.
func (list ResolverDomains) WithRemoved(domain string) (ResolverDomains, error) {
	out := make(ResolverDomains, 0, len(list))
	for _, d := range list {
		if d.Domain != domain {
			out = append(out, d)
		}
	}
	if len(out) == len(list) {
		return nil, fmt.Errorf("%q is not in dns_router.resolver_domains", domain)
	}
	return out, nil
}

// WithToggled returns a copy with one domain's state flipped. An unknown
// domain is refused rather than added: the menu bar can only toggle what the
// config already declares, so a stale click cannot introduce a suffix.
func (list ResolverDomains) WithToggled(domain string, enabled bool) (ResolverDomains, error) {
	out := make(ResolverDomains, len(list))
	copy(out, list)

	for i := range out {
		if out[i].Domain == domain {
			out[i].Enabled = enabled
			return out, nil
		}
	}
	return nil, fmt.Errorf("%q is not in dns_router.resolver_domains", domain)
}
