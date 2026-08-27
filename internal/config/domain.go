package config

import (
	"fmt"
	"strings"
)

// NormaliseDomain turns what somebody types into a suffix that can be matched
// against. A URL pasted from a browser and a wildcard borrowed from a proxy
// config are both what people reach for, and both mean the same thing here.
func NormaliseDomain(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	if i := strings.IndexAny(d, "/:"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimPrefix(d, "*.")
	d = strings.Trim(d, ".")

	if d == "" {
		return "", fmt.Errorf("no domain given")
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return "", fmt.Errorf("%q has an empty label", domain)
		}
		for _, r := range label {
			ok := r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if !ok {
				return "", fmt.Errorf("%q is not a domain name", domain)
			}
		}
	}
	return d, nil
}
