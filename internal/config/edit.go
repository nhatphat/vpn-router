package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SetResolverDomains rewrites the dns_router.resolver_domains block in place
// and leaves the rest of the file byte for byte as it was.
//
// It edits lines rather than decoding and re-encoding the document, because a
// round trip through the YAML types would strip every comment in the file. A
// configuration people are expected to read and annotate cannot be rewritten
// by a graphical toggle at the cost of its own documentation.
//
// The consequence is that only this block is normalised. Comments inside it
// are replaced along with the entries; comments above the key, and everything
// else in the file, survive untouched.
func SetResolverDomains(path string, list ResolverDomains) error {
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	updated, err := replaceResolverBlock(string(original), list)
	if err != nil {
		return err
	}
	if updated == string(original) {
		return nil
	}

	// Written through a temporary file in the same directory so a crash
	// cannot leave a half-written configuration, which the daemon would
	// refuse to load on its next start.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vpnctl-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(updated); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

const resolverKey = "resolver_domains:"

func replaceResolverBlock(text string, list ResolverDomains) (string, error) {
	lines := strings.Split(text, "\n")

	sectionStart, sectionEnd := findSection(lines, "dns_router:")
	if sectionStart < 0 {
		// No section to edit: append one, so a configuration that predates
		// this setting can still be toggled.
		block := renderResolverBlock(2, list)
		out := strings.TrimRight(text, "\n") + "\n\ndns_router:\n" + strings.Join(block, "\n") + "\n"
		return out, nil
	}

	keyLine := -1
	for i := sectionStart + 1; i < sectionEnd; i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), resolverKey) {
			keyLine = i
			break
		}
	}

	if keyLine < 0 {
		// Insert at the top of the section rather than the bottom: the
		// section's own trailing comments belong to what precedes them.
		block := renderResolverBlock(indentOf(lines[sectionStart])+2, list)
		out := append([]string{}, lines[:sectionStart+1]...)
		out = append(out, block...)
		out = append(out, lines[sectionStart+1:]...)
		return strings.Join(out, "\n"), nil
	}

	keyIndent := indentOf(lines[keyLine])
	blockEnd := keyLine + 1
	for blockEnd < len(lines) {
		line := lines[blockEnd]
		if strings.TrimSpace(line) == "" {
			// A blank line only continues the block if something deeper
			// follows it; otherwise it separates sections.
			if next := nextNonBlank(lines, blockEnd+1); next < 0 || indentOf(lines[next]) <= keyIndent {
				break
			}
			blockEnd++
			continue
		}
		if indentOf(line) <= keyIndent {
			break
		}
		blockEnd++
	}

	block := renderResolverBlock(keyIndent, list)

	out := append([]string{}, lines[:keyLine]...)
	out = append(out, block...)
	out = append(out, lines[blockEnd:]...)
	return strings.Join(out, "\n"), nil
}

// renderResolverBlock writes the key and its entries at the given indentation.
func renderResolverBlock(indent int, list ResolverDomains) []string {
	pad := strings.Repeat(" ", indent)

	if len(list) == 0 {
		return []string{pad + resolverKey + " []"}
	}

	out := []string{pad + resolverKey}
	for _, d := range list {
		if d.Enabled {
			out = append(out, pad+"  - "+d.Domain)
			continue
		}
		out = append(out, pad+"  - domain: "+d.Domain, pad+"    enabled: false")
	}
	return out
}

// findSection returns the line of a top-level key and the line after its
// block.
func findSection(lines []string, key string) (start, end int) {
	start = -1
	for i, line := range lines {
		if indentOf(line) == 0 && strings.HasPrefix(line, key) {
			start = i
			break
		}
	}
	if start < 0 {
		return -1, -1
	}

	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		if indentOf(line) == 0 {
			return start, i
		}
	}
	return start, len(lines)
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

func nextNonBlank(lines []string, from int) int {
	for i := from; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "" {
			return i
		}
	}
	return -1
}

// ToggleResolverDomain flips one domain in the file at path and returns the
// new list.
func ToggleResolverDomain(path, domain string, enabled bool) (ResolverDomains, error) {
	return editResolverDomains(path, func(list ResolverDomains) (ResolverDomains, error) {
		return list.WithToggled(domain, enabled)
	})
}

// AddResolverDomain adds a suffix for macOS to resolve here, switched on.
func AddResolverDomain(path, domain string) (ResolverDomains, error) {
	return editResolverDomains(path, func(list ResolverDomains) (ResolverDomains, error) {
		return list.WithAdded(domain)
	})
}

// RemoveResolverDomain takes a suffix out of the list altogether. Switching
// one off leaves it in the file to switch back on; removing it does not.
func RemoveResolverDomain(path, domain string) (ResolverDomains, error) {
	return editResolverDomains(path, func(list ResolverDomains) (ResolverDomains, error) {
		return list.WithRemoved(domain)
	})
}

// editResolverDomains re-reads the file before changing it, so an edit made in
// an editor since the caller last looked is not clobbered by a stale copy.
func editResolverDomains(path string, change func(ResolverDomains) (ResolverDomains, error)) (ResolverDomains, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}

	next, err := change(cfg.DNSRouter.ResolverDomains)
	if err != nil {
		return nil, err
	}
	if err := SetResolverDomains(path, next); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return next, nil
}
