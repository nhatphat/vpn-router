// Package vpndns reports the DNS servers the VPN currently pushes.
//
// OpenVPN's --up script inside the container writes them to a file. Two ways
// of reading it are supported, in this order:
//
//	a shared bind mount, read straight off the host filesystem — no round
//	trip, and it keeps working while the container runtime is busy;
//
//	the Engine API, which runs `cat` inside the container — the fallback for
//	an image built before the bind mount existed.
//
// What is deliberately absent is a third option: shelling out to the `docker`
// command. The daemon runs as root, and on this platform that command is a
// user-owned symlink into an application bundle, so executing it would hand
// root's privileges to whatever an unprivileged writer put there.
package vpndns

import (
	"context"
	"fmt"
	"os"
	"strings"

	"vpn-router/internal/dockerctl"
)

// ContainerFunc returns the id of the container to read from, or "" when it is
// not known yet.
type ContainerFunc func() string

type Source struct {
	// File is the host-side path of the shared bind mount. Empty disables it.
	File string

	Docker    *dockerctl.Client
	Container ContainerFunc
	// Path is the file's location inside the container.
	Path string

	// Logf records the ordinary course of events, Warnf the parts that need
	// attention. They are separate because the healthy path here is worth
	// stating — which route is in use is not otherwise visible — and logging
	// it as a warning is how warnings stop being read.
	Logf  func(string, ...any)
	Warnf func(string, ...any)

	// reported remembers which route was announced, so the choice is visible
	// once in the log instead of either silently or on every refresh. Which
	// one is in use matters: a bind mount that is not actually shared reads
	// as "working" because the API fallback covers it.
	reported string
}

func (s *Source) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Source) warnf(format string, args ...any) {
	if s.Warnf != nil {
		s.Warnf(format, args...)
		return
	}
	s.logf(format, args...)
}

// Servers satisfies dnsrouter.ServerSource.
func (s *Source) Servers(ctx context.Context) ([]string, error) {
	if s.File != "" {
		if addrs, err := readFile(s.File); err == nil && len(addrs) > 0 {
			s.report("file", "reading the shared file %s", s.File)
			return addrs, nil
		} else if err != nil && !os.IsNotExist(err) {
			s.warnf("vpn-dns: reading %s failed (%v), falling back to the container", s.File, err)
		}
	}

	if s.Docker == nil || s.Container == nil {
		return nil, fmt.Errorf("no source for VPN DNS servers")
	}

	id := s.Container()
	if id == "" {
		return nil, fmt.Errorf("VPN container not identified yet")
	}

	path := s.Path
	if path == "" {
		path = "/run/vpn-dns"
	}

	out, err := s.Docker.ReadFile(ctx, id, path)
	if err != nil {
		return nil, fmt.Errorf("read %s from container: %w", path, err)
	}

	if s.File != "" {
		// A configured shared file that never appears is the silent failure
		// this package's comment describes, so it is a warning even though
		// everything still works.
		s.reportWarn("api", "the shared file %s is not appearing, reading %s from inside the container instead "+
			"(check that the bind mount's host path is one the container runtime shares)", s.File, path)
	} else {
		s.report("api", "reading %s from inside the container", path)
	}

	return strings.Fields(string(out)), nil
}

// report notes the chosen route the first time it is used, and again whenever
// it changes.
func (s *Source) report(route, format string, args ...any) {
	if s.reported == route {
		return
	}
	s.reported = route
	s.logf("vpn-dns: "+format, args...)
}

// reportWarn is report at warning level.
func (s *Source) reportWarn(route, format string, args ...any) {
	if s.reported == route {
		return
	}
	s.reported = route
	s.warnf("vpn-dns: "+format, args...)
}

func readFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(data)), nil
}
