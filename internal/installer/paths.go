// Package installer sets vpnctl up as a launchd daemon, once, so that nothing
// afterwards needs elevated privileges.
//
// The privilege model is deliberately boring: `sudo vpnctl install` is the
// only step that asks for authorisation, and it uses the machine's own
// mechanism — whatever the user has configured for sudo, which on a Mac with
// Touch ID configured in /etc/pam.d/sudo_local is a fingerprint. There is no
// custom authorisation code, no privileged helper to bless, and nothing to
// code-sign. After installation the daemon is resident, so restarting a
// component from the menu bar never prompts, and the stack is up after a
// reboot before anyone logs in.
package installer

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

const (
	// DaemonLabel is the launchd job that runs the supervisor as root.
	//
	// launchd labels are conventionally reverse-DNS, but that convention
	// exists to claim a name in a global namespace using a domain you own.
	// This project owns no domain, and borrowing an organisation's would be
	// worse than not using one: it would follow every copy of the software
	// around. The project's own name is unique enough for a job nobody
	// publishes.
	DaemonLabel = "vpnctl"
	// AgentLabel is the per-user job that runs the menu bar.
	AgentLabel = "vpnctl.menubar"

	LibexecDir = "/usr/local/libexec/vpnctl"
	StateDir   = "/usr/local/var/vpnctl"
	LogDir     = "/usr/local/var/log/vpnctl"
	EtcDir     = "/usr/local/etc/vpnctl"

	DaemonPlist = "/Library/LaunchDaemons/" + DaemonLabel + ".plist"

	// BinaryPath is where install copies vpnctl. The daemon is launched from
	// here rather than from wherever it was built, so a rebuild in a
	// developer's tree cannot change what root runs.
	BinaryPath = LibexecDir + "/vpnctl"
	// SingBoxPath is the managed copy of sing-box: root-owned, which is what
	// makes the daemon willing to execute it.
	SingBoxPath = LibexecDir + "/sing-box"

	InstallRecord = EtcDir + "/install.json"

	// SymlinkPath puts vpnctl on the default PATH, so "vpnctl status" works
	// without anyone having to remember where the binary lives.
	SymlinkPath = "/usr/local/bin/vpnctl"

	// UpdateStagingName is where "vpnctl update" leaves the freshly
	// downloaded binary before handing over to it. Install removes it once
	// the real copy is in place.
	UpdateStagingName = "vpnctl.update"
)

// Target describes who the installation is for. The daemon runs as root but
// belongs to one login user: their config file, their group on the control
// socket, their LaunchAgent.
type Target struct {
	User    string
	UID     int
	GID     int
	HomeDir string
}

// ResolveTarget identifies the invoking user behind sudo. Installing "for
// root" is refused, because the config and the menu bar belong to a person.
func ResolveTarget() (*Target, error) {
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return nil, fmt.Errorf("cannot tell which user to install for: run this through sudo, as\n  sudo vpnctl install")
	}

	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("look up user %s: %w", name, err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("parse gid %q: %w", u.Gid, err)
	}

	return &Target{User: name, UID: uid, GID: gid, HomeDir: u.HomeDir}, nil
}

// AgentPlist is the LaunchAgent path in the target user's home.
func (t *Target) AgentPlist() string {
	return filepath.Join(t.HomeDir, "Library", "LaunchAgents", AgentLabel+".plist")
}

// DefaultConfigPath mirrors config.DefaultPath but for another user's home,
// which is what an installer running as root needs.
func (t *Target) DefaultConfigPath() string {
	return filepath.Join(t.HomeDir, ".config", "vpnctl", "config.yaml")
}
