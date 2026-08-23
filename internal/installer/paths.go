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

	// SymlinkPath puts vpnctl on the default PATH, so "vpnctl status" works
	// without anyone having to remember where the binary lives.
	SymlinkPath = "/usr/local/bin/vpnctl"

	// UpdateStagingName is where "vpnctl update" leaves the freshly
	// downloaded binary before handing over to it. Install removes it once
	// the real copy is in place.
	UpdateStagingName = "vpnctl.update"
)

// InstallRecord names the file recording who an installation belongs to. A
// variable rather than a constant only so a test can put it somewhere
// writable; nothing sets it at runtime.
var InstallRecord = EtcDir + "/install.json"

// Target describes who the installation is for. The daemon runs as root but
// belongs to one login user: their config file, their group on the control
// socket, their LaunchAgent.
type Target struct {
	User    string
	UID     int
	GID     int
	HomeDir string
}

// ResolveTarget identifies the person an installation belongs to. Installing
// "for root" is refused, because the config and the menu bar belong to
// somebody who logs in.
//
// SUDO_USER first, because that is who is actually running this. Failing that,
// the record a previous install left: root can arrive here without sudo — from
// an authorisation dialog, a root shell, a launchd job — and on a machine that
// already has vpnctl, the person it was installed for is not in doubt. Only a
// first install on such a path has nothing to go on, and that is the case the
// error is about.
func ResolveTarget() (*Target, error) {
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		if rec, err := LoadRecord(); err == nil {
			name = rec.User
		}
	}
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

// AgentLog is where the menu bar's own output goes.
//
// Not beside the daemon's log: that directory is root-owned, and the menu bar
// runs as the user, so launchd could not create the file there. ~/Library/Logs
// is where a user agent's log belongs anyway — Console.app lists it.
func (t *Target) AgentLog() string {
	return filepath.Join(t.HomeDir, "Library", "Logs", "vpnctl-menubar.log")
}

// DefaultConfigPath mirrors config.DefaultPath but for another user's home,
// which is what an installer running as root needs.
func (t *Target) DefaultConfigPath() string {
	return filepath.Join(t.HomeDir, ".config", "vpnctl", "config.yaml")
}
