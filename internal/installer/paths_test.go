package installer

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// TestResolveTargetFallsBackToTheInstallRecord covers the path that broke a
// real update. The menu bar gets root through an authorisation dialog, not
// through sudo, so SUDO_USER is not set — and an install that can only read
// SUDO_USER stops there, after the new binary has already been downloaded,
// verified and staged.
func TestResolveTargetFallsBackToTheInstallRecord(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	if me.Username == "root" {
		t.Skip("this test needs a non-root user to name")
	}

	dir := t.TempDir()
	restore := InstallRecord
	InstallRecord = filepath.Join(dir, "install.json")
	t.Cleanup(func() { InstallRecord = restore })

	t.Setenv("SUDO_USER", "")

	if _, err := ResolveTarget(); err == nil {
		t.Fatal("with no sudo and no record, resolving a target should fail rather than guess")
	}

	rec, _ := json.Marshal(Record{User: me.Username})
	if err := os.WriteFile(InstallRecord, rec, 0o644); err != nil {
		t.Fatalf("write record: %v", err)
	}

	target, err := ResolveTarget()
	if err != nil {
		t.Fatalf("with a record present: %v", err)
	}
	if target.User != me.Username {
		t.Fatalf("resolved %q, want %q", target.User, me.Username)
	}
}

// TestSudoUserWinsOverTheRecord: the record says who the machine was set up
// for, but somebody running this under sudo right now is who to believe.
func TestSudoUserWinsOverTheRecord(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Username == "root" {
		t.Skip("this test needs a non-root user to name")
	}

	dir := t.TempDir()
	restore := InstallRecord
	InstallRecord = filepath.Join(dir, "install.json")
	t.Cleanup(func() { InstallRecord = restore })

	rec, _ := json.Marshal(Record{User: "nobody-at-all"})
	if err := os.WriteFile(InstallRecord, rec, 0o644); err != nil {
		t.Fatalf("write record: %v", err)
	}
	t.Setenv("SUDO_USER", me.Username)

	target, err := ResolveTarget()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if target.User != me.Username {
		t.Fatalf("resolved %q, want the sudo user %q", target.User, me.Username)
	}
}

// TestARootRecordIsRefused: "installed for root" is not a thing this program
// does, and a record claiming it must not talk it into trying.
func TestARootRecordIsRefused(t *testing.T) {
	dir := t.TempDir()
	restore := InstallRecord
	InstallRecord = filepath.Join(dir, "install.json")
	t.Cleanup(func() { InstallRecord = restore })

	rec, _ := json.Marshal(Record{User: "root"})
	if err := os.WriteFile(InstallRecord, rec, 0o644); err != nil {
		t.Fatalf("write record: %v", err)
	}
	t.Setenv("SUDO_USER", "")

	if _, err := ResolveTarget(); err == nil {
		t.Fatal("a record naming root was accepted")
	}
}
