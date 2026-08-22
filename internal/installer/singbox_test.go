package installer

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestHashFileFollowsSymlinks matters because the thing being hashed may be a
// link into a package manager's cellar, and hashing the link rather than the
// file it names would compare nothing useful.
func TestHashFileFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()

	real := filepath.Join(dir, "real")
	body := []byte("a binary, more or less")
	if err := os.WriteFile(real, body, 0o755); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])

	for _, path := range []string{real, link} {
		got, err := hashFile(path)
		if err != nil {
			t.Fatalf("hashFile(%s): %v", path, err)
		}
		if got != want {
			t.Errorf("hashFile(%s) = %s, want %s", path, got, want)
		}
	}
}

func TestHashFileReportsAMissingFile(t *testing.T) {
	if _, err := hashFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("hashing a missing file succeeded")
	}
}

// TestInstalledHashIsAbsentWhenNothingIsInstalled keeps the skip path from
// mistaking "no binary" for "the right binary".
func TestInstalledHashIsAbsentWhenNothingIsInstalled(t *testing.T) {
	if _, err := os.Stat(SingBoxPath); err == nil {
		t.Skip("a sing-box is installed on this machine")
	}
	if _, ok := installedHash(); ok {
		t.Error("installedHash reported a hash with nothing installed")
	}
}
