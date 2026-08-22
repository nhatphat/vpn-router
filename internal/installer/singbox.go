package installer

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"vpn-router/internal/config"
)

// releaseURL builds the official download URL for a sing-box version.
func releaseURL(version string) string {
	arch := runtime.GOARCH // "arm64" and "amd64" match upstream's naming
	return fmt.Sprintf(
		"https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-darwin-%s.tar.gz",
		version, version, arch)
}

// InstallSingBox puts a root-owned sing-box at SingBoxPath.
//
// The daemon refuses to execute a binary a non-root user can replace, so this
// is not a convenience: a Homebrew-installed sing-box lives under a
// user-writable prefix and would be rejected. Copying it here is what makes it
// usable, and it also pins the version against an unrelated `brew upgrade`.
//
// fromPath, when set, is copied instead of downloading — useful offline, and
// for reusing a binary a package manager already verified.
func InstallSingBox(version, fromPath string, pins config.Hashes, logf func(string, ...any)) (string, error) {
	if err := os.MkdirAll(LibexecDir, 0o755); err != nil {
		return "", err
	}

	var (
		data []byte
		err  error
		src  string
	)

	if fromPath != "" {
		src = fromPath
		resolved, rerr := filepath.EvalSymlinks(fromPath)
		if rerr != nil {
			return "", fmt.Errorf("resolve %s: %w", fromPath, rerr)
		}
		data, err = os.ReadFile(resolved)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", resolved, err)
		}
		logf("copying sing-box from %s", resolved)
	} else {
		src = releaseURL(version)
		logf("downloading %s", src)
		data, err = downloadAndExtract(src)
		if err != nil {
			return "", err
		}
	}

	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	key := config.PinKey(version, config.Platform())
	want, pinned := pins.Lookup(version)

	switch {
	case fromPath != "":
		// The pin describes the published release, and this binary did not
		// come from there. Checking it would fail on a perfectly good file.
		logf("sing-box sha256: %s (copied from local disk, so the pinned release checksum does not apply)", got)

	case !pinned:
		// HTTPS to the release host authenticates the source, so an unpinned
		// download is not unverified — but it is unreproducible. Print the
		// hash and the exact key to record it under.
		logf("sing-box sha256: %s", got)
		logf("  this version is not pinned; add it under singbox.sha256 as:")
		logf("    %s: %s", key, got)

	case !strings.EqualFold(want, got):
		return "", fmt.Errorf("sing-box checksum mismatch for %s\n  want %s\n  got  %s\n  from %s\n\n"+
			"The pin names this exact version, so this is not a version mismatch: either the\n"+
			"release was replaced or the download was tampered with. Nothing was installed.",
			key, want, got, src)

	default:
		logf("sing-box sha256 verified against the pin for %s", key)
	}

	// Write via a temporary file in the same directory so the replacement is
	// atomic: the daemon may be about to execute this path.
	tmp, err := os.CreateTemp(LibexecDir, "sing-box-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chown(tmp.Name(), 0, 0); err != nil {
		return "", fmt.Errorf("chown sing-box to root: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), SingBoxPath); err != nil {
		return "", err
	}

	return got, nil
}

func downloadAndExtract(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s (is the version right?)", url, resp.Status)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gunzip %s: %w", url, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no sing-box binary inside %s", url)
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "sing-box" {
			continue
		}
		// Bounded read: a hostile archive should not be able to exhaust
		// memory here.
		const maxBinary = 200 << 20
		data, err := io.ReadAll(io.LimitReader(tr, maxBinary))
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("sing-box entry in %s is empty", url)
		}
		return data, nil
	}
}
