// Package release fetches vpnctl's own published builds.
//
// Everything here downloads over HTTPS and then checks the result against the
// SHA256SUMS published beside it. HTTPS already authenticates the host, so the
// checksum is not there to catch a hostile network; it is there so that what
// gets installed is demonstrably the artefact the release names, and so a
// truncated or half-written download fails loudly instead of producing a
// binary that runs as root.
package release

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// Owner and Repo name where releases are published.
	Owner = "nhatphat"
	Repo  = "vpn-router"

	// SumsName is the checksum file published with every release.
	SumsName = "SHA256SUMS"

	// maxAsset bounds a download so a hostile or broken response cannot
	// exhaust memory.
	maxAsset = 200 << 20
)

// AssetName is the archive published for a version on this platform.
func AssetName(version string) string {
	return fmt.Sprintf("vpnctl_%s_%s_%s.tar.gz", strings.TrimPrefix(version, "v"), runtime.GOOS, runtime.GOARCH)
}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type Release struct {
	Tag        string  `json:"tag_name"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
	HTMLURL    string  `json:"html_url"`
}

// Asset finds a published file by name.
func (r *Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

func client() *http.Client { return &http.Client{Timeout: 5 * time.Minute} }

// Latest returns the newest published release, ignoring pre-releases.
func Latest(ctx context.Context) (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", Owner, Repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("ask GitHub for the latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s/%s has no published releases yet", Owner, Repo)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ask GitHub for the latest release: %s", resp.Status)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// Fetch downloads one asset.
func Fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxAsset))
}

// VerifySum checks data against the entry for name in a SHA256SUMS file.
//
// A missing entry is an error rather than a pass. "No checksum was published
// for this file" and "the checksum matched" must not lead to the same place.
func VerifySum(sums []byte, name string, data []byte) error {
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// shasum writes "<hash>  <name>", with the name sometimes prefixed
		// by "*" for binary mode.
		if strings.TrimPrefix(fields[1], "*") == name {
			want = fields[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("%s lists no checksum for %s", SumsName, name)
	}

	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(want, got) {
		return fmt.Errorf("checksum mismatch for %s\n  want %s\n  got  %s", name, want, got)
	}
	return nil
}

// ExtractBinary pulls one file out of a gzipped tar archive.
func ExtractBinary(archive []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no %s inside the archive", name)
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Name != name {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, maxAsset))
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("%s in the archive is empty", name)
		}
		return data, nil
	}
}

// IsNewer compares two versions the way releases are tagged: v1.2.3, with a
// leading v that may or may not be there.
//
// An unparsable current version — "dev", from a local build — counts as older
// than anything published, because a developer asking to update is asking to
// move to a release.
func IsNewer(candidate, current string) bool {
	c, okC := parse(candidate)
	n, okN := parse(current)
	if !okC {
		return false
	}
	if !okN {
		return true
	}

	for i := 0; i < len(c) && i < len(n); i++ {
		if c[i] != n[i] {
			return c[i] > n[i]
		}
	}
	return len(c) > len(n)
}

func parse(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return nil, false
	}
	// Ignore any pre-release suffix; the numeric part is what orders them.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}

	var out []int
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}
