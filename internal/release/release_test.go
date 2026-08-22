package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		candidate, current string
		want               bool
	}{
		{"v1.2.4", "v1.2.3", true},
		{"v1.3.0", "v1.2.9", true},
		{"v2.0.0", "v1.99.99", true},
		{"1.2.3", "v1.2.3", false},
		{"v1.2.3", "v1.2.4", false},
		{"v1.2", "v1.2.1", false},
		{"v1.2.1", "v1.2", true},
		// A local build reports "dev", and someone running update from one is
		// asking to move to a release.
		{"v0.1.0", "dev", true},
		{"v0.1.0", "", true},
		// Nonsense on the published side must never look like an upgrade.
		{"", "v1.0.0", false},
		{"latest", "v1.0.0", false},
		// A pre-release suffix orders by its numeric part.
		{"v1.3.0-rc.1", "v1.2.0", true},
	}

	for _, c := range cases {
		if got := IsNewer(c.candidate, c.current); got != c.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", c.candidate, c.current, got, c.want)
		}
	}
}

func TestVerifySum(t *testing.T) {
	data := []byte("the artefact")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	sums := fmt.Sprintf("%s  vpnctl_1.0.0_darwin_arm64.tar.gz\n%s  something-else.tar.gz\n",
		hash, strings.Repeat("0", 64))

	if err := VerifySum([]byte(sums), "vpnctl_1.0.0_darwin_arm64.tar.gz", data); err != nil {
		t.Errorf("a matching checksum was rejected: %v", err)
	}

	if err := VerifySum([]byte(sums), "something-else.tar.gz", data); err == nil {
		t.Error("a mismatched checksum was accepted")
	}

	// The case that matters: no entry must not read as success.
	if err := VerifySum([]byte(sums), "not-published.tar.gz", data); err == nil {
		t.Error("a missing checksum entry was treated as verified")
	} else if !strings.Contains(err.Error(), "no checksum") {
		t.Errorf("the error does not say the entry is missing: %v", err)
	}
}

func TestVerifySumAcceptsBinaryModeMarker(t *testing.T) {
	data := []byte("x")
	sum := sha256.Sum256(data)
	sums := fmt.Sprintf("%s *file.tar.gz\n", hex.EncodeToString(sum[:]))

	if err := VerifySum([]byte(sums), "file.tar.gz", data); err != nil {
		t.Errorf("shasum's binary-mode marker was not handled: %v", err)
	}
}

func TestExtractBinary(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for name, body := range map[string]string{"README": "hello", "vpnctl": "ELF-ish"} {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()

	got, err := ExtractBinary(buf.Bytes(), "vpnctl")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ELF-ish" {
		t.Errorf("extracted %q", got)
	}

	if _, err := ExtractBinary(buf.Bytes(), "absent"); err == nil {
		t.Error("extracting a missing file succeeded")
	}
}

func TestAssetNameDropsTheLeadingV(t *testing.T) {
	// The tag is v1.2.3 but the file is named 1.2.3; getting this wrong means
	// a release that exists but cannot be downloaded.
	if got := AssetName("v1.2.3"); !strings.HasPrefix(got, "vpnctl_1.2.3_") {
		t.Errorf("AssetName(v1.2.3) = %q", got)
	}
	if AssetName("v1.2.3") != AssetName("1.2.3") {
		t.Error("the leading v changes the asset name")
	}
}
