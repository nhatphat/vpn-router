package container

import (
	"archive/tar"
	"bytes"
	"io"
	"sort"
	"strings"
	"testing"
)

// TestBuildContextCarriesEverythingTheImageNeeds guards the property the
// embedding exists for: an installed vpnctl can build the image with no source
// checkout present, so every file the Dockerfile references must be inside the
// binary.
func TestBuildContextCarriesEverythingTheImageNeeds(t *testing.T) {
	tarball, err := BuildContext()
	if err != nil {
		t.Fatalf("BuildContext: %v", err)
	}

	names, contents := readTar(t, tarball)
	sort.Strings(names)

	want := []string{
		"Dockerfile", "capture-dns.sh", "danted.conf",
		"entrypoint.sh", "healthcheck.sh", "vpn.exp",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("context holds %v, want %v", names, want)
	}

	dockerfile := contents["Dockerfile"]
	if dockerfile == "" {
		t.Fatal("Dockerfile is empty")
	}

	// Every COPY source in the Dockerfile must be present, flat, in the
	// archive: a stale path here fails the build only on a machine without
	// the source tree, which is the hardest place to debug it.
	for _, line := range strings.Split(dockerfile, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.EqualFold(fields[0], "COPY") {
			continue
		}
		src := fields[1]
		if _, ok := contents[src]; !ok {
			t.Errorf("Dockerfile copies %q, which is not in the embedded context", src)
		}
	}

	if !strings.Contains(dockerfile, "HEALTHCHECK") {
		t.Error("the image declares no HEALTHCHECK; the supervisor reads container health from it")
	}
}

func TestBuildContextIsDeterministic(t *testing.T) {
	first, err := BuildContext()
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildContext()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, second) {
		t.Fatal("BuildContext is not byte-stable, so the image tag would change on every build")
	}
}

func TestImageTagIsDerivedFromTheContent(t *testing.T) {
	tag, err := ImageTag()
	if err != nil {
		t.Fatal(err)
	}
	repo, digest, found := strings.Cut(tag, ":")
	if !found || repo != imageRepo || len(digest) != 12 {
		t.Fatalf("tag %q is not %s:<12 hex chars>", tag, imageRepo)
	}

	hash, err := ContextHash()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, digest) {
		t.Errorf("tag digest %q does not come from the context hash %q", digest, hash)
	}
}

func TestScriptsAreExecutableInTheArchive(t *testing.T) {
	tarball, err := BuildContext()
	if err != nil {
		t.Fatal(err)
	}

	tr := tar.NewReader(bytes.NewReader(tarball))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		executable := strings.HasSuffix(hdr.Name, ".sh") || strings.HasSuffix(hdr.Name, ".exp")
		if executable && hdr.Mode&0o111 == 0 {
			t.Errorf("%s is not executable in the archive (mode %o)", hdr.Name, hdr.Mode)
		}
	}
}

func readTar(t *testing.T, data []byte) ([]string, map[string]string) {
	t.Helper()
	var names []string
	contents := make(map[string]string)

	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		contents[hdr.Name] = string(body)
	}
	return names, contents
}
