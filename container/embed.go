// Package container carries the VPN container's build context inside the
// vpnctl binary.
//
// It is embedded rather than read from the source tree because an installed
// vpnctl has to be self-sufficient: the binary plus ~/.config/vpnctl is the
// whole runtime, and a checkout of this repository is only needed to change
// vpnctl, never to run it. That includes being able to build the image on a
// machine that has never seen the source.
//
// The consequence is intentional: changing anything in context/ means
// rebuilding vpnctl. The image and the supervisor that manages it are one
// artefact with one version.
package container

import (
	"archive/tar"
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
)

//go:embed context
var contextFS embed.FS

// ImageTag is the image vpnctl builds and runs. The tag carries a content
// hash so an upgraded vpnctl does not silently keep running an old image.
const imageRepo = "vpnctl/vpn"

// BuildContext returns the embedded context as an uncompressed tar archive,
// which is the format the Engine API's build endpoint expects.
func BuildContext() ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	err := fs.WalkDir(contextFS, "context", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		data, err := contextFS.ReadFile(path)
		if err != nil {
			return err
		}

		name := filepath.Base(path)
		mode := int64(0o644)
		// Scripts have to be executable in the context so the image does not
		// depend on a chmod that could be forgotten.
		if filepath.Ext(name) == ".sh" || filepath.Ext(name) == ".exp" {
			mode = 0o755
		}

		hdr := &tar.Header{
			Name:     name,
			Mode:     mode,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
			// A fixed timestamp keeps the archive byte-identical across
			// builds, so the content hash below identifies the content and
			// not the moment it was packed.
			ModTime: fixedModTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Files lists what is embedded, for diagnostics.
func Files() ([]string, error) {
	var out []string
	err := fs.WalkDir(contextFS, "context", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		out = append(out, filepath.Base(path))
		return nil
	})
	return out, err
}

// ImageTag is vpnctl's image name, tagged with a hash of the build context so
// that a vpnctl carrying a different context runs a different image.
func ImageTag() (string, error) {
	sum, err := ContextHash()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s", imageRepo, sum[:12]), nil
}
