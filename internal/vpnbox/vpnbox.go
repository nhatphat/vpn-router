// Package vpnbox owns the VPN container: it builds the image from the context
// embedded in this binary, and creates and maintains the container from a
// specification written in Go.
//
// Compose is deliberately not involved at runtime. Two reasons came out of
// testing this setup. A compose-created container records the directory it was
// created from, which would tie a running installation to a checkout of the
// source; and `docker compose` is a CLI plugin that lives in the invoking
// user's home, so a root daemon cannot find it at all — verified on this
// platform, where the plugin resolves only through the user's DOCKER_CONFIG.
// Talking to the Engine API avoids both.
package vpnbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vpn-router/container"
	"vpn-router/internal/config"
	"vpn-router/internal/dockerctl"
)

const (
	// LabelOwner marks every container this package creates.
	LabelOwner = "vpnctl"
	// LabelSpec records a hash of the specification the container was created
	// from, so a changed configuration is detected without having to compare
	// the whole inspect output field by field.
	LabelSpec = "vpnctl.spec"

	// ComposeLabel identifies containers created by the older compose-based
	// setup, which have to be stood down before ours can bind the same port.
	ComposeLabel = "com.docker.compose.project"
)

type Options struct {
	Docker *dockerctl.Client
	Cfg    *config.Config
	Logf   func(string, ...any)
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// EnsureImage builds the image if the daemon does not already have it. The tag
// contains a hash of the embedded build context, so an unchanged vpnctl never
// rebuilds and a changed one always does.
func EnsureImage(ctx context.Context, o Options) (string, error) {
	tag, err := container.ImageTag()
	if err != nil {
		return "", err
	}

	exists, err := o.Docker.ImageExists(ctx, tag)
	if err != nil {
		return "", err
	}
	if exists {
		o.logf("image %s already built", tag)
		return tag, nil
	}

	tarball, err := container.BuildContext()
	if err != nil {
		return "", err
	}

	files, _ := container.Files()
	o.logf("building %s from %d embedded files (%s)", tag, len(files), strings.Join(files, ", "))

	if err := o.Docker.BuildImage(ctx, tag, tarball, func(line string) {
		o.logf("  %s", line)
	}); err != nil {
		return "", err
	}

	o.logf("built %s", tag)
	return tag, nil
}

// Spec builds the container specification. Every path in it is absolute and
// outside the source tree: the running installation must not depend on a
// checkout existing.
func Spec(cfg *config.Config, tag string) (dockerctl.ContainerSpec, error) {
	env, err := LoadEnvFile(cfg.VPN.EnvFile)
	if err != nil {
		return dockerctl.ContainerSpec{}, fmt.Errorf("read %s: %w", cfg.VPN.EnvFile, err)
	}

	secret := env["TOTP_SECRET"]
	if secret == "" {
		return dockerctl.ContainerSpec{}, fmt.Errorf(
			"TOTP_SECRET is not set in %s; the VPN cannot answer its one-time-code challenge without it",
			cfg.VPN.EnvFile)
	}

	for label, path := range map[string]string{
		"vpn.config":    cfg.VPN.Config,
		"vpn.auth_file": cfg.VPN.AuthFile,
	} {
		if _, err := os.Stat(path); err != nil {
			return dockerctl.ContainerSpec{}, fmt.Errorf("%s: %w", label, err)
		}
	}

	host, portStr, err := net.SplitHostPort(cfg.Docker.Socks)
	if err != nil {
		return dockerctl.ContainerSpec{}, fmt.Errorf("docker.socks: %w", err)
	}
	if _, err := strconv.Atoi(portStr); err != nil {
		return dockerctl.ContainerSpec{}, fmt.Errorf("docker.socks: bad port %q", portStr)
	}

	retry := cfg.VPN.RetryDelay.D()

	// The shared directory lives beside the config, not in the state
	// directory, because a container runtime only bind-mounts host paths its
	// virtual machine actually shares. Verified on this platform: a mount of
	// a path under /usr/local silently resolves inside the runtime's own VM
	// instead — the container writes the file, the host never sees it, and
	// nothing reports an error. Paths under /Users are shared.
	shared := SharedDir(cfg)

	spec := dockerctl.ContainerSpec{
		Image: tag,
		Env: []string{
			"TOTP_SECRET=" + secret,
			"VPN_CONFIG=/config/company.ovpn",
			"VPN_AUTH_FILE=/config/auth.txt",
			"RETRY_DELAY=" + strconv.Itoa(int(retry.Seconds())),
		},
		Labels: map[string]string{
			LabelOwner: "true",
		},
		ExposedPorts: map[string]struct{}{"1080/tcp": {}},
		HostConfig: dockerctl.HostConfig{
			Binds: []string{
				cfg.VPN.Config + ":/config/company.ovpn:ro",
				cfg.VPN.AuthFile + ":/config/auth.txt:ro",
				shared + ":/run/shared",
			},
			CapAdd: []string{"NET_ADMIN"},
			Devices: []dockerctl.DeviceMapping{{
				PathOnHost:        "/dev/net/tun",
				PathInContainer:   "/dev/net/tun",
				CgroupPermissions: "rwm",
			}},
			PortBindings: map[string][]dockerctl.PortBinding{
				"1080/tcp": {{HostIP: host, HostPort: portStr}},
			},
			// The container restarts itself if the engine or the machine
			// restarts. That is the fail-closed half of the design: the proxy
			// inside it cannot leak, so having it come back on its own is
			// safe and means VPN traffic recovers without vpnctl acting.
			RestartPolicy: dockerctl.RestartPolicy{Name: "unless-stopped"},
		},
	}

	hash, err := specHash(spec)
	if err != nil {
		return dockerctl.ContainerSpec{}, err
	}
	spec.Labels[LabelSpec] = hash

	return spec, nil
}

// SharedDir is the host directory the container and the host exchange files
// through.
func SharedDir(cfg *config.Config) string {
	return filepath.Join(cfg.Dir, "run")
}

// specHash fingerprints the specification. The secret is part of the spec, so
// the hash is computed over it — which also means a rotated TOTP secret is
// noticed and the container is recreated.
func specHash(spec dockerctl.ContainerSpec) (string, error) {
	// Hash without the spec label itself, which does not exist yet.
	copySpec := spec
	labels := make(map[string]string, len(spec.Labels))
	for k, v := range spec.Labels {
		if k == LabelSpec {
			continue
		}
		labels[k] = v
	}
	copySpec.Labels = labels

	data, err := json.Marshal(copySpec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:32], nil
}

// EnsureContainer creates the container if it is missing, recreates it if the
// specification changed, and starts it if it is not running. It returns the
// container id.
func EnsureContainer(ctx context.Context, o Options, tag string) (string, error) {
	spec, err := Spec(o.Cfg, tag)
	if err != nil {
		return "", err
	}
	name := o.Cfg.Docker.Container

	existing, err := o.Docker.ListByLabel(ctx, LabelOwner+"=true")
	if err != nil {
		return "", err
	}

	for _, ct := range existing {
		if ct.Labels[LabelSpec] == spec.Labels[LabelSpec] && ct.Image == tag {
			if ct.State != "running" {
				o.logf("starting existing container %s", ct.Name())
				if err := o.Docker.Start(ctx, ct.ID); err != nil {
					return "", err
				}
			}
			return ct.ID, nil
		}

		reason := "configuration changed"
		if ct.Image != tag {
			reason = fmt.Sprintf("image changed (%s -> %s)", ct.Image, tag)
		}
		o.logf("recreating container %s: %s", ct.Name(), reason)
		if err := o.Docker.RemoveContainer(ctx, ct.ID); err != nil {
			return "", fmt.Errorf("remove outdated container %s: %w", ct.Name(), err)
		}
	}

	// A container may hold the name we want without carrying the label we
	// look for — most plainly after the label itself changes, as it did when
	// these names stopped borrowing an organisation's domain. The name comes
	// from our own configuration, so a container using it is one of ours, and
	// a container is disposable: the image and the configuration are what
	// carry state.
	if stale, err := o.Docker.FindByName(ctx, name); err == nil {
		o.logf("removing %s, which holds the name but not the current label", stale.Name())
		if err := o.Docker.RemoveContainer(ctx, stale.ID); err != nil {
			return "", fmt.Errorf("remove %s: %w", stale.Name(), err)
		}
	}

	id, err := o.Docker.CreateContainer(ctx, name, spec)
	if err != nil {
		return "", err
	}
	o.logf("created container %s", name)

	if err := o.Docker.Start(ctx, id); err != nil {
		return "", fmt.Errorf("start container %s: %w", name, err)
	}
	o.logf("started container %s", name)

	return id, nil
}

// StopLegacyContainers stands down containers from the older compose-based
// setup. They are stopped rather than deleted: stopping frees the port that
// ours needs, and is undone with a single `docker start` if anything here
// turns out to be wrong.
func StopLegacyContainers(ctx context.Context, o Options) error {
	list, err := o.Docker.ListByLabel(ctx, ComposeLabel+"="+o.Cfg.Docker.Project)
	if err != nil {
		return err
	}

	for _, ct := range list {
		if ct.Labels[LabelOwner] == "true" {
			continue // ours
		}
		if ct.State != "running" {
			continue
		}
		o.logf("stopping the compose-created container %s (it holds the SOCKS port)", ct.Name())
		if err := o.Docker.Stop(ctx, ct.ID, 15*time.Second); err != nil {
			return fmt.Errorf("stop %s: %w", ct.Name(), err)
		}
		o.logf("  it is only stopped, not deleted; \"docker start %s\" puts it back", ct.Name())

		// If it also holds the name ours wants, move it aside rather than
		// deleting it: a rename is reversible, and the alternative is a
		// create that fails on a name conflict.
		if ct.Name() == o.Cfg.Docker.Container {
			renamed := ct.Name() + "-precompose"
			if err := o.Docker.Rename(ctx, ct.ID, renamed); err != nil {
				return fmt.Errorf("rename %s out of the way: %w", ct.Name(), err)
			}
			o.logf("  renamed it to %s so the name is free", renamed)
		}
	}
	return nil
}
