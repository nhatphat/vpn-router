package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"vpn-router/internal/installer"
	"vpn-router/internal/release"
)

// updateCmd replaces this installation with the latest published release.
//
// It ends by handing over to the new binary's own "install", rather than
// copying a file into place and restarting the daemon here. Everything an
// upgrade might need — a different pinned sing-box, a changed container
// specification, a new launchd job name — is already handled there, and
// duplicating any of it would create a second path that is only exercised
// during upgrades and therefore never quite right.
func updateCmd(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "report whether an update exists and do nothing else")
	force := fs.Bool("force", false, "reinstall even if the published version is not newer")
	detach := fs.Bool("detach", false, "run the install step in the background (used by the menu bar)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fmt.Printf("current version: %s\n", version)

	rel, err := release.Latest(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("latest release:  %s\n", rel.Tag)

	newer := release.IsNewer(rel.Tag, version)
	switch {
	case *check && newer:
		fmt.Printf("\nAn update is available: %s\nInstall it with:  sudo vpnctl update\n", rel.HTMLURL)
		return nil
	case *check:
		fmt.Println("\nAlready up to date.")
		return nil
	case !newer && !*force:
		fmt.Println("\nAlready up to date. Use -force to reinstall this version anyway.")
		return nil
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("updating replaces a root-owned binary and restarts the daemon:\n  sudo vpnctl update")
	}

	assetName := release.AssetName(rel.Tag)
	asset, ok := rel.Asset(assetName)
	if !ok {
		return fmt.Errorf("%s does not publish %s; this platform may not be built yet", rel.Tag, assetName)
	}

	sums, ok := rel.Asset(release.SumsName)
	if !ok {
		return fmt.Errorf("%s publishes no %s, so the download cannot be verified", rel.Tag, release.SumsName)
	}

	fmt.Printf("\ndownloading %s\n", asset.Name)
	archive, err := release.Fetch(ctx, asset.URL)
	if err != nil {
		return err
	}

	sumsData, err := release.Fetch(ctx, sums.URL)
	if err != nil {
		return err
	}
	if err := release.VerifySum(sumsData, assetName, archive); err != nil {
		return fmt.Errorf("%w\n\nNothing was installed", err)
	}
	fmt.Println("checksum verified")

	binary, err := release.ExtractBinary(archive, "vpnctl")
	if err != nil {
		return err
	}

	// Staged inside the install directory rather than a temporary one: it has
	// to be on a filesystem that allows execution, owned by root, and on the
	// same volume as its destination.
	staged := filepath.Join(installer.LibexecDir, installer.UpdateStagingName)
	if err := os.MkdirAll(installer.LibexecDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(staged, binary, 0o755); err != nil {
		return fmt.Errorf("stage the new binary: %w", err)
	}
	if err := os.Chown(staged, 0, 0); err != nil {
		return err
	}

	fmt.Printf("installing %s\n\n", rel.Tag)

	if *detach {
		return detachInstall(staged, rel.Tag)
	}

	// Hand over. The new binary copies itself into place, refreshes sing-box,
	// the container and the launchd jobs, and removes this staging file.
	if err := syscall.Exec(staged, []string{staged, "install"}, os.Environ()); err != nil {
		return fmt.Errorf("run the new binary: %w", err)
	}
	return nil
}

// UpdateLog is where a detached install writes what it did.
const UpdateLog = installer.LogDir + "/update.log"

// detachInstall runs the handover in a session of its own, and returns.
//
// Only the install step, and only when asked. Everything before it — reaching
// GitHub, the checksum, staging the binary — has already run and reported in
// the caller's own output, which is where an error belongs. What is left is
// the part that cannot run where it was started: installing reloads both
// launchd jobs, and "launchctl bootout" takes down every process in the job it
// unloads. Started from the menu bar, that is this process. Setsid puts it in
// a session launchd is not tearing down, which was measured rather than
// assumed — the child is reparented to pid 1 and survives the bootout that
// kills its parent.
func detachInstall(staged, tag string) error {
	if err := os.MkdirAll(installer.LogDir, 0o755); err != nil {
		return err
	}
	log, err := os.OpenFile(UpdateLog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", UpdateLog, err)
	}
	defer log.Close()

	fmt.Fprintf(log, "installing %s\n\n", tag)

	cmd := exec.Command(staged, "install")
	cmd.Stdout, cmd.Stderr = log, log

	// Name the user explicitly. The binary about to run is a published
	// release, which cannot be changed after the fact, and older ones work
	// out who to install for from SUDO_USER alone — which is not set when
	// root came from an authorisation dialog rather than sudo. Fixing that in
	// the installer only helps versions that do not exist yet; saying it here
	// works for every version there has ever been. exec uses the last value
	// for a duplicated key, so this wins over an inherited one.
	cmd.Env = os.Environ()
	if t, err := installer.ResolveTarget(); err == nil {
		cmd.Env = append(cmd.Env, "SUDO_USER="+t.User)
	}
	// Setsid, not just a background process: a new session is what takes it
	// out of the launchd job that is about to be unloaded.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the new binary: %w", err)
	}

	fmt.Printf("installing in the background; the log is %s\n", UpdateLog)
	return nil
}
