package main

import (
	"context"
	"flag"
	"fmt"
	"os"
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

	// Hand over. The new binary copies itself into place, refreshes sing-box,
	// the container and the launchd jobs, and removes this staging file.
	if err := syscall.Exec(staged, []string{staged, "install"}, os.Environ()); err != nil {
		return fmt.Errorf("run the new binary: %w", err)
	}
	return nil
}
