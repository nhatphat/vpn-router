package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"vpn-router/internal/config"
	"vpn-router/internal/installer"
)

func genSingbox(args []string) error {
	fs := flag.NewFlagSet("gen-singbox", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yaml")
	out := fs.String("o", "-", `write to this path ("-" for stdout)`)
	if err := fs.Parse(args); err != nil {
		return err
	}

	_, doc, err := generate(*configPath)
	if err != nil {
		return err
	}

	if *out == "-" {
		_, err = os.Stdout.Write(doc)
		return err
	}
	return os.WriteFile(*out, doc, 0o644)
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yaml")
	singboxBin := fs.String("singbox", "", "sing-box binary to validate with (default: config, then $PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, doc, err := generate(*configPath)
	if err != nil {
		return err
	}
	fmt.Printf("config      %s: ok\n", cfg.Path)

	// Same order the daemon uses, so "check" validates with the binary that
	// would actually run. The managed copy comes before anything on PATH:
	// after installation there may be nothing on PATH at all.
	bin := *singboxBin
	for _, candidate := range []string{cfg.SingBox.Binary, installer.SingBoxPath} {
		if bin != "" {
			break
		}
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			bin = candidate
		}
	}
	if bin == "" {
		if found, err := exec.LookPath("sing-box"); err == nil {
			bin = found
		}
	}
	if bin == "" {
		fmt.Println("sing-box    not found: skipped document validation")
		return nil
	}

	if err := config.CheckExecutable(bin, cfg.SingBox.AllowUnsafeBinary); err != nil {
		// Not fatal here: "check" only validates a document, it does not run
		// anything as root. The daemon enforces this for real.
		fmt.Printf("sing-box    %s: WARNING %v\n", bin, err)
	}

	tmp, err := os.CreateTemp("", "vpnctl-singbox-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(doc); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	out, err := exec.Command(bin, "check", "-c", tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box check failed: %v\n%s", err, out)
	}
	fmt.Printf("sing-box    %s: document ok\n", bin)
	if len(out) > 0 {
		fmt.Printf("%s", out)
	}
	return nil
}

func configExampleCmd(args []string) error {
	fs := flag.NewFlagSet("config-example", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Print(config.ExampleYAML)
	return nil
}
