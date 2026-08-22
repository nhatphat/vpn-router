package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"

	"vpn-router/internal/installer"
)

// versionCmd answers "what am I running" without going to the network, which
// "update -check" has to do and which is the wrong tool for a local question.
func versionCmd(args []string) error {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Printf("vpnctl %s  %s/%s\n", version, runtime.GOOS, runtime.GOARCH)

	if info, ok := debug.ReadBuildInfo(); ok {
		var revision, when string
		var dirty bool
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.time":
				when = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if revision != "" {
			short := revision
			if len(short) > 12 {
				short = short[:12]
			}
			// A dirty build is worth saying: it means the binary does not
			// correspond to any commit, so a bug report naming the revision
			// would send someone to the wrong code.
			suffix := ""
			if dirty {
				suffix = " (with uncommitted changes)"
			}
			fmt.Printf("  built from %s %s%s\n", short, when, suffix)
		}
		fmt.Printf("  %s\n", info.GoVersion)
	}

	if v, ok := singBoxVersion(); ok {
		fmt.Printf("  sing-box %s at %s\n", v, installer.SingBoxPath)
	}

	return nil
}

// singBoxVersion asks the managed binary what it is, rather than reporting
// what the configuration asks for: the two can differ until an install runs.
func singBoxVersion() (string, bool) {
	if _, err := os.Stat(installer.SingBoxPath); err != nil {
		return "", false
	}

	out, err := exec.Command(installer.SingBoxPath, "version").Output()
	if err != nil {
		return "", false
	}

	// "sing-box version 1.13.19" on the first line.
	first, _, _ := strings.Cut(string(out), "\n")
	fields := strings.Fields(first)
	if len(fields) < 3 {
		return "", false
	}
	return fields[2], true
}
