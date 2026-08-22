package main

import (
	"flag"
	"fmt"
	"os"

	"vpn-router/internal/doctor"
	"vpn-router/internal/ipc"
)

func doctorCmd(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yaml")
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	report := doctor.Run(doctor.Options{ConfigPath: *configPath, SocketPath: *socketPath})

	mark := map[doctor.Level]string{
		doctor.LevelOK:   "ok  ",
		doctor.LevelWarn: "warn",
		doctor.LevelFail: "FAIL",
	}

	for _, c := range report.Checks {
		fmt.Printf("%s  %-16s %s\n", mark[c.Level], c.Name, c.Detail)
		if c.Fix != "" {
			fmt.Printf("      %-16s -> %s\n", "", c.Fix)
		}
	}

	ok, warn, fail := report.Counts()
	fmt.Printf("\n%d ok, %d warning(s), %d failure(s)\n", ok, warn, fail)

	if report.Failed() {
		// A non-zero exit makes this usable from a script or a launchd job.
		os.Exit(1)
	}
	return nil
}

// configExampleCmd prints the annotated default configuration, which is
// embedded in the binary so it cannot drift from the compiled defaults.
