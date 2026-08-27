package main

import (
	"context"
	"flag"
	"fmt"

	"vpn-router/internal/ipc"
	"vpn-router/internal/logbus"
	"vpn-router/internal/status"
)

func client(socketPath string) *ipc.Client {
	return &ipc.Client{Path: socketPath}
}

func statusCmd(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
	watch := fs.Bool("w", false, "keep printing as the status changes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	print := func(s *status.Snapshot) {
		mark := map[status.Overall]string{
			status.OverallGreen: "OK", status.OverallYellow: "!!", status.OverallRed: "XX",
		}[s.Overall]
		fmt.Printf("[%s] %s  (generation %d, vpnctl %s)\n", mark, s.Reason, s.Generation, s.Version)
		for _, c := range s.Components {
			line := fmt.Sprintf("  %-11s %-12s %s", c.Name, c.Phase, c.Detail)
			if c.Restarts > 0 {
				line += fmt.Sprintf(" [%d restarts]", c.Restarts)
			}
			fmt.Println(line)
			if c.LastErr != "" && c.Phase != status.PhaseRunning {
				fmt.Printf("  %-11s %s\n", "", "last error: "+c.LastErr)
			}
		}
	}

	if !*watch {
		resp, err := client(*socketPath).Do(ipc.Request{Op: ipc.OpStatus})
		if err != nil {
			return err
		}
		print(resp.Status)
		return nil
	}

	return client(*socketPath).Stream(context.Background(), ipc.Request{Op: ipc.OpStatusStream}, func(r *ipc.Response) bool {
		if r.Status != nil {
			fmt.Println()
			print(r.Status)
		}
		return true
	})
}

func logsCmd(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
	follow := fs.Bool("f", false, "keep streaming new entries")
	source := fs.String("source", "", "only this source (supervisor, singbox, vpn, dns, racer)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	printEntry := func(e logbus.Entry) {
		suffix := ""
		if e.Count > 1 {
			suffix = fmt.Sprintf("  (x%d)", e.Count)
		}
		fmt.Printf("%s %-10s %-5s %s%s\n",
			e.TS.Format("15:04:05"), e.Source, e.Level, e.Msg, suffix)
	}

	req := ipc.Request{Op: ipc.OpLogs, Source: logbus.Source(*source), Follow: *follow}

	if !*follow {
		resp, err := client(*socketPath).Do(req)
		if err != nil {
			return err
		}
		for _, e := range resp.Entries {
			printEntry(e)
		}
		return nil
	}

	return client(*socketPath).Stream(context.Background(), req, func(r *ipc.Response) bool {
		for _, e := range r.Entries {
			printEntry(e)
		}
		if r.Entry != nil {
			printEntry(*r.Entry)
		}
		return true
	})
}

func restartCmd(args []string) error {
	fs := flag.NewFlagSet("restart", flag.ExitOnError)
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	component := "all"
	if fs.NArg() > 0 {
		component = fs.Arg(0)
	}

	if _, err := client(*socketPath).Do(ipc.Request{Op: ipc.OpRestart, Component: component}); err != nil {
		return err
	}
	fmt.Printf("restart requested: %s\n", component)
	return nil
}

func reloadCmd(args []string) error {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resp, err := client(*socketPath).Do(ipc.Request{Op: ipc.OpReload})
	if err != nil {
		return err
	}

	r := resp.Reload
	if r == nil {
		fmt.Println("reloaded")
		return nil
	}

	if len(r.Restarted) == 0 {
		fmt.Printf("%s parses to the configuration already running; nothing restarted\n", r.ConfigPath)
		return nil
	}

	fmt.Printf("applied %s\n", r.ConfigPath)
	for _, c := range r.Restarted {
		fmt.Printf("  restarting %s\n", c)
	}
	if r.Disruptive {
		fmt.Println("\nsing-box is restarting, so the tunnel interface drops for a moment and")
		fmt.Println("connections through it are reset. Public traffic continues directly.")
	}
	return nil
}

func retryCmd(args []string) error {
	fs := flag.NewFlagSet("retry", flag.ExitOnError)
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := client(*socketPath).Do(ipc.Request{Op: ipc.OpRetry}); err != nil {
		return err
	}
	fmt.Println("leaving safe mode")
	return nil
}
