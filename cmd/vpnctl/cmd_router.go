package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"vpn-router/internal/config"
	"vpn-router/internal/dnsrouter"
	"vpn-router/internal/dockerctl"
	"vpn-router/internal/netmon"
	"vpn-router/internal/racer"
	"vpn-router/internal/vpndns"
)

func runRouter(args []string) error {
	fs := flag.NewFlagSet("run-router", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yaml (default: $XDG_CONFIG_HOME/vpnctl/config.yaml)")

	// The flags below keep the same names and meanings the standalone
	// host-dns-router binary had, so existing habits and scripts still work.
	// An explicitly set flag wins over the config file.
	listen := fs.String("listen", "", "address to listen on for DNS queries from sing-box")
	publicDNS := fs.String("public-dns", "", "upstream public DNS server")
	bindInterface := fs.String("bind-interface", "", "physical interface to bind direct traffic to, bypassing the TUN")
	socksAddr := fs.String("socks", "", "SOCKS5 proxy address exposed by the VPN container")
	container := fs.String("container", "", "docker container name/id running the VPN")
	racerListen := fs.String("racer-listen", "", "address for the tier-2 race-dial SOCKS5 server")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	override := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	override(&cfg.DNSRouter.Listen, *listen)
	override(&cfg.DNSRouter.PublicDNS, *publicDNS)
	override(&cfg.DNSRouter.BindInterface, *bindInterface)
	override(&cfg.Docker.Socks, *socksAddr)
	override(&cfg.Docker.Container, *container)
	override(&cfg.Racer.Listen, *racerListen)

	bindIP, resolved, err := netmon.Static(cfg.DNSRouter.BindInterface)
	if err != nil {
		return err
	}
	if resolved != nil {
		fmt.Fprintf(os.Stderr, "binding direct traffic to %s (%s)\n", cfg.DNSRouter.BindInterface, resolved)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	docker, err := dockerctl.New(cfg.Docker.Host)
	if err != nil {
		return err
	}

	var containerID atomic.Pointer[string]
	go resolveContainer(ctx, docker, cfg, &containerID)

	servers := &vpndns.Source{
		File:   cfg.Docker.VPNDNSFile,
		Docker: docker,
		Container: func() string {
			if p := containerID.Load(); p != nil {
				return *p
			}
			return ""
		},
		Logf:  log.Printf,
		Warnf: log.Printf,
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return dnsrouter.Start(ctx, dnsrouter.Config{
			Listen:          cfg.DNSRouter.Listen,
			PublicDNS:       cfg.DNSRouter.PublicDNS,
			SocksAddr:       cfg.Docker.Socks,
			RefreshInterval: cfg.DNSRouter.RefreshInterval.D(),
			QueryTimeout:    cfg.DNSRouter.QueryTimeout.D(),
			GraceWindow:     cfg.DNSRouter.GraceWindow.D(),
			BindIP:          bindIP,
			Servers:         servers.Servers,
		})
	})
	g.Go(func() error {
		return racer.Start(ctx, racer.Config{
			Listen:      cfg.Racer.Listen,
			SocksAddr:   cfg.Docker.Socks,
			DialTimeout: cfg.Racer.DialTimeout.D(),
			RelayBuffer: cfg.Racer.RelayBuffer.Bytes(),
			LearnedTTL:  cfg.Racer.LearnedTTL.D(),
			BindIP:      bindIP,
		})
	})

	return g.Wait()
}

// resolveContainer finds the VPN container in the background, so run-router
// starts serving immediately even when the container runtime is not up yet.
func resolveContainer(ctx context.Context, docker *dockerctl.Client, cfg *config.Config, out *atomic.Pointer[string]) {
	for {
		if ct, err := docker.FindByComposeProject(ctx, cfg.Docker.Project, "vpn"); err == nil {
			id := ct.ID
			out.Store(&id)
			return
		}
		if ct, err := docker.FindByName(ctx, cfg.Docker.Container); err == nil {
			id := ct.ID
			out.Store(&id)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// routerProcessName is the process that owns the DNS router's sockets, which
// sing-box's first route rule must name to keep the router's own queries from
// looping back through the TUN.
