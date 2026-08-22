package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"time"
)

// startPprof exposes Go's profiling endpoints on a loopback address.
//
// Off unless asked for. It is here because a question came up that no amount
// of reasoning about the code could settle — the same relay code moved data at
// full speed as a standalone process and at a fraction of it inside the
// daemon, with the CPU almost idle — and "where is it blocked" is a question
// the runtime can answer directly.
//
// Block and mutex profiling are switched on with it. Both cost something on
// every synchronisation event, which is why they are not on by default.
func startPprof(addr string, logf func(string, ...any)) {
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logf("pprof: %v", err)
		return
	}

	host, _, _ := net.SplitHostPort(ln.Addr().String())
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		// Profiles expose stack traces and can be used to stall the process;
		// this is a diagnostic port, not a service.
		logf("pprof: refusing to serve on a non-loopback address %s", addr)
		ln.Close()
		return
	}

	logf("pprof: http://%s/debug/pprof/ (block and mutex profiling are on)", ln.Addr())

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil {
			fmt.Fprintf(os.Stderr, "pprof: %v\n", err)
		}
	}()
}
