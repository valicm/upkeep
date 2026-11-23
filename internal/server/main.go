// Package server is "upkeep server": it takes the agents' reports, polls the appliances,
// asks the registries, sends the digest mail and serves the dashboard.
//
// Its HTTP side:
//
//	POST /api/v1/report   one report as JSON (internal/report), at most 1 MiB, with
//	                      "Authorization: Bearer <token>". 200 when stored; 400 for a body
//	                      that is no usable report, 401 without a known token, 403 for a
//	                      token that may not report that name, 409 for the name of a polled
//	                      system, 413 and 415 for a body too large or compressed.
//	GET  /api/v1/state    systems, image checks and findings as JSON, with the shared token.
//	DELETE /api/v1/systems/<name>
//	                      forget a system that no longer exists, with the shared token.
//	GET  /healthz         "ok", for a supervisor.
//	everything else       the dashboard, behind its password when [dashboard] sets one.
//
// Errors of the API are JSON: {"error": "..."}.
package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/valicm/upkeep/internal/demo"
	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/registry"
	"github.com/valicm/upkeep/internal/store"
	"github.com/valicm/upkeep/internal/version"
	"github.com/valicm/upkeep/internal/web"
)

const (
	// shutdownTimeout is how long requests in flight get to finish after SIGTERM.
	shutdownTimeout = 10 * time.Second
	// demoRefresh keeps the made-up systems of -demo from going silent while one looks.
	demoRefresh = 5 * time.Minute
	demoListen  = "127.0.0.1:8484"
)

// Main runs "upkeep server" with its command-line arguments, until SIGTERM or Ctrl-C.
func Main(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	return run(ctx, args, surroundings{stderr: os.Stderr})
}

// surroundings is what run takes from outside the process, so that tests can give it their
// own.
type surroundings struct {
	stderr    io.Writer
	listening func(net.Addr) // told the address once the server accepts connections
	registry  ImageChecker   // nil: the real registries
}

// run is Main without the signal handling: it serves until ctx is done.
func run(ctx context.Context, args []string, env surroundings) error {
	stderr := env.stderr
	flags := flag.NewFlagSet("upkeep server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", DefaultConfigPath, "the configuration `file`")
	demoMode := flags.Bool("demo", false, "show the dashboard with made-up systems; needs no configuration, agents or appliances")
	listen := flags.String("listen", "", "listen on this `address` instead of the configured one")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))

	// What runs beside the HTTP server. It starts once the server has its port, so that a
	// second upkeep started by mistake polls nothing, and it stops when work is cancelled:
	// when ctx is done or the HTTP server fails.
	var jobs []func(context.Context)
	work, cancel := context.WithCancel(ctx)
	var background sync.WaitGroup
	stop := func() {
		cancel()
		background.Wait()
	}
	defer stop()

	a := &api{now: time.Now, log: log, version: version.Version}
	var mapView web.Map
	if *demoMode {
		st := store.NewMemory()
		if err := demo.Fill(work, st, time.Now()); err != nil {
			return fmt.Errorf("filling the demo: %w", err)
		}
		jobs = append(jobs, func(ctx context.Context) {
			every(ctx, demoRefresh, demoRefresh, func(ctx context.Context) {
				if err := demo.Fill(ctx, st, time.Now()); err != nil {
					log.Error("demo not refreshed", "error", err)
				}
			})
		})
		a.store, a.policy = st, model.DefaultPolicy()
		if *listen == "" {
			*listen = demoListen
		}
		log.Info("demo: made-up systems, nothing is polled, reports are refused")
	} else {
		cfg, err := Load(*configPath)
		if err != nil {
			return err
		}
		connectors, err := cfg.connectors()
		if err != nil {
			return fmt.Errorf("configuration %s: %w", *configPath, err)
		}
		if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
			return fmt.Errorf("creating the data directory: %w", err)
		}
		st, err := store.OpenSQLite(work, filepath.Join(cfg.DataDir, "upkeep.db"))
		if err != nil {
			return err
		}
		defer func() {
			stop() // first, so that nothing uses the store when it closes
			st.Close()
		}()

		a.store, a.policy = st, cfg.policy()
		mapView = cfg.mapView()
		a.agentToken, a.systemTokens = cfg.agentToken, cfg.systemTokens
		a.dashboardUser, a.dashboardPassword = cfg.Dashboard.User, cfg.dashboardPassword
		a.polled = map[string]bool{}
		for _, c := range connectors {
			a.polled[c.Source.Name()] = true
		}
		if *listen == "" {
			*listen = cfg.Listen
		}
		if cfg.agentToken == nil && len(cfg.systemTokens) == 0 {
			log.Warn("no token_file and no [tokens]: reports from agents are refused")
		}
		if cfg.Dashboard.User == "" {
			log.Info("the dashboard asks for no password: [dashboard] is not set")
		}

		if env.registry == nil {
			env.registry = registry.New(registry.Options{})
		}
		sched := &Scheduler{
			Store: st, Values: st, Connectors: connectors, Registry: env.registry,
			Policy: a.policy, Mail: cfg.Mail, Log: log,
			ConnectorInterval: time.Duration(cfg.ConnectorInterval),
			RegistryInterval:  time.Duration(cfg.RegistryInterval),
		}
		jobs = append(jobs, sched.Run)
		log.Info("configuration read", "file", *configPath, "connectors", len(connectors),
			"connector_interval", sched.ConnectorInterval.String(), "registry_interval", sched.RegistryInterval.String(),
			"mail", cfg.Mail.Enabled())
	}
	a.dashboard = web.Handler(web.Options{Store: a.store, Policy: a.policy, Now: a.now, Version: a.version, Map: mapView})

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *listen, err)
	}
	srv := &http.Server{
		Handler: a.handler(),
		// A client that is slow on purpose must not hold a connection for ever. Reports
		// are small and pages quick to make, so these are generous.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	for _, job := range jobs {
		background.Go(func() { job(work) })
	}
	log.Info("listening", "address", ln.Addr().String(), "version", version.String())
	if env.listening != nil {
		env.listening(ln.Addr())
	}

	select {
	case err := <-served:
		return fmt.Errorf("serving HTTP: %w", err)
	case <-ctx.Done():
	}
	log.Info("stopping")
	// The signal's context is done; shutting down needs one that is not.
	stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer stopCancel()
	if err := srv.Shutdown(stopCtx); err != nil {
		srv.Close()
		log.Warn("requests were cut off while stopping", "error", err)
	}
	return nil
}
