// Package agent is "upkeep agent": it runs on a machine, asks its collectors what needs
// attention there, and sends the answer to the server as one report.
//
// It needs no privileges: it reads, runs a few commands that only look, and makes one HTTP
// request. Run it as a user of its own.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/valicm/upkeep/internal/collect"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/version"
)

// Main runs "upkeep agent" with its command-line arguments. It returns when a signal asks it
// to stop, or after one report with -once or -print.
func Main(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	return run(ctx, args, os.Getenv, os.Stdout, os.Stderr)
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("upkeep agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", DefaultConfigPath, "configuration `file`")
	once := flags.Bool("once", false, "send one report and exit; the exit status says whether the server took it")
	printOnly := flags.Bool("print", false, "write the report to standard output as JSON and send nothing")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	explicit := false
	flags.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })

	cfg, err := LoadConfig(*configPath, explicit, getenv)
	if err != nil {
		return err
	}
	name, err := systemName(cfg.Name)
	if err != nil {
		return err
	}
	// Better said now than by the server, every fifteen minutes.
	if err := (&report.Report{Schema: report.Schema, System: report.System{Name: name, Source: "agent"}}).Validate(); err != nil {
		return fmt.Errorf("this machine cannot report as %q: %w", name, err)
	}

	// No timestamps: systemd and syslog add their own.
	logger := log.New(stderr, "", 0)
	a := &agent{
		name:       name,
		collectors: collectors(cfg, name),
		timeout:    cfg.Timeout.Duration,
		grace:      grace,
		interval:   cfg.Interval.Duration,
		logf:       logger.Printf,
		now:        time.Now,
		sleep:      sleep,
		jitter:     jitter,
	}

	if *printOnly {
		r := a.build(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}

	endpoint, err := cfg.endpoint()
	if err != nil {
		return err
	}
	a.send = newSender(endpoint, cfg.TokenFile).send
	if plainHTTP(endpoint) {
		a.logf("warning: %s is not https: the token and the reports can be read on the way", endpoint)
	}

	if *once {
		return a.report(ctx, onceTries, time.Time{})
	}
	a.logf("upkeep agent %s: reporting as %q to %s every %s", version.String(), name, endpoint, a.interval)
	a.loop(ctx)
	a.logf("stopped")
	return nil
}

// agent is one running agent. The functions are fields so that tests need neither a clock
// nor a network.
type agent struct {
	name       string
	collectors []collect.Collector
	timeout    time.Duration // for each collector
	grace      time.Duration // see runCollector
	interval   time.Duration

	behind map[int]<-chan collected // collectors that did not come back, see runCollector

	send   func(ctx context.Context, body []byte) error
	logf   func(format string, args ...any)
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) bool // false when ctx ended first
	jitter func(d time.Duration) time.Duration
}

// loop reports until ctx ends. A report that cannot be delivered is retried until the next one
// is due; then it is dropped, because the next one says everything it said, only newer.
func (a *agent) loop(ctx context.Context) {
	for ctx.Err() == nil {
		next := a.now().Add(a.jitter(a.interval))
		if err := a.report(ctx, 0, next); err != nil && ctx.Err() == nil {
			a.logf("report not delivered: %v", err)
		}
		if !a.sleep(ctx, next.Sub(a.now())) {
			return
		}
	}
}

// report builds one report and delivers it.
func (a *agent) report(ctx context.Context, tries int, deadline time.Time) error {
	r := a.build(ctx)
	if ctx.Err() != nil {
		return ctx.Err() // stopping: collectors were cut off, the report would be half empty
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("the report is not fit to send: %w", err)
	}
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("encode the report: %w", err)
	}
	if err := a.deliver(ctx, body, tries, deadline); err != nil {
		return err
	}
	a.logf("report sent: %s", summary(r))
	return nil
}

// summary is the one line the log gets for a delivered report.
func summary(r *report.Report) string {
	var parts []string
	if p := r.Packages; p != nil {
		s := count(p.Pending, "package update")
		if p.Security > 0 {
			s += fmt.Sprintf(" (%d security)", p.Security)
		}
		if p.RebootRequired {
			s += ", reboot required"
		}
		parts = append(parts, s)
	}
	for _, c := range []struct {
		n     int
		thing string
	}{
		{len(r.Containers), "container"}, {len(r.Backups), "backup"}, {len(r.Software), "software item"}, {len(r.Errors), "problem"},
	} {
		if c.n > 0 {
			parts = append(parts, count(c.n, c.thing))
		}
	}
	if len(parts) == 0 {
		return "nothing to say"
	}
	return strings.Join(parts, ", ")
}

// count says "1 thing" or "3 things".
func count(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

// systemName is the name this machine reports as: the configured one, or the host name
// without its domain, as "server" is what people call server.example.net.
func systemName(configured string) (string, error) {
	if name := strings.TrimSpace(configured); name != "" {
		return name, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("find this machine's name (set \"name\" in the configuration or UPKEEP_NAME): %w", err)
	}
	short, _, _ := strings.Cut(hostname, ".")
	if short == "" {
		return "", errors.New("this machine has no host name: set \"name\" in the configuration or UPKEEP_NAME")
	}
	return short, nil
}

// plainHTTP is true for an http address that is not this machine itself.
func plainHTTP(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

// sleep waits for d or until ctx ends, and says which: true for the full wait.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// jitter moves d by up to a tenth either way, so that agents started together (after a power
// cut, say) do not all report in the same second for ever.
func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.9 + 0.2*rand.Float64()))
}
