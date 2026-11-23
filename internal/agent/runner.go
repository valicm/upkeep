package agent

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/valicm/upkeep/internal/collect"
	"github.com/valicm/upkeep/internal/collect/backup"
	"github.com/valicm/upkeep/internal/collect/containers"
	"github.com/valicm/upkeep/internal/collect/host"
	"github.com/valicm/upkeep/internal/collect/network"
	"github.com/valicm/upkeep/internal/collect/ospkg"
	"github.com/valicm/upkeep/internal/connect"
	"github.com/valicm/upkeep/internal/connect/homeassistant"
	"github.com/valicm/upkeep/internal/connect/opnsense"
	"github.com/valicm/upkeep/internal/report"
)

// grace is how long a collector whose time is up gets to come back on its own, so that the
// report can carry its own words about what it was doing. After that it is left behind.
const grace = 3 * time.Second

// collectors returns what this configuration asks to run, in order, for the system called
// name. The host comes first: it says what the machine is. The package manager comes before
// the local sources, so that its answer about packages is the one that counts when a source
// has one too.
func collectors(cfg Config, name string) []collect.Collector {
	list := []collect.Collector{
		host.New(host.Config{}),
		network.New(cfg.Network, cfg.Server),
		ospkg.New(cfg.Packages),
		containers.New(cfg.Containers),
		backup.New(cfg.Backups),
	}
	if cfg.HomeAssistant != nil {
		c := *cfg.HomeAssistant
		if c.Name == "" {
			c.Name = name // the source wants one, and here it describes this very system
		}
		src, err := homeassistant.New(c)
		// An app inside Home Assistant is Home Assistant, as far as the dashboard goes: the
		// container it runs in is nobody's business.
		list = append(list, local("homeassistant", src, err, c.Supervisor))
	}
	if cfg.OPNsense != nil {
		c := *cfg.OPNsense
		if c.Name == "" {
			c.Name = name
		}
		src, err := opnsense.New(c)
		// Asked from a FreeBSD machine, the firewall is that machine.
		list = append(list, local("opnsense", src, err, runtime.GOOS == "freebsd"))
	}
	return list
}

// local makes a collector of a source the server would otherwise poll. It is named after its
// table, not after the system the source describes: here that system is this machine. With
// self, the agent runs on the appliance itself and the source also says what kind of system
// this is (connect.AsSelf). A source that could not be set up still becomes a collector, one
// that fails with the reason: a mistake in one table must show on the dashboard, not stop the
// rest from reporting.
func local(table string, src connect.Source, err error, self bool) collect.Collector {
	switch {
	case err != nil:
		return named{table, failing{fmt.Errorf("set up from the [%s] table: %w", table, err)}}
	case self:
		return named{table, connect.AsSelf(src)}
	}
	return named{table, connect.AsCollector(src)}
}

type named struct {
	name string
	collect.Collector
}

func (n named) Name() string { return n.name }

type failing struct{ err error }

func (failing) Name() string                                    { return "" }
func (f failing) Collect(context.Context, *report.Report) error { return f.err }

// build runs every collector and returns the report. It always returns one: a collector that
// fails, panics or does not come back becomes a Problem in it, and the others still count.
func (a *agent) build(ctx context.Context) *report.Report {
	r := &report.Report{
		Schema: report.Schema,
		System: report.System{Name: a.name, Source: "agent"},
		Sent:   a.now().UTC(),
	}
	for i, c := range a.collectors {
		if ctx.Err() != nil {
			break // the agent is stopping; the report will not be sent
		}
		part, err := a.runCollector(ctx, i, c, r.System)
		if err != nil {
			if ctx.Err() != nil {
				break // cut off because the agent is stopping, which is no problem of the collector
			}
			a.logf("collector %s: %v", c.Name(), err)
			r.Errors = append(r.Errors, report.Problem{Collector: c.Name(), Message: err.Error()})
			continue
		}
		for _, p := range part.Errors {
			a.logf("collector %s: %s", p.Collector, p.Message)
		}
		merge(r, part)
		// Who this report is about is the agent's to say, whatever a collector wrote.
		r.System.Name, r.System.Source = a.name, "agent"
	}
	return r
}

// collected is what one run of a collector came back with.
type collected struct {
	part *report.Report
	err  error
}

// runCollector runs one collector on a report of its own and returns that report.
//
// A report of its own, because a collector that ignores its deadline keeps writing after the
// agent has moved on; it must not write into what is being sent. And because of it, a
// collector that fails leaves nothing behind: an error means "I could not look", so the part
// stays empty instead of half filled. A collector that found some things and not others
// returns no error and adds its own Problem.
//
// i is the collector's place in a.collectors. A collector that was left behind is not started
// again until it has come back, so one that hangs for good costs one goroutine, not one more
// with every report.
func (a *agent) runCollector(ctx context.Context, i int, c collect.Collector, sys report.System) (*report.Report, error) {
	if old, busy := a.behind[i]; busy {
		select {
		case <-old:
			delete(a.behind, i)
		default:
			return nil, errors.New("is still busy with an earlier report and was not started again")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	done := make(chan collected, 1)
	go func() {
		part := &report.Report{Schema: report.Schema, System: sys}
		defer func() {
			if p := recover(); p != nil {
				// The stack goes to the log, for whoever has to fix it; the report gets one line.
				a.logf("collector %s panicked: %v\n%s", c.Name(), p, debug.Stack())
				done <- collected{nil, fmt.Errorf("panic: %v", p)}
			}
		}()
		err := c.Collect(ctx, part)
		done <- collected{part, err}
	}()

	var res collected
	select {
	case res = <-done:
	case <-ctx.Done():
		select {
		case res = <-done:
		case <-time.After(a.grace):
			if a.behind == nil {
				a.behind = map[int]<-chan collected{}
			}
			a.behind[i] = done
			return nil, fmt.Errorf("gave no answer within %s and was left behind", a.timeout)
		}
	}
	if res.err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("stopped after %s: %w", a.timeout, res.err)
		}
		return nil, res.err
	}
	return res.part, nil
}

// merge adds what one collector found to the report.
func merge(r, part *report.Report) {
	r.System = part.System
	if r.Packages == nil {
		r.Packages = part.Packages
	}
	r.Software = append(r.Software, part.Software...)
	r.Containers = append(r.Containers, part.Containers...)
	r.Backups = append(r.Backups, part.Backups...)
	r.Errors = append(r.Errors, part.Errors...)
}
