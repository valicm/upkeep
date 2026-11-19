// Package connect defines a source that is asked instead of reporting by itself: an appliance
// with an API. The server polls such sources; an agent can run one locally as a collector.
package connect

import (
	"context"
	"errors"

	"github.com/valicm/upkeep/internal/collect"
	"github.com/valicm/upkeep/internal/report"
)

// Source fetches a complete report about one system through that system's API.
type Source interface {
	Name() string // the system's name, as in report.System.Name
	Fetch(ctx context.Context) (*report.Report, error)
}

// AsCollector lets an agent use a Source: what the source finds is merged into the agent's
// report, and the agent's own system identity stays. It is for a source this machine can
// reach better than the server can.
func AsCollector(s Source) collect.Collector { return sourceCollector{s: s} }

// AsSelf is AsCollector for an agent that runs on the appliance itself: an app inside Home
// Assistant, an agent on the firewall. There the host only knows a container's or a kernel's
// name, and the appliance knows what it is: its kind, the name of its operating system and
// its version are taken from the source. The system's name, the running kernel and the
// architecture stay the agent's.
func AsSelf(s Source) collect.Collector { return sourceCollector{s: s, self: true} }

type sourceCollector struct {
	s    Source
	self bool
}

func (c sourceCollector) Name() string { return c.s.Name() }

func (c sourceCollector) Collect(ctx context.Context, r *report.Report) error {
	got, err := c.s.Fetch(ctx)
	if err != nil {
		return err
	}
	if got == nil {
		return errors.New("the source returned nothing")
	}
	if c.self {
		if got.System.Kind != "" {
			r.System.Kind = got.System.Kind
		}
		if got.System.OS != "" {
			r.System.OS, r.System.OSVersion = got.System.OS, got.System.OSVersion
		}
		if r.System.Kernel == "" {
			r.System.Kernel = got.System.Kernel
		}
	}
	if got.Packages != nil && r.Packages == nil {
		r.Packages = got.Packages
	}
	r.Software = append(r.Software, got.Software...)
	r.Containers = append(r.Containers, got.Containers...)
	r.Backups = append(r.Backups, got.Backups...)
	r.Errors = append(r.Errors, got.Errors...)
	return nil
}
