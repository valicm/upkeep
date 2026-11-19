// Package collect defines what an agent's collectors have in common. Each collector looks at
// one thing on the machine (packages, containers, backups) and fills its part of the report.
package collect

import (
	"context"

	"github.com/valicm/upkeep/internal/report"
)

// Collector fills one part of a report. It must not touch parts that are not its own.
//
// A returned error means "I could not look at all": the runner records it in the report's
// Errors and drops whatever the collector had written by then, so that the part is empty and
// not half filled. A collector that found some things and not others returns nil and appends
// a report.Problem of its own to Errors for what it could not find out.
type Collector interface {
	Name() string
	Collect(ctx context.Context, r *report.Report) error
}
