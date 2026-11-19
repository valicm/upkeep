// Package model holds what the server knows and derives: the latest report per system, what the
// registries say about the images in use, and the list of things that need attention.
package model

import (
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// SystemState is the latest report of one system and when it arrived.
type SystemState struct {
	Report     report.Report
	ReceivedAt time.Time
}

// ImageCheck is what a registry says about one image reference in use somewhere.
type ImageCheck struct {
	Image      string // exactly as reported: "docker.io/gitea/gitea:1.23.6"
	Tag        string // "1.23.6"
	TagDigest  string // what the tag points at in the registry now; differs from a container's digest when the tag was rebuilt
	NewerPatch string // newest tag that only raises the patch level: "1.23.8"
	NewerMinor string // newest tag within the same major: "1.25.2"
	NewerMajor string // newest tag of a higher major: "2.0.1"
	CheckedAt  time.Time
	Error      string // why the registry could not be asked; the other fields are then stale or empty
	// Note is a remark on a check that worked: the registry has more tags than were read, so
	// a newer one may be missing. It is not a failure and the other fields are what the
	// registry said.
	Note string
}

// Category groups findings on the dashboard.
type Category string

const (
	CategoryOS        Category = "os"        // packages of the operating system
	CategoryReboot    Category = "reboot"    // a reboot is waiting
	CategoryContainer Category = "container" // a container image has something newer
	CategorySoftware  Category = "software"  // firmware, Home Assistant and its apps, plugins
	CategoryBackup    Category = "backup"    // a backup failed, is stale or never ran
	CategorySource    Category = "source"    // the agent or connector itself: silent, or a collector failed
)

// Severity orders findings.
type Severity int

const (
	Info Severity = iota // worth knowing: an update exists
	Warn                 // should be done: security updates, a reboot waiting for days, a stale backup
	Crit                 // broken: a backup that failed, a system that stopped reporting
)

// String never fails: a severity outside the scale, from a newer build's data, reads as the
// nearest one on it.
func (s Severity) String() string {
	return [...]string{"info", "warn", "crit"}[min(max(s, Info), Crit)]
}

// Finding is one thing that needs attention on one system.
type Finding struct {
	System   string
	Category Category
	Severity Severity
	Title    string // "12 package updates, 3 of them security"
	Detail   string // one line more: package names, versions, since when
}

// Policy sets the thresholds Findings uses.
type Policy struct {
	SilentAfter   time.Duration // a source that has not reported for this long is a finding
	BackupMaxAge  time.Duration // a backup whose last success is older is stale, unless the backup says otherwise
	RebootWarnAge time.Duration // reserved: how long a reboot may wait before it is a warning
}

// DefaultPolicy is what a server uses unless its configuration says otherwise.
func DefaultPolicy() Policy {
	return Policy{SilentAfter: 2 * time.Hour, BackupMaxAge: 26 * time.Hour, RebootWarnAge: 72 * time.Hour}
}
