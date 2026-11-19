// Package backup reports whether this machine's backups ran. It does not run or inspect a
// backup itself; it reads the evidence one leaves behind: the state of the systemd unit that
// runs it, the newest file in the place an appliance drops its backups, or the newest snapshot
// in a restic repository.
package backup

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"

	"github.com/valicm/upkeep/internal/collect"
	"github.com/valicm/upkeep/internal/report"
)

// Config is this collector's part of the agent's configuration file:
//
//	[backups]
//	enabled = false                    # default true
//
//	[[backups.systemd]]                # a unit that runs the backup
//	name = "restic-backup"             # default: the unit's name
//	unit = "restic-backup.service"
//	max_age_hours = 26                 # default 0: the server's own limit
//
//	[[backups.file]]                   # a place where backup files appear
//	name = "opnsense config"
//	path = "/srv/backups/opnsense/config-*.xml"   # a file, a directory or a pattern
//
//	[[backups.restic]]                 # a restic repository
//	name = "restic repository"
//	env_file = "/etc/restic/backup.env"            # RESTIC_REPOSITORY=..., RESTIC_PASSWORD=...
//	# or: repository_file (or repository) and password_file
//	host = "server"                    # only this host's snapshots
//	tag = "nightly"                    # only snapshots with this tag
//
// With no job configured, a unit named restic-backup.service is reported when the machine has
// one.
type Config struct {
	Enabled *bool `toml:"enabled"`
	// StateDir is where the collector remembers what it saw. Left empty, systemd's
	// $STATE_DIRECTORY is used (the agent's unit sets StateDirectory=upkeep), and without that
	// the memory lasts only as long as the process.
	StateDir string       `toml:"state_dir"`
	Systemd  []SystemdJob `toml:"systemd"`
	File     []FileJob    `toml:"file"`
	Restic   []ResticJob  `toml:"restic"`
}

// SystemdJob is a backup run by a systemd service, usually started by a timer.
type SystemdJob struct {
	Name        string `toml:"name"`
	Unit        string `toml:"unit"`
	MaxAgeHours int    `toml:"max_age_hours"`
}

// FileJob is a backup that shows as files: the newest one that matches counts.
type FileJob struct {
	Name        string `toml:"name"`
	Path        string `toml:"path"`
	MaxAgeHours int    `toml:"max_age_hours"`
}

// ResticJob is a restic repository: the newest snapshot counts.
type ResticJob struct {
	Name string `toml:"name"`
	// EnvFile holds the variables restic reads (RESTIC_REPOSITORY, RESTIC_PASSWORD, ...), in
	// the form of a systemd EnvironmentFile: the same file the backup's own unit uses.
	EnvFile string `toml:"env_file"`
	// Repository is the repository's address. One that carries a password belongs in
	// RepositoryFile or EnvFile instead: the agent's configuration is not a place for secrets.
	Repository     string `toml:"repository"`
	RepositoryFile string `toml:"repository_file"`
	PasswordFile   string `toml:"password_file"`
	Host           string `toml:"host"`
	Tag            string `toml:"tag"`
	MaxAgeHours    int    `toml:"max_age_hours"`
}

// defaultUnit is what the homelab's backup is called, and a common name for one elsewhere.
const defaultUnit = "restic-backup.service"

type collector struct {
	enabled  bool
	stateDir string
	systemd  []SystemdJob
	file     []FileJob
	restic   []ResticJob
	invalid  []error // what is wrong with the configuration, said again at every run

	run    runner // runs systemctl and restic
	memory state  // stands in for the state file when there is no state directory
}

// New returns the collector.
func New(cfg Config) collect.Collector {
	c := &collector{
		enabled:  cfg.Enabled == nil || *cfg.Enabled,
		stateDir: cfg.StateDir,
		run:      execute,
	}
	if c.stateDir == "" {
		// systemd names the unit's StateDirectory= here; several are separated by colons.
		c.stateDir, _, _ = strings.Cut(os.Getenv("STATE_DIRECTORY"), ":")
	}

	names := map[string]bool{}
	accept := func(name string, maxAge int, problem string) bool {
		if problem == "" && maxAge < 0 {
			problem = "max_age_hours must not be negative"
		}
		if problem == "" && names[name] {
			problem = "another backup has the same name"
		}
		if problem != "" {
			c.invalid = append(c.invalid, fmt.Errorf("backup %q in the configuration is left out: %s", name, problem))
			return false
		}
		names[name] = true
		return true
	}
	for _, j := range cfg.Systemd {
		var problem string
		j.Unit, problem = serviceName(j.Unit)
		if j.Name == "" {
			j.Name = strings.TrimSuffix(j.Unit, ".service")
		}
		if accept(j.Name, j.MaxAgeHours, problem) {
			c.systemd = append(c.systemd, j)
		}
	}
	for _, j := range cfg.File {
		var problem string
		if j.Path == "" {
			problem = "it has no path"
		}
		if j.Name == "" {
			j.Name = j.Path
		}
		if accept(j.Name, j.MaxAgeHours, problem) {
			c.file = append(c.file, j)
		}
	}
	for _, j := range cfg.Restic {
		if j.Name == "" {
			j.Name = "restic"
		}
		if accept(j.Name, j.MaxAgeHours, j.problem()) {
			c.restic = append(c.restic, j)
		}
	}
	return c
}

func (c *collector) Name() string { return "backup" }

// Collect looks at every configured backup. One that cannot be looked at is still reported,
// with what is remembered of it, so that it does not vanish from the dashboard; the reason
// goes into the report's Errors.
func (c *collector) Collect(ctx context.Context, r *report.Report) error {
	if !c.enabled {
		return nil
	}
	errs := append([]error(nil), c.invalid...)
	before, err := c.loadState()
	if err != nil {
		errs = append(errs, err) // carry on without a memory, and write a fresh one
	}
	// Nothing is ever dropped from the memory: a backup that is missing from one run (systemd
	// did not answer, the configuration was being edited) must not lose its last success.
	after := state{Jobs: map[string]jobState{}}
	maps.Copy(after.Jobs, before.Jobs)

	var found []report.Backup
	for _, j := range c.systemd {
		key := "systemd:" + j.Unit
		u, err := c.showUnit(ctx, j.Unit)
		why := "systemd could not be asked about " + j.Unit
		if err == nil && u.load != "loaded" {
			why = fmt.Sprintf("systemd has no usable unit %s (it is %s)", j.Unit, u.load)
			err = errors.New(why)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("backup %s: %w", j.Name, err))
			found = append(found, unasked(j, before.Jobs[key], why))
			continue
		}
		b, remember := judge(j, u, before.Jobs[key])
		after.keep(key, remember)
		found = append(found, b)
	}
	if len(c.systemd)+len(c.file)+len(c.restic)+len(c.invalid) == 0 {
		// Nothing was asked for: report the unit most machines call their backup, if this
		// one has it. No such unit, or no systemd at all, is not an error.
		j := SystemdJob{Name: strings.TrimSuffix(defaultUnit, ".service"), Unit: defaultUnit}
		key := "systemd:" + defaultUnit
		known, reported := before.Jobs[key]
		u, err := c.showUnit(ctx, defaultUnit)
		switch {
		case err != nil && reported:
			// It was there the last time. One question systemd did not answer must not make
			// the backup vanish from the dashboard without a word.
			errs = append(errs, fmt.Errorf("backup %s: %w", j.Name, err))
			found = append(found, unasked(j, known, "systemd could not be asked about "+j.Unit))
		case err != nil:
		case u.load != "loaded":
			delete(after.Jobs, key) // the unit was removed
		default:
			b, remember := judge(j, u, known)
			after.keep(key, remember)
			found = append(found, b)
		}
	}
	for _, j := range c.file {
		b, err := fileBackup(j)
		if err != nil {
			errs = append(errs, err)
		}
		found = append(found, b)
	}
	for _, j := range c.restic {
		key := "restic:" + j.Name
		b, remember, err := c.resticBackup(ctx, j, before.Jobs[key])
		if err != nil {
			errs = append(errs, err)
		}
		after.keep(key, remember)
		found = append(found, b)
	}

	if err := c.saveState(before, after); err != nil {
		errs = append(errs, err)
	}
	r.Backups = append(r.Backups, found...)

	// The agent drops everything a collector found when the collector returns an error, so an
	// error is only for a run that has nothing to report. What went wrong beside the backups
	// that are reported goes into the report with them.
	if len(found) == 0 {
		return oneError(errs)
	}
	for _, err := range errs {
		r.Errors = append(r.Errors, report.Problem{Collector: c.Name(), Message: err.Error()})
	}
	return nil
}

// oneError makes one error of several, on one line: it becomes one line on the dashboard.
func oneError(errs []error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	}
	said := make([]string, len(errs))
	for i, err := range errs {
		said[i] = err.Error()
	}
	return errors.New(strings.Join(said, "; "))
}

// size says a number of bytes the way restic and ls -h do: "41 GiB", "1.4 MiB".
func size(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value, suffix := float64(n), ""
	for _, s := range []string{"KiB", "MiB", "GiB", "TiB", "PiB"} {
		value, suffix = value/unit, s
		if value < unit {
			break
		}
	}
	if value < 10 {
		return fmt.Sprintf("%.1f %s", value, suffix)
	}
	return fmt.Sprintf("%.0f %s", value, suffix)
}
