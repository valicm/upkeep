// Package ospkg reports the state of the operating system's package manager: what an upgrade
// would bring to a newer version, which of that is a security update, whether a reboot is
// waiting, and how old the package lists are.
//
// It needs no root and never refreshes the lists: the host's own timer does that, and the
// date of the lists is part of the report so that a timer which stopped shows up.
package ospkg

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/collect"
	"github.com/valicm/upkeep/internal/collect/host"
	"github.com/valicm/upkeep/internal/report"
)

// Config is this collector's part of the agent's configuration file, the [packages] table.
type Config struct {
	// Enabled is true unless the file says otherwise: a machine whose packages are nobody's
	// business, such as an appliance that updates itself, sets enabled = false.
	Enabled *bool `toml:"enabled"`
	// Manager names the package manager when the guess is wrong: "apt", "dnf", "apk" or "pkg".
	Manager string `toml:"manager"`
}

// manager is one package manager. Everything it does only reads.
type manager interface {
	name() string
	// pending asks what an upgrade would do. An error means the question got no answer.
	pending(ctx context.Context) (pending, error)
	// reboot says whether the package manager's own records ask for a reboot, and why.
	reboot(ctx context.Context) (need bool, why string)
}

// pending is what one package manager answered.
type pending struct {
	items []report.PackageUpdate // what an upgrade would bring to a newer version
	// kept have a newer version too, but an upgrade would leave them alone. They are not
	// counted as pending: nothing happens to them until somebody decides otherwise.
	kept         []keptPackage
	listsUpdated time.Time
	doubts       []string // why the numbers may be wrong although the manager answered
}

// keptPackage is a package with a newer version that an upgrade would not install.
type keptPackage struct {
	name, installed, candidate string
	why                        string // keptHeld, keptPhased or keptBack
}

const (
	keptHeld   = "held"      // the administrator put it on hold
	keptPhased = "phased"    // the distribution has not offered it to this machine yet
	keptBack   = "kept back" // its dependencies cannot be met
)

type collector struct {
	cfg Config
	m   *machine
}

// New returns the collector.
func New(cfg Config) collect.Collector {
	return &collector{cfg: cfg, m: &machine{goos: runtime.GOOS, goarch: runtime.GOARCH, run: runCommand, have: haveCommand, uname: host.Uname}}
}

func (*collector) Name() string { return "ospkg" }

// Collect fills r.Packages. A machine without a package manager it knows is an error, which
// the agent reports as a problem: the report then says "nobody looked", not "nothing pending".
func (c *collector) Collect(ctx context.Context, r *report.Report) error {
	if c.cfg.Enabled != nil && !*c.cfg.Enabled {
		return nil
	}
	mgr, err := c.manager()
	if err != nil {
		return err
	}
	got, err := mgr.pending(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", mgr.name(), err)
	}

	p := &report.Packages{Manager: mgr.name(), Pending: len(got.items)}
	if !got.listsUpdated.IsZero() {
		p.ListsUpdated = got.listsUpdated.UTC()
	}
	// Security updates first, so that they survive the cap and lead the list.
	sort.SliceStable(got.items, func(i, j int) bool {
		a, b := got.items[i], got.items[j]
		if a.Security != b.Security {
			return a.Security
		}
		return a.Name < b.Name
	})
	for _, it := range got.items {
		if it.Security {
			p.Security++
		}
	}
	p.Items = got.items
	if len(p.Items) > report.MaxItems {
		p.Items = p.Items[:report.MaxItems]
	}

	// What an upgrade would leave alone, with the reason. A held package gets no security
	// update either, so it must not go unseen; it is still not pending.
	sort.SliceStable(got.kept, func(i, j int) bool { return got.kept[i].name < got.kept[j].name })
	for _, k := range got.kept {
		if len(p.KeptBack) == report.MaxItems {
			break
		}
		p.KeptBack = append(p.KeptBack, report.PackageUpdate{Name: k.name, Installed: k.installed, Candidate: k.candidate, Reason: k.why})
	}

	p.RebootRequired, p.RebootReason = mgr.reboot(ctx)
	if c.m.goos == "linux" {
		// A package manager's flag names the package; when it names nothing, or does not
		// exist on this distribution, the kernels on disk still tell.
		running := host.Kernel(ctx, c.m.root, c.m.goos, c.m.uname)
		if newer := newerKernel(c.m.root, running); newer != "" && p.RebootReason == "" {
			p.RebootRequired = true
			p.RebootReason = "kernel " + running + " running, " + newer + " installed"
		}
	}
	if p.RebootRequired && p.RebootReason == "" {
		p.RebootReason = "asked for by an installed package"
	}

	r.Packages = p
	for _, d := range got.doubts {
		r.Errors = append(r.Errors, report.Problem{Collector: c.Name(), Message: mgr.name() + ": " + d})
	}
	return nil
}

// manager picks the package manager: the configured one, else the one the operating system
// is known for, else the first whose database and command both exist. The operating system
// goes first because a second manager can be installed as a mere tool: Fedora packages apt.
func (c *collector) manager() (manager, error) {
	all := []struct {
		name    string
		command string
		ids     []string // values of ID and ID_LIKE in os-release that mean this manager
		db      []string // one of these exists where the manager is really in use
		make    func() manager
	}{
		{"apt", "apt-get", []string{"debian", "ubuntu", "raspbian"}, []string{"/var/lib/dpkg/status"}, func() manager { return apt{c.m} }},
		{"dnf", "dnf", []string{"fedora", "rhel", "centos"}, []string{"/usr/lib/sysimage/rpm", "/var/lib/rpm"}, func() manager { return dnf{c.m} }},
		{"apk", "apk", []string{"alpine"}, []string{"/lib/apk/db/installed", "/usr/lib/apk/db/installed"}, func() manager { return apk{c.m} }},
		{"pkg", "pkg", []string{"freebsd"}, []string{"/var/db/pkg/local.sqlite"}, func() manager { return pkg{c.m} }},
	}

	if want := strings.ToLower(strings.TrimSpace(c.cfg.Manager)); want != "" {
		for _, m := range all {
			if m.name == want {
				if !c.m.have(m.command) {
					return nil, fmt.Errorf("the configured package manager %q is not installed: no %s command", want, m.command)
				}
				return m.make(), nil
			}
		}
		return nil, fmt.Errorf("unknown package manager %q in the configuration: use apt, dnf, apk or pkg", c.cfg.Manager)
	}

	rel := host.ReadOSRelease(c.m.root)
	ids := append([]string{rel["ID"]}, strings.Fields(rel["ID_LIKE"])...)
	if c.m.goos == "freebsd" {
		ids = append(ids, "freebsd") // OPNsense and old FreeBSD have no os-release
	}
	for _, m := range all {
		for _, id := range ids {
			if contains(m.ids, id) && c.m.have(m.command) {
				return m.make(), nil
			}
		}
	}
	for _, m := range all {
		for _, db := range m.db {
			if c.m.exists(db) && c.m.have(m.command) {
				return m.make(), nil
			}
		}
	}
	return nil, errors.New("no package manager found: looked for apt-get, dnf, apk and pkg")
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s && s != "" {
			return true
		}
	}
	return false
}

// markSecurity sets Security on the items a second source names as security updates.
func markSecurity(items []report.PackageUpdate, isSecurity func(report.PackageUpdate) bool) {
	for i := range items {
		if isSecurity(items[i]) {
			items[i].Security = true
		}
	}
}
