package ospkg

import (
	"context"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// pkg is FreeBSD's package manager, which OPNsense uses too.
type pkg struct{ m *machine }

func (pkg) name() string { return "pkg" }

const pkgTimeout = 2 * time.Minute

// pkgUpgrade is a dry run that does not refresh the catalogue (-U). pkg allows a dry run to
// a normal user who can read the databases (src/upgrade.c in pkg).
var pkgUpgrade = command{name: "pkg", args: []string{"upgrade", "-n", "-U"}, timeout: pkgTimeout}

// pkgAudit prints the installed packages with a known vulnerability, one "name-version" a
// line, from the list the system's daily security job downloads. It fetches nothing itself.
var pkgAudit = command{name: "pkg", args: []string{"audit", "-q"}, timeout: pkgTimeout}

func (p pkg) pending(ctx context.Context) (pending, error) {
	out, err := p.m.run(ctx, pkgUpgrade)
	if err != nil {
		return pending{}, err
	}
	got, ok := parsePkgUpgrade(out.stdout)
	// The exit code is not the same in every version of pkg when there is something to
	// upgrade, so the output decides: a run that printed neither a list nor "up to date"
	// did not answer.
	if !ok {
		return pending{}, failure(pkgUpgrade, out)
	}
	// The catalogue is "repos/<name>/db" in pkg 2 and was "repo-<name>.sqlite" in pkg 1.19.
	// pkg gives the file the time the repository published it, as apt does with its lists.
	got.listsUpdated = p.m.newestMtime("/var/db/pkg/repos/*/db", "/var/db/pkg/repo-*.sqlite")

	if len(got.items) > 0 {
		// An upgrade is a security update when the version installed now has a known
		// vulnerability. Exit code 1 means "found some"; without the list of
		// vulnerabilities pkg prints nothing on stdout and nothing gets marked.
		if out, err := p.m.run(ctx, pkgAudit); err == nil {
			vulnerable := map[string]bool{}
			for _, nameVersion := range strings.Fields(out.stdout) {
				vulnerable[nameVersion] = true
			}
			markSecurity(got.items, func(it report.PackageUpdate) bool { return vulnerable[it.Name+"-"+it.Installed] })
		}
	}
	return got, nil
}

// reboot compares the kernel on disk with the running one. The userland's version is not
// part of it: a patch that does not touch the kernel raises only the userland's patch level,
// and the two then differ for good (freebsd-version(1), "Implementation notes").
func (p pkg) reboot(ctx context.Context) (bool, string) {
	out, err := p.m.run(ctx, command{name: "freebsd-version", args: []string{"-kr"}, timeout: time.Minute})
	if err != nil || out.code != 0 {
		return false, ""
	}
	// With both options it prints the installed kernel first, then the running one.
	v := strings.Fields(out.stdout)
	if len(v) != 2 || v[0] == v[1] {
		return false, ""
	}
	return true, "kernel " + v[1] + " running, " + v[0] + " installed"
}

// Section headers of pkg's summary of jobs (src/utils.c in pkg).
const (
	pkgUpgraded = "Installed packages to be UPGRADED:"
	pkgLocked   = "Installed packages LOCKED:"
	pkgUpToDate = "Your packages are up to date."
	pkgSummary  = "package(s) will be affected"
)

// parsePkgUpgrade reads "pkg upgrade -n". The packages come in sections, a tab before each:
//
//	Installed packages to be UPGRADED:
//		curl: 8.10.1 -> 8.11.0 [OPNsense]
//
//	Installed packages LOCKED:
//		Package nginx-1.26.2 is locked and may not be upgraded to version 1.26.3
//
// The repository in brackets is only printed when more than one is configured. ok is false
// when the text is not an answer at all.
func parsePkgUpgrade(text string) (got pending, ok bool) {
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.Contains(line, pkgUpToDate), strings.Contains(line, pkgSummary):
			ok = true
		case line == "":
			section = ""
		case line[0] != '\t':
			section = line
		case section == pkgUpgraded:
			if up, valid := parsePkgUpgraded(line); valid {
				got.items = append(got.items, up)
			}
		case section == pkgLocked:
			if k, valid := parsePkgLocked(line); valid {
				got.kept = append(got.kept, k)
			}
		}
	}
	return got, ok
}

// parsePkgUpgraded reads "\tname: old -> new" with an optional " [repository]".
func parsePkgUpgraded(line string) (report.PackageUpdate, bool) {
	name, rest, ok := strings.Cut(strings.TrimSpace(line), ": ")
	if !ok {
		return report.PackageUpdate{}, false
	}
	old, new, ok := strings.Cut(rest, " -> ")
	if !ok {
		return report.PackageUpdate{}, false
	}
	new, _, _ = strings.Cut(new, " ")
	return report.PackageUpdate{Name: name, Installed: old, Candidate: new}, name != "" && new != ""
}

// parsePkgLocked reads "\tPackage name-version is locked and may not be upgraded to version X".
// Locked packages that would be reinstalled or removed are not newer versions and are left out.
func parsePkgLocked(line string) (keptPackage, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Package ")
	if !ok {
		return keptPackage{}, false
	}
	nameVersion, rest, ok := strings.Cut(rest, " is locked and may not be upgraded to version ")
	if !ok {
		return keptPackage{}, false
	}
	// A FreeBSD version has no dash, so the last one ends the name.
	dash := strings.LastIndex(nameVersion, "-")
	if dash <= 0 {
		return keptPackage{}, false
	}
	return keptPackage{name: nameVersion[:dash], installed: nameVersion[dash+1:], candidate: strings.TrimSpace(rest), why: keptHeld}, true
}
