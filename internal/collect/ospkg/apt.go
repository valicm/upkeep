package ospkg

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// apt is Debian's package manager, also on Ubuntu and Raspberry Pi OS.
//
// What is pending comes from a simulated full upgrade ("apt-get -s dist-upgrade"), not from
// "apt list --upgradable". Both were run on the same machines (testdata/README):
//   - the list prints a held package and a phased update like any other one, although no
//     upgrade would install them; the simulation names them apart;
//   - the simulation says where each new version comes from, which is how a security update
//     is told from the rest; the list only names the suite;
//   - apt warns that the output of "apt" is not stable for scripts, apt-get's is;
//   - a plain "upgrade" instead of "dist-upgrade" keeps a new kernel back, because that needs
//     a new package: the one update that matters most would be missing.
type apt struct{ m *machine }

func (apt) name() string { return "apt" }

const (
	// Without root apt cannot keep its cache and builds it in memory on every run. On a
	// Raspberry Pi with a slow card that takes a while.
	aptSimulateTimeout = 2 * time.Minute
	aptMarkTimeout     = 30 * time.Second
)

// aptSimulate is the simulation. NoLocking: a simulation takes no lock as a normal user, and
// must not take one as root either, or it fails whenever the host's own apt is running.
var aptSimulate = command{
	name: "apt-get",
	args: []string{
		"-s", "-V",
		"-o", "Debug::NoLocking=true",
		"-o", "APT::Get::Show-User-Simulation-Note=false",
		"dist-upgrade",
	},
	timeout: aptSimulateTimeout,
}

func (a apt) pending(ctx context.Context) (pending, error) {
	out, err := a.m.run(ctx, aptSimulate)
	if err != nil {
		return pending{}, err
	}
	if out.code != 0 {
		return pending{}, failure(aptSimulate, out)
	}
	sim, err := parseAptSimulation(out.stdout)
	if err != nil {
		return pending{}, fmt.Errorf("read the output of %s: %w", aptSimulate, err)
	}

	got := pending{items: sim.upgrades, kept: sim.kept}
	if sim.upgraded != len(sim.upgrades) {
		got.doubts = append(got.doubts, fmt.Sprintf(
			"apt-get counts %d upgrades but %d were read from its output: its format may have changed",
			sim.upgraded, len(sim.upgrades)))
	}
	if hasKept(got.kept, keptBack) {
		a.markHeld(ctx, got.kept)
	}

	got.listsUpdated = a.listsUpdated()
	if got.listsUpdated.IsZero() {
		got.doubts = append(got.doubts,
			"there are no package lists in /var/lib/apt/lists, so no update can be seen: \"apt-get update\" has to run on this machine")
	}
	return got, nil
}

// markHeld tells a package the administrator holds from one that is kept back for another
// reason, usually dependencies that cannot be met. If the question fails they all stay "kept
// back", which is still true.
func (a apt) markHeld(ctx context.Context, kept []keptPackage) {
	out, err := a.m.run(ctx, command{name: "apt-mark", args: []string{"showhold"}, timeout: aptMarkTimeout})
	if err != nil || out.code != 0 {
		return
	}
	held := map[string]bool{}
	for _, name := range strings.Fields(out.stdout) {
		held[name] = true
	}
	for i := range kept {
		if kept[i].why == keptBack && held[kept[i].name] {
			kept[i].why = keptHeld
		}
	}
}

func hasKept(kept []keptPackage, why string) bool {
	for _, k := range kept {
		if k.why == why {
			return true
		}
	}
	return false
}

// listsUpdated is the newest proof that a refresh of the package lists worked.
//
// apt keeps no record of that. The candidates were tried (testdata/README): the directory
// lists/partial and apt's own periodic stamp both move when a refresh fails for lack of
// network, so they would call stale lists fresh. A Release file is only stored when it was
// fetched and verified, and it carries the time the repository published it; that lags the
// refresh itself by some hours on Debian, whose archives are published several times a day.
// update-success-stamp is exact, but only exists where update-notifier-common is installed.
func (a apt) listsUpdated() time.Time {
	t := a.m.newestMtime(
		"/var/lib/apt/lists/*_InRelease",
		"/var/lib/apt/lists/*_Release",
		"/var/lib/apt/periodic/update-success-stamp",
	)
	if t.IsZero() {
		// A bare directory of packages, used as a repository, has no Release file at all.
		t = a.m.newestMtime("/var/lib/apt/lists/*_Packages*")
	}
	return t
}

// reboot reads the flag a package sets when it needs a reboot, and the list of packages that
// set it. On Debian that is the kernel, through a hook of unattended-upgrades; Ubuntu adds
// libc, systemd and others.
func (a apt) reboot(context.Context) (bool, string) {
	for _, dir := range []string{"/run", "/var/run"} {
		if !a.m.exists(dir + "/reboot-required") {
			continue
		}
		b, _ := os.ReadFile(a.m.path(dir + "/reboot-required.pkgs"))
		return true, joinNames(strings.Fields(string(b)))
	}
	return false, ""
}

// joinNames lists names once each, and only the first few of a long list.
func joinNames(names []string) string {
	const most = 5
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) > most {
		return strings.Join(out[:most], ", ") + fmt.Sprintf(" and %d more", len(out)-most)
	}
	return strings.Join(out, ", ")
}

// aptSimulation is what "apt-get -s dist-upgrade" printed.
type aptSimulation struct {
	upgrades []report.PackageUpdate // installed packages that get a newer version
	kept     []keptPackage          // held, kept back or phased: a newer version nobody installs
	upgraded int                    // the count in apt's own summary line
}

// Headers of the sections apt-get prints before the list of actions (apt-private/private-output.cc).
const (
	aptKeptBack   = "The following packages have been kept back:"
	aptPhased     = "The following upgrades have been deferred due to phasing:"
	aptDowngraded = "The following packages will be DOWNGRADED:"
)

// parseAptSimulation reads the simulation. Two parts matter. The "Inst" lines are the actions,
// one per package, with the installed version in brackets when there is one and the new
// version with its origins in parentheses:
//
//	Inst libssl3t64 [3.5.1-1] (3.5.7-1~deb13u3 Debian-Security:13/stable-security [amd64])
//
// The sections above them list what is left alone. With -V they give versions,
// "   tzdata (2025b-4 => 2026f-0+deb13u1)"; without, just names, several on a line.
func parseAptSimulation(text string) (aptSimulation, error) {
	var sim aptSimulation
	sections := map[string][]keptPackage{}
	section, summary := "", false

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "":
			section = ""
		case line[0] == ' ':
			if section != "" {
				sections[section] = append(sections[section], parseAptListed(line)...)
			}
		case strings.HasPrefix(line, "Inst "):
			section = ""
			if up, ok := parseAptInst(line); ok && up.Installed != "" {
				sim.upgrades = append(sim.upgrades, up)
			}
		case strings.HasSuffix(line, ":"):
			section = line
		default:
			section = ""
			if n, ok := parseAptSummary(line); ok {
				sim.upgraded, summary = n, true
			}
		}
	}
	if !summary {
		return sim, fmt.Errorf("no summary line (\"N upgraded, ...\") in %d bytes of output", len(text))
	}

	// A downgrade is an action on an installed package too, but not a newer version.
	down := map[string]bool{}
	for _, d := range sections[aptDowngraded] {
		down[d.name] = true
	}
	if len(down) > 0 {
		kept := sim.upgrades[:0]
		for _, up := range sim.upgrades {
			if !down[up.Name] {
				kept = append(kept, up)
			}
		}
		sim.upgrades = kept
	}

	for _, k := range sections[aptKeptBack] {
		k.why = keptBack
		sim.kept = append(sim.kept, k)
	}
	for _, k := range sections[aptPhased] {
		k.why = keptPhased
		sim.kept = append(sim.kept, k)
	}
	return sim, nil
}

// parseAptInst reads one "Inst" line. Installed is empty for a package that is new.
func parseAptInst(line string) (report.PackageUpdate, bool) {
	var up report.PackageUpdate
	rest, ok := strings.CutPrefix(line, "Inst ")
	if !ok {
		return up, false
	}
	up.Name, rest, ok = strings.Cut(rest, " ")
	if !ok {
		return up, false
	}
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "] ")
		if end < 0 {
			return up, false
		}
		up.Installed, rest = rest[1:end], rest[end+2:]
	}
	if !strings.HasPrefix(rest, "(") {
		return up, false
	}
	// The parentheses end after the architecture, "... [amd64])". Notes in more brackets
	// may follow, so the first "])" is the end, not the last.
	end := strings.Index(rest, "])")
	if end < 0 {
		return up, false
	}
	inner := rest[1:end]
	var origins string
	up.Candidate, origins, _ = strings.Cut(inner, " ")
	if i := strings.LastIndex(origins, " ["); i >= 0 {
		origins = origins[:i] // cut the architecture
	} else {
		origins = "" // no origin at all: only the architecture was there
	}
	up.Security = aptSecurityOrigin(origins)
	return up, up.Name != "" && up.Candidate != ""
}

// aptSecurityOrigin says whether one of the archives a version comes from is a security
// archive. apt prints each as Label:Version/Archive, for example
// "Debian-Security:13/stable-security" or "Ubuntu:24.04/noble-security". A security update
// that a point release has since folded into the main archive shows both and still counts.
func aptSecurityOrigin(origins string) bool {
	for _, origin := range strings.Split(origins, ", ") {
		label, rest, found := strings.Cut(origin, ":")
		if !found {
			label, rest = "", origin
		}
		archive := rest[strings.LastIndex(rest, "/")+1:]
		if strings.HasSuffix(archive, "-security") || strings.Contains(strings.ToLower(label), "security") {
			return true
		}
	}
	return false
}

// parseAptListed reads one indented line of a section: "name (old => new)" with -V, or names.
func parseAptListed(line string) []keptPackage {
	line = strings.TrimSpace(line)
	if name, rest, ok := strings.Cut(line, " ("); ok && strings.HasSuffix(rest, ")") {
		versions := strings.TrimSuffix(rest, ")")
		if old, new, ok := strings.Cut(versions, " => "); ok {
			return []keptPackage{{name: name, installed: old, candidate: new}}
		}
		return []keptPackage{{name: name, candidate: versions}}
	}
	var out []keptPackage
	for _, name := range strings.Fields(line) {
		out = append(out, keptPackage{name: strings.TrimSuffix(name, "*")}) // "*" marks a purge
	}
	return out
}

// parseAptSummary reads "50 upgraded, 2 newly installed, 0 to remove and 0 not upgraded."
func parseAptSummary(line string) (upgraded int, ok bool) {
	count, rest, found := strings.Cut(line, " upgraded, ")
	if !found || !strings.Contains(rest, "newly installed") {
		return 0, false
	}
	n, err := strconv.Atoi(count)
	return n, err == nil
}
