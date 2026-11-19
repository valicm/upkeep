package model

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// ConnectorProblem is the collector name the server puts in a report's Errors when it could
// not reach a system through its API. Findings words that one differently from an agent's
// collector that failed.
const ConnectorProblem = "connector"

// ListsMaxAge is how old package lists may be before the pending count cannot be trusted.
const ListsMaxAge = 72 * time.Hour

// Findings turns the raw state into the list of things that need attention, most severe first.
// It is a pure function: the dashboard and the digest mail both show exactly this list.
//
// A title never changes just because time passes (it names a date, not an age), so two calls
// give the same titles until the state itself changes. The "on change" mail relies on that.
// Ages are in the details.
func Findings(states []SystemState, checks map[string]ImageCheck, now time.Time, p Policy) []Finding {
	var out []Finding
	for _, st := range states {
		f := finder{system: st.Report.System.Name, now: now, policy: p}
		f.silence(st)
		f.packages(st.Report.Packages)
		f.containers(st.Report.Containers, checks)
		f.software(st.Report.Software)
		f.backups(st.Report.Backups)
		f.problems(st.Report.Errors)
		out = append(out, f.found...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Severity != b.Severity:
			return a.Severity > b.Severity
		case a.System != b.System:
			return a.System < b.System
		case a.Category != b.Category:
			return categoryRank(a.Category) < categoryRank(b.Category)
		}
		return a.Title < b.Title
	})
	return out
}

// categoryRank orders the findings of one system and one severity: first what says the rest
// may be out of date or lost (the source itself, backups), then what is to be done on the
// machine, then what there is to update, the many containers last.
func categoryRank(c Category) int {
	for i, k := range [...]Category{CategorySource, CategoryBackup, CategoryReboot, CategoryOS, CategorySoftware, CategoryContainer} {
		if c == k {
			return i
		}
	}
	return 99
}

// finder collects the findings of one system.
type finder struct {
	system string
	now    time.Time
	policy Policy
	found  []Finding
}

func (f *finder) add(c Category, s Severity, title, detail string) {
	f.found = append(f.found, Finding{System: f.system, Category: c, Severity: s, Title: title, Detail: detail})
}

// silence reports a source that stopped reporting. What it said last is still shown: old news
// about pending updates is better than none.
func (f *finder) silence(st SystemState) {
	if f.policy.SilentAfter <= 0 || st.ReceivedAt.IsZero() {
		return
	}
	quiet := f.now.Sub(st.ReceivedAt)
	if quiet <= f.policy.SilentAfter {
		return
	}
	who := "agent"
	if st.Report.System.Source == "connector" {
		who = "connector"
	}
	f.add(CategorySource, Crit,
		"no report since "+stamp(st.ReceivedAt),
		fmt.Sprintf("silent for %s; the %s should report at least every %s", span(quiet), who, span(f.policy.SilentAfter)))
}

func (f *finder) packages(p *report.Packages) {
	if p == nil {
		return
	}
	pending := max(p.Pending, len(p.Items))
	security := p.Security
	if security == 0 {
		for _, it := range p.Items {
			if it.Security {
				security++
			}
		}
	}
	security = min(security, pending)
	if pending > 0 {
		sev, title := Info, count(pending, "package update")
		if security > 0 {
			sev = Warn
			title += fmt.Sprintf(", %d security", security)
		}
		f.add(CategoryOS, sev, title, packageNames(p.Items, pending))
	}
	if p.RebootRequired {
		f.add(CategoryReboot, Warn, "reboot required", oneLine(p.RebootReason))
	}
	f.keptBack(p.KeptBack)
	if !p.ListsUpdated.IsZero() && f.now.Sub(p.ListsUpdated) > ListsMaxAge {
		detail := span(f.now.Sub(p.ListsUpdated)) + " ago"
		if p.Manager != "" {
			detail += " (" + p.Manager + ")"
		}
		f.add(CategoryOS, Warn,
			"package lists not refreshed since "+p.ListsUpdated.UTC().Format(time.DateOnly),
			detail+"; newer updates may exist that are not counted here")
	}
}

// keptBack says which newer versions an upgrade would leave alone because somebody, or a
// broken dependency, holds them: such a package gets no security update either. Updates the
// distribution is still phasing in are nobody's to act on and are left out.
func (f *finder) keptBack(kept []report.PackageUpdate) {
	var held, other []string
	for _, k := range kept {
		switch k.Reason {
		case "phased":
		case "held":
			held = append(held, k.Name)
		default:
			other = append(other, k.Name)
		}
	}
	n := len(held) + len(other)
	if n == 0 {
		return
	}
	var parts []string
	if len(held) > 0 {
		parts = append(parts, "on hold: "+someNames(held))
	}
	if len(other) > 0 {
		parts = append(parts, "kept back, their dependencies cannot be met: "+someNames(other))
	}
	f.add(CategoryOS, Info, count(n, "package update")+" held back", strings.Join(parts, "; "))
}

// someNames lists the first few names of a list and counts the rest.
func someNames(names []string) string {
	if len(names) > maxNames {
		return strings.Join(names[:maxNames], ", ") + fmt.Sprintf(" and %d more", len(names)-maxNames)
	}
	return strings.Join(names, ", ")
}

// maxNames is how many package names fit in one line of detail.
const maxNames = 8

// packageNames lists the pending packages in one line, security updates first.
func packageNames(items []report.PackageUpdate, pending int) string {
	var secure, other []string
	for _, it := range items {
		if it.Security {
			secure = append(secure, it.Name)
		} else {
			other = append(other, it.Name)
		}
	}
	if len(secure) > maxNames {
		secure = secure[:maxNames]
	}
	if len(other) > maxNames-len(secure) {
		other = other[:maxNames-len(secure)]
	}
	var line string
	switch {
	case len(secure) > 0 && len(other) > 0:
		line = "security: " + strings.Join(secure, ", ") + "; also " + strings.Join(other, ", ")
	case len(secure) > 0:
		line = "security: " + strings.Join(secure, ", ")
	case len(other) > 0:
		line = strings.Join(other, ", ")
	default:
		return ""
	}
	if rest := pending - len(secure) - len(other); rest > 0 {
		line += fmt.Sprintf(" and %d more", rest)
	}
	return line
}

func (f *finder) containers(containers []report.Container, checks map[string]ImageCheck) {
	var unchecked []string // images of this system the registry could not be asked about
	var firstError string
	seen := map[string]bool{}
	for _, c := range containers {
		check, ok := checks[c.Image]
		if !ok {
			continue // never checked: a local image, one pinned by digest, or not asked yet
		}
		if check.Error != "" && !seen[c.Image] {
			seen[c.Image] = true
			unchecked = append(unchecked, c.Image)
			if firstError == "" {
				firstError = check.Error
			}
		}
		// With an error the other fields are what the registry said last time. A newer
		// version does not go away, so they are still worth showing.
		if Rebuilt(c, check) {
			title := c.Name + ": image was rebuilt"
			if check.Tag != "" {
				title = fmt.Sprintf("%s: tag %s was rebuilt", c.Name, check.Tag)
			}
			detail := fmt.Sprintf("%s is now %s, the container runs %s", c.Image, shortDigest(check.TagDigest), shortDigest(runningDigest(c)))
			switch {
			case strings.Contains(c.Image, "@"):
				detail += "; the container is pinned to its digest and only moves when the pin is changed"
			case UpdatesItself(c):
				detail += "; it updates itself (auto-update " + c.AutoUpdate + ")"
			default:
				detail += "; pull the image and restart the container"
			}
			f.add(CategoryContainer, Info, title, detail)
		}
		// One finding per container: the smallest step up is the one most likely to be taken,
		// the bigger ones are named in the detail.
		var title, kind string
		var others []string
		for _, s := range []struct{ version, kind string }{
			{check.NewerPatch, "patch"}, {check.NewerMinor, "minor"}, {check.NewerMajor, "major"},
		} {
			switch {
			case s.version == "":
			case title == "":
				title, kind = fmt.Sprintf("%s: %s available", c.Name, s.version), s.kind
			default:
				others = append(others, fmt.Sprintf("%s (%s)", s.version, s.kind))
			}
		}
		if title != "" {
			detail := kind + " update of " + c.Image
			if len(others) > 0 {
				detail += "; also " + strings.Join(others, ", ")
			}
			f.add(CategoryContainer, Info, title, detail)
		}
	}
	if len(unchecked) > 0 {
		detail := unchecked[0] + ": " + oneLine(firstError)
		if len(unchecked) > 1 {
			detail += fmt.Sprintf(" (and %d more)", len(unchecked)-1)
		}
		f.add(CategoryContainer, Info, count(len(unchecked), "image")+" could not be checked", detail)
	}
}

// UpdatesItself reports whether Podman's auto-update will pull a rebuilt tag by itself.
// podman-auto-update(1): "registry" asks the registry; "image" is its old name.
func UpdatesItself(c report.Container) bool {
	return c.AutoUpdate == "registry" || c.AutoUpdate == "image"
}

// DigestKnown reports whether the container says which image it runs, so that it can be
// compared with what the registry has. An agent leaves the digest out when the runtime does
// not tell: then a rebuilt tag cannot be seen, which is not the same as "not rebuilt".
func DigestKnown(c report.Container) bool { return runningDigest(c) != "" }

// Rebuilt reports whether the tag in the registry now points at another image than the one
// the container runs. A runtime knows an image for several architectures by more than one
// digest (the whole set's, and this machine's variant's), and the registry names the set's:
// the tag only moved when it matches none of them. Without a digest on either side nothing
// can disagree.
func Rebuilt(c report.Container, k ImageCheck) bool {
	if k.TagDigest == "" || !DigestKnown(c) {
		return false
	}
	if strings.EqualFold(c.Digest, k.TagDigest) {
		return false
	}
	for _, d := range c.Digests {
		if strings.EqualFold(d, k.TagDigest) {
			return false
		}
	}
	return true
}

// runningDigest is the digest to name the running image by: the one it was pulled as, or
// else the first of those it is known by.
func runningDigest(c report.Container) string {
	if c.Digest != "" {
		return c.Digest
	}
	for _, d := range c.Digests {
		if d != "" {
			return d
		}
	}
	return ""
}

func (f *finder) software(software []report.Software) {
	for _, s := range software {
		if !s.UpdateAvailable {
			continue
		}
		title := s.Name + " update available"
		if s.Latest != "" {
			title = s.Name + " " + s.Latest + " available"
		}
		var parts []string
		if s.Installed != "" {
			parts = append(parts, "installed "+s.Installed)
		}
		if s.Detail != "" {
			parts = append(parts, oneLine(s.Detail))
		}
		if s.URL != "" {
			parts = append(parts, s.URL)
		}
		f.add(CategorySoftware, Info, title, strings.Join(parts, "; "))
	}
}

func (f *finder) backups(backups []report.Backup) {
	for _, b := range backups {
		maxAge := f.policy.BackupMaxAge
		if b.MaxAgeHours > 0 {
			maxAge = time.Duration(b.MaxAgeHours) * time.Hour
		}
		last := b.LastSuccess
		if last.IsZero() && b.LastResult == "ok" {
			last = b.LastRun // it says it worked and only this time is known
		}
		age := f.now.Sub(last)
		tooOld := func(limit time.Duration) bool { return !last.IsZero() && maxAge > 0 && age > limit }
		stale := func(sev Severity, note string) {
			f.add(CategoryBackup, sev,
				"backup "+b.Name+" last succeeded "+last.UTC().Format(time.DateOnly),
				fmt.Sprintf("%s ago, at %s; allowed age is %s%s", span(age), last.UTC().Format("15:04 UTC"), span(maxAge), note))
		}

		switch {
		case b.LastResult == "failed":
			var parts []string
			if !b.LastRun.IsZero() {
				parts = append(parts, "last run "+stamp(b.LastRun))
			}
			if b.Detail != "" {
				parts = append(parts, oneLine(b.Detail))
			}
			if last.IsZero() {
				parts = append(parts, "no successful run is known")
			} else {
				parts = append(parts, "last success "+stamp(last))
			}
			f.add(CategoryBackup, Crit, "backup "+b.Name+" failed", strings.Join(parts, "; "))
		case b.LastResult == "running" && tooOld(2*maxAge):
			// A backup that hangs stays "running" for ever and must not hide behind that.
			stale(Crit, "; a run is in progress")
		case b.LastResult == "running":
			// Nothing to say: it is doing its job right now.
		case tooOld(2 * maxAge):
			stale(Crit, "")
		case tooOld(maxAge):
			stale(Warn, "")
		case last.IsZero() && b.LastResult != "ok":
			detail := oneLine(b.Detail)
			if detail == "" {
				detail = "no successful run is known"
			}
			f.add(CategoryBackup, Warn, "backup "+b.Name+" never succeeded", detail)
		}
	}
}

func (f *finder) problems(problems []report.Problem) {
	for _, p := range problems {
		title := "collector " + p.Collector + " failed"
		switch p.Collector {
		case ConnectorProblem:
			title = "connector failed"
		case "":
			title = "a collector failed"
		}
		f.add(CategorySource, Warn, title, oneLine(p.Message))
	}
}

// count says "1 thing" or "3 things".
func count(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

// span says a duration the way a person would: "40 minutes", "5 hours", "3 days".
func span(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return count(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return count(int(d/time.Hour), "hour")
	}
	return count(int(d/(24*time.Hour)), "day")
}

// stamp is a moment in UTC. Findings is pure, so it cannot know the reader's time zone.
func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// shortDigest keeps enough of a digest to recognise it.
func shortDigest(d string) string {
	algo, hex, ok := strings.Cut(d, ":")
	if !ok || len(hex) <= 12 {
		return d
	}
	return algo + ":" + hex[:12]
}

// maxLine caps what a collector's message may take of one line.
const maxLine = 300

// oneLine makes a message from outside fit a single line of detail.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxLine {
		cut := maxLine
		for cut > 0 && !isRuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
