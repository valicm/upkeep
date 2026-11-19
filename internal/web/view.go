package web

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
)

// snapshot is what one request reads from the store, and everything a page is built from.
type snapshot struct {
	states   []model.SystemState
	checks   map[string]model.ImageCheck
	findings []model.Finding
	now      time.Time
	policy   model.Policy
}

// page is what the layout needs on every page.
type page struct {
	Title     string
	Nav       string // the navigation entry of this page
	Root      string // leads from this page to "/": links are relative, so a proxy may serve the dashboard under any path
	Asset     string // version in the static files' addresses
	Version   string
	Generated timeView
	Clock     string // when the page was built, as a time of day
	Live      bool   // the page shows state, so the script keeps it fresh
}

// sysView is one system, prepared for every page that shows it.
type sysView struct {
	Name         string
	Href         string
	Anchor       string // id of its section on the updates page
	Kind         string
	OS           string
	Kernel       string
	Arch         string
	Source       string
	AgentVersion string
	Received     timeView
	Sent         timeView
	Silent       bool
	Overall      mark // the worst of its findings

	Pkgs       *pkgView
	Containers []containerView
	Software   []softwareView
	Backups    []backupView
	Problems   []report.Problem
	Findings   []findingView
	Checked    timeView // the oldest registry check among its containers' images

	// The cells of the overview's table and the chips on the updates page.
	OSMark        mark
	RebootMark    mark
	ContainerMark mark
	SoftwareMark  mark
	BackupMark    mark
	Summary       []mark
	UpdateMark    mark // the loudest of Summary, for the list of systems on the updates page

	containersPending int
	containersAuto    int
	softwarePending   int
}

// pkgView is the package manager's state of one system.
type pkgView struct {
	ID           string // of the list's <details>, which the script keeps open across a refresh
	Manager      string
	Pending      int
	Security     int
	Items        []report.PackageUpdate
	More         int                    // pending packages the report had no room to list
	KeptID       string                 // of the list of held packages
	Kept         []report.PackageUpdate // newer versions an upgrade would leave alone, with the reason
	Lists        timeView
	Status       mark
	Reboot       mark
	RebootWaits  bool
	RebootReason string
}

// containerView is one container and what the registry says about its image.
type containerView struct {
	Name      string
	Image     string // as reported
	Repo      string
	Running   string // the tag, or a shortened digest when there is no tag
	Tagged    bool
	State     string
	Started   timeView
	Runtime   string
	Digest    string
	Auto      bool   // it pulls a newer image and restarts by itself
	AutoWord  string // "yes", "no", "local only"
	AutoLabel string
	Checked   timeView
	imageState
}

// softwareView is one piece of versioned software outside the package manager.
type softwareView struct {
	report.Software
	Status     mark
	Link       string // release notes, only when it is a plain web address
	LatestSame bool   // the latest version says nothing the installed one does not
}

// backupView is one backup job.
type backupView struct {
	System      string
	Href        string
	Name        string
	Kind        string
	State       string
	Marks       []mark
	LastSuccess timeView
	LastRun     timeView
	Result      string
	MaxAge      string
	MaxAgeOwn   bool // the backup set its own limit, it is not the server's default
	Detail      string

	status backupStatus
}

// findingView is one finding as a row.
type findingView struct {
	Mark     mark
	System   string
	Href     string
	Category string
	Title    string
	Detail   string
}

// findingBand is all findings of one severity.
type findingBand struct {
	Tone  tone
	Title string
	Plain bool // without its own heading row: something around it says what it is
	Rows  []findingView
}

// categoryLabel names a finding's category for a reader.
func categoryLabel(c model.Category) string {
	switch c {
	case model.CategoryOS:
		return "OS updates"
	case model.CategoryReboot:
		return "Reboot"
	case model.CategoryContainer:
		return "Container"
	case model.CategorySoftware:
		return "Software"
	case model.CategoryBackup:
		return "Backup"
	case model.CategorySource:
		return "Reporting"
	}
	return string(c)
}

func severityWord(s model.Severity) string {
	switch clampSeverity(s) {
	case model.Crit:
		return "broken"
	case model.Warn:
		return "to do"
	}
	return "to know"
}

func bandTitle(s model.Severity) string {
	switch clampSeverity(s) {
	case model.Crit:
		return "Broken"
	case model.Warn:
		return "Should be done"
	}
	return "Worth knowing"
}

func systemHref(root, name string) string {
	return root + "systems/" + url.PathEscape(name)
}

// findingRows turns findings into rows, in the order they come in: model.Findings sorts them,
// and the dashboard shows the same list as the digest mail.
func findingRows(fs []model.Finding, root string) []findingView {
	rows := make([]findingView, 0, len(fs))
	for _, f := range fs {
		v := findingView{
			Mark:     mark{Tone: severityTone(f.Severity), Text: severityWord(f.Severity)},
			System:   f.System,
			Category: categoryLabel(f.Category),
			Title:    f.Title,
			Detail:   f.Detail,
		}
		if f.System != "" {
			v.Href = systemHref(root, f.System)
		}
		rows = append(rows, v)
	}
	return rows
}

// bands groups the findings by severity, the worst first. Within a group nothing moves.
func bands(fs []model.Finding, root string) []findingBand {
	var out []findingBand
	for _, sev := range []model.Severity{model.Crit, model.Warn, model.Info} {
		var of []model.Finding
		for _, f := range fs {
			if clampSeverity(f.Severity) == sev {
				of = append(of, f)
			}
		}
		if len(of) > 0 {
			out = append(out, findingBand{Tone: severityTone(sev), Title: bandTitle(sev), Rows: findingRows(of, root)})
		}
	}
	return out
}

// verdicts is what the findings say per system and category. The overview's cells take their
// colour from here when a finding exists, so the table never disagrees with the list above it.
type verdicts map[string]map[model.Category]model.Severity

func newVerdicts(fs []model.Finding) verdicts {
	v := verdicts{}
	for _, f := range fs {
		if v[f.System] == nil {
			v[f.System] = map[model.Category]model.Severity{}
		}
		sev := clampSeverity(f.Severity)
		if old, ok := v[f.System][f.Category]; !ok || sev > old {
			v[f.System][f.Category] = sev
		}
	}
	return v
}

// tone returns the findings' verdict on one category of one system, or fallback when the
// findings do not mention it.
func (v verdicts) tone(system string, c model.Category, fallback tone) tone {
	if sev, ok := v[system][c]; ok {
		return severityTone(sev)
	}
	return fallback
}

// cell gives one cell of the overview its state. The words are the row's own; the colour is
// the findings' when they say anything about that category, also when the row itself looks
// fine: package lists that were not refreshed for days make "none pending" a guess.
func (v verdicts) cell(system string, c model.Category, m mark) mark {
	t := v.tone(system, c, m.Tone)
	if t.weight() > m.Tone.weight() && m.Title == "" {
		m.Title = "the list above says why"
	}
	m.Tone = t
	return m
}

// worst returns the highest severity among a system's findings.
func (v verdicts) worst(system string) (model.Severity, bool) {
	var worst model.Severity
	found := false
	for _, sev := range v[system] {
		if !found || sev > worst {
			worst, found = sev, true
		}
	}
	return worst, found
}

// anchors hands out ids that are valid in HTML and unique on one page, whatever a system is
// called.
type anchors map[string]bool

func (a anchors) id(prefix, name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	base := prefix + b.String()
	id := base
	for n := 2; a[id]; n++ {
		id = base + "-" + strconv.Itoa(n)
	}
	a[id] = true
	return id
}

// systemViews prepares every system of a snapshot.
func (s *snapshot) systemViews(root string) []sysView {
	v := newVerdicts(s.findings)
	ids := anchors{}
	out := make([]sysView, 0, len(s.states))
	for _, st := range s.states {
		out = append(out, s.systemView(st, root, v, ids))
	}
	return out
}

// notReported fills a cell about something the source does not look at.
var notReported = mark{Tone: toneBlank, Text: "—", Title: "this source does not report it"}

func (s *snapshot) systemView(st model.SystemState, root string, v verdicts, ids anchors) sysView {
	r := st.Report
	name := r.System.Name
	sv := sysView{
		Name:         name,
		Href:         systemHref(root, name),
		Anchor:       ids.id("sys-", name),
		Kind:         r.System.Kind,
		OS:           strings.TrimSpace(r.System.OS + " " + r.System.OSVersion),
		Kernel:       r.System.Kernel,
		Arch:         r.System.Arch,
		Source:       r.System.Source,
		AgentVersion: r.System.AgentVersion,
		Received:     newTimeView(st.ReceivedAt, s.now),
		Sent:         newTimeView(r.Sent, s.now),
		Silent:       silent(st.ReceivedAt, s.now, s.policy),
		Problems:     r.Errors,
		Overall:      mark{Tone: toneOK, Text: "nothing to do"},
	}
	if sev, ok := v.worst(name); ok {
		sv.Overall = mark{Tone: severityTone(sev), Text: strings.ToLower(bandTitle(sev))}
	}
	var own []model.Finding
	for _, f := range s.findings {
		if f.System == name {
			own = append(own, f)
		}
	}
	sv.Findings = findingRows(own, root)

	s.addPackages(&sv, r.Packages, v, ids)
	s.addContainers(&sv, r.Containers, v)
	s.addSoftware(&sv, r.Software, v)
	s.addBackups(&sv, r.Backups, v)

	switch {
	case len(sv.Summary) > 0:
	case sv.Pkgs == nil && len(sv.Containers) == 0 && len(sv.Software) == 0:
		sv.Summary = []mark{{Tone: toneNone, Text: "reports nothing that can be updated"}}
	default:
		sv.Summary = []mark{{Tone: toneOK, Text: "nothing to update"}}
	}
	sv.UpdateMark = sv.Summary[0]
	for _, m := range sv.Summary[1:] {
		if m.Tone.weight() > sv.UpdateMark.Tone.weight() {
			sv.UpdateMark = m
		}
	}
	return sv
}

// addPackages fills in the package manager's state and the reboot it may ask for.
func (s *snapshot) addPackages(sv *sysView, p *report.Packages, v verdicts, ids anchors) {
	sv.OSMark, sv.RebootMark = notReported, notReported
	if p == nil {
		return
	}
	pending, security := packageCounts(p)
	pv := &pkgView{
		ID:           ids.id("pk-", sv.Name),
		Manager:      p.Manager,
		Pending:      pending,
		Security:     security,
		Items:        append([]report.PackageUpdate(nil), p.Items...),
		Lists:        newTimeView(p.ListsUpdated, s.now),
		RebootWaits:  p.RebootRequired,
		RebootReason: p.RebootReason,
	}
	// Security updates first: they are the reason to open the list.
	sort.SliceStable(pv.Items, func(i, j int) bool {
		if pv.Items[i].Security != pv.Items[j].Security {
			return pv.Items[i].Security
		}
		return pv.Items[i].Name < pv.Items[j].Name
	})
	if more := pending - len(p.Items); more > 0 && len(p.Items) > 0 {
		pv.More = more
	}
	if len(p.KeptBack) > 0 {
		pv.KeptID = ids.id("kb-", sv.Name)
		pv.Kept = append([]report.PackageUpdate(nil), p.KeptBack...)
	}

	switch {
	case pending == 0:
		pv.Status = mark{Tone: toneOK, Text: "up to date"}
		sv.OSMark = mark{Tone: toneOK, Text: "none"}
	case security > 0:
		pv.Status = mark{Tone: toneWarn, Text: fmt.Sprintf("%d pending, %d security", pending, security)}
		sv.OSMark = mark{Tone: toneWarn, Text: fmt.Sprintf("%d · %d security", pending, security)}
	default:
		pv.Status = mark{Tone: toneInfo, Text: fmt.Sprintf("%d pending", pending)}
		sv.OSMark = mark{Tone: toneInfo, Text: strconv.Itoa(pending)}
	}
	sv.OSMark = v.cell(sv.Name, model.CategoryOS, sv.OSMark)
	held := 0 // as the findings count them: what the distribution is still phasing in is nobody's to act on
	for _, k := range p.KeptBack {
		if k.Reason != "phased" {
			held++
		}
	}
	switch {
	case pending > 0 || sv.OSMark.Tone == toneOK:
	case held > 0 && sv.OSMark.Tone == toneInfo:
		sv.OSMark.Text = fmt.Sprintf("%d held back", held)
	default:
		// The findings doubt the count, for example because the package lists are old.
		sv.OSMark.Text = "none known"
	}
	if pending > 0 {
		sv.Summary = append(sv.Summary, mark{Tone: pv.Status.Tone, Text: count(pending, "package", "packages")})
	}

	if p.RebootRequired {
		pv.Reboot = mark{Tone: toneWarn, Text: "waiting"}
		sv.RebootMark = v.cell(sv.Name, model.CategoryReboot, mark{Tone: toneWarn, Text: "waiting", Title: p.RebootReason})
		sv.Summary = append(sv.Summary, mark{Tone: toneWarn, Text: "reboot"})
	} else {
		pv.Reboot = mark{Tone: toneOK, Text: "not needed"}
		sv.RebootMark = mark{Tone: toneOK, Text: "no"}
	}
	sv.Pkgs = pv
}

// addContainers compares every container with the registry check of its image.
func (s *snapshot) addContainers(sv *sysView, containers []report.Container, v verdicts) {
	sv.ContainerMark = notReported
	unknown := 0
	var oldestCheck time.Time
	for _, c := range containers {
		check, checked := s.checks[c.Image]
		ref := splitImage(c.Image)
		cv := containerView{
			Name:       c.Name,
			Image:      c.Image,
			Repo:       ref.Repo,
			Running:    ref.Tag,
			Tagged:     ref.Tag != "",
			State:      c.State,
			Started:    newTimeView(c.StartedAt, s.now),
			Runtime:    c.Runtime,
			Digest:     c.Digest,
			AutoLabel:  c.AutoUpdate,
			Checked:    timeView{Zero: true, Rel: "never"},
			imageState: imageStatus(c, check, checked),
		}
		cv.Auto, cv.AutoWord = selfUpdate(c)
		if cv.Running == "" && ref.Digest != "" {
			cv.Running = "@" + shortDigest(ref.Digest)
		}
		if checked && !check.CheckedAt.IsZero() {
			cv.Checked = newTimeView(check.CheckedAt, s.now)
			if oldestCheck.IsZero() || check.CheckedAt.Before(oldestCheck) {
				oldestCheck = check.CheckedAt
			}
		}
		switch {
		case cv.Pending:
			sv.containersPending++
			if cv.Auto {
				sv.containersAuto++
			}
		case cv.Unknown:
			unknown++
		}
		sv.Containers = append(sv.Containers, cv)
	}
	// What has something newer comes first, the rest follows by name.
	sort.SliceStable(sv.Containers, func(i, j int) bool {
		a, b := sv.Containers[i], sv.Containers[j]
		if a.Pending != b.Pending {
			return a.Pending
		}
		return a.Name < b.Name
	})
	sv.Checked = newTimeView(oldestCheck, s.now)

	n := len(sv.Containers)
	switch {
	case n == 0:
		return
	case sv.containersPending > 0:
		sv.ContainerMark = mark{Tone: toneInfo, Text: fmt.Sprintf("%d of %d newer", sv.containersPending, n),
			Title: fmt.Sprintf("%d of %s have something newer", sv.containersPending, count(n, "container", "containers"))}
		sv.Summary = append(sv.Summary, mark{Tone: toneInfo, Text: count(sv.containersPending, "container", "containers")})
	case unknown > 0:
		sv.ContainerMark = mark{Tone: toneNone, Text: fmt.Sprintf("%d of %d unchecked", unknown, n),
			Title: "the registry has not been asked or could not be, or the running image is not known"}
	default:
		sv.ContainerMark = mark{Tone: toneOK, Text: fmt.Sprintf("%d current", n)}
	}
	sv.ContainerMark = v.cell(sv.Name, model.CategoryContainer, sv.ContainerMark)
}

// addSoftware fills in what has its own version: firmware, Home Assistant and its apps.
func (s *snapshot) addSoftware(sv *sysView, software []report.Software, v verdicts) {
	sv.SoftwareMark = notReported
	for _, sw := range software {
		w := softwareView{Software: sw, Link: webLink(sw.URL)}
		w.LatestSame = !sw.UpdateAvailable && (sw.Latest == "" || sw.Latest == sw.Installed)
		switch {
		case sw.UpdateAvailable:
			w.Status = mark{Tone: toneInfo, Text: "update"}
			sv.softwarePending++
		case sw.Installed != "":
			w.Status = mark{Tone: toneOK, Text: "current"}
		default:
			w.Status = mark{Tone: toneNone, Text: "unknown", Title: "the source did not say which version is installed"}
		}
		sv.Software = append(sv.Software, w)
	}
	// Updates first; otherwise the source's own order, which goes from the base to the apps.
	sort.SliceStable(sv.Software, func(i, j int) bool {
		return sv.Software[i].UpdateAvailable && !sv.Software[j].UpdateAvailable
	})

	n := len(sv.Software)
	switch {
	case n == 0:
		return
	case sv.softwarePending > 0:
		sv.SoftwareMark = mark{Tone: toneInfo, Text: fmt.Sprintf("%d of %d newer", sv.softwarePending, n)}
		sv.Summary = append(sv.Summary, mark{Tone: toneInfo, Text: count(sv.softwarePending, "software update", "software updates")})
	default:
		sv.SoftwareMark = mark{Tone: toneOK, Text: fmt.Sprintf("%d current", n)}
	}
	sv.SoftwareMark = v.cell(sv.Name, model.CategorySoftware, sv.SoftwareMark)
}

// addBackups fills in the backups and sums them up in one cell: the state that needs a person
// most, and how many of the system's backups are in it.
func (s *snapshot) addBackups(sv *sysView, backups []report.Backup, v verdicts) {
	sv.BackupMark = notReported
	for _, b := range backups {
		sv.Backups = append(sv.Backups, s.backupView(sv.Name, sv.Href, b))
	}
	var first *backupView
	same := 0
	for i := range sv.Backups {
		bv := &sv.Backups[i]
		switch {
		case first == nil || bv.status.rank() < first.status.rank():
			first, same = bv, 1
		case bv.State == first.State:
			same++
		}
	}
	if first == nil {
		return
	}
	text := first.State
	switch n := len(sv.Backups); {
	case n > 1 && same == n:
		text = fmt.Sprintf("%d %s", n, first.State)
	case n > 1:
		text = fmt.Sprintf("%d of %d %s", same, n, first.State)
	}
	sv.BackupMark = v.cell(sv.Name, model.CategoryBackup, mark{Tone: first.status.worst(), Text: text})
}

func (s *snapshot) backupView(system, href string, b report.Backup) backupView {
	st := readBackup(b, s.now, s.policy)
	bv := backupView{
		System:      system,
		Href:        href,
		Name:        b.Name,
		Kind:        b.Kind,
		State:       st.State,
		Marks:       []mark{{Tone: st.Tone, Text: st.State}},
		LastSuccess: newTimeView(st.Last, s.now),
		LastRun:     newTimeView(b.LastRun, s.now),
		Result:      b.LastResult,
		MaxAgeOwn:   st.Own,
		Detail:      b.Detail,
		status:      st,
	}
	if st.Late {
		bv.Marks = append(bv.Marks, mark{Tone: st.LateTone, Text: backupLate})
	}
	if st.MaxAge > 0 {
		bv.MaxAge = span(st.MaxAge)
	}
	return bv
}

// webLink lets only a plain web address become a link. A report is data from another machine:
// whatever else it puts into a URL field is shown as nothing.
func webLink(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return u.String()
}

// tile is one number in the overview's top row.
type tile struct {
	Label string
	Value int
	Note  mark
	Href  string
}

type overviewPage struct {
	page
	Tiles   []tile
	Bands   []findingBand // what is broken and what should be done
	ToDo    int           // how many findings that is
	Info    []findingBand // what is only worth knowing, folded away while there is something to do
	Systems []sysView
}

func (s *snapshot) overview(p page) overviewPage {
	systems := s.systemViews(p.Root)
	o := overviewPage{page: p, Systems: systems}
	// Ten seconds are for what is broken and what should be done. That an update exists is
	// worth knowing, and one click away.
	for _, b := range bands(s.findings, p.Root) {
		if b.Tone == toneInfo {
			b.Plain = true
			o.Info = append(o.Info, b)
		} else {
			o.Bands = append(o.Bands, b)
			o.ToDo += len(b.Rows)
		}
	}

	var (
		silentN, pending, security, reboots   int
		withPkgs, cUnknown, unreached         int
		containers, cPending, cAuto           int
		backups, bFailed, bNever, bLate, bRun int
		needing, findCrit, findWarn           int
		bWorst                                tone
	)
	v := newVerdicts(s.findings)
	for _, sv := range systems {
		if sv.Silent {
			silentN++
		} else {
			// Polled, and the last poll failed: what is shown is from before, or nothing at all.
			for _, p := range sv.Problems {
				if p.Collector == model.ConnectorProblem {
					unreached++
					break
				}
			}
		}
		if sev, ok := v.worst(sv.Name); ok && sev >= model.Warn {
			needing++
		}
		if p := sv.Pkgs; p != nil {
			withPkgs++
			pending += p.Pending
			security += p.Security
			if p.RebootWaits {
				reboots++
			}
		}
		containers += len(sv.Containers)
		for _, c := range sv.Containers {
			if c.Unknown {
				cUnknown++
			}
		}
		cPending += sv.containersPending
		cAuto += sv.containersAuto
		for _, b := range sv.Backups {
			backups++
			switch {
			case b.State == backupFailed:
				bFailed++
			case b.State == backupNever:
				bNever++
			case b.status.overdue():
				bLate++
			case b.State == backupRunning:
				bRun++
			}
			if w := b.status.worst(); w.weight() > bWorst.weight() {
				bWorst = w
			}
		}
	}
	for _, f := range s.findings {
		switch clampSeverity(f.Severity) {
		case model.Crit:
			findCrit++
		case model.Warn:
			findWarn++
		}
	}

	// Systems.
	t := tile{Label: "Systems", Value: len(systems), Href: "#systems", Note: mark{Tone: toneOK, Text: "all reporting"}}
	switch {
	case len(systems) == 0:
		t.Note = mark{Tone: toneNone, Text: "none has reported yet"}
	case silentN > 0 && unreached > 0:
		t.Note = mark{Tone: toneCrit, Text: fmt.Sprintf("%d silent, %d not answering", silentN, unreached)}
	case silentN > 0:
		t.Note = mark{Tone: toneCrit, Text: fmt.Sprintf("%d silent", silentN)}
	case unreached > 0:
		t.Note = mark{Tone: toneWarn, Text: fmt.Sprintf("%d not answering", unreached)}
	}
	o.Tiles = append(o.Tiles, t)

	// Systems needing attention: the ones with something to do, not the ones with news only.
	t = tile{Label: "Need attention", Value: needing, Href: "#attention", Note: mark{Tone: toneOK, Text: "nothing to do"}}
	switch {
	case len(systems) == 0:
		// Nothing to do because nothing is known is not the same as all being well.
		t.Note = mark{Tone: toneNone, Text: "no system to look at"}
	case findCrit > 0 && findWarn > 0:
		t.Note = mark{Tone: toneCrit, Text: fmt.Sprintf("%d broken, %d to do", findCrit, findWarn)}
	case findCrit > 0:
		t.Note = mark{Tone: toneCrit, Text: fmt.Sprintf("%d broken", findCrit)}
	case findWarn > 0:
		t.Note = mark{Tone: toneWarn, Text: fmt.Sprintf("%d to do", findWarn)}
	case len(s.findings) > 0:
		t.Note = mark{Tone: toneInfo, Text: fmt.Sprintf("%d to know", len(s.findings))}
	}
	o.Tiles = append(o.Tiles, t)

	// Operating system packages.
	t = tile{Label: "OS updates", Value: pending, Href: p.Root + "updates", Note: mark{Tone: toneOK, Text: "none pending"}}
	switch {
	case withPkgs == 0:
		t.Note = mark{Tone: toneNone, Text: "none reported"}
	case security > 0 && reboots > 0:
		t.Note = mark{Tone: toneWarn, Text: fmt.Sprintf("%d security, %s", security, count(reboots, "reboot", "reboots"))}
	case security > 0:
		t.Note = mark{Tone: toneWarn, Text: fmt.Sprintf("%d security", security)}
	case reboots > 0:
		t.Note = mark{Tone: toneInfo, Text: count(reboots, "reboot waiting", "reboots waiting")}
	case pending > 0:
		t.Note = mark{Tone: toneInfo, Text: "no security updates"}
	}
	o.Tiles = append(o.Tiles, t)

	// Containers.
	t = tile{Label: "Container updates", Value: cPending, Href: p.Root + "updates",
		Note: mark{Tone: toneOK, Text: fmt.Sprintf("all %d current", containers)}}
	switch {
	case containers == 0:
		t.Note = mark{Tone: toneNone, Text: "none reported"}
	case cPending > 0 && cAuto > 0:
		t.Note = mark{Tone: toneInfo, Text: fmt.Sprintf("of %d, %s", containers, count(cAuto, "updates itself", "update themselves"))}
	case cPending > 0:
		t.Note = mark{Tone: toneInfo, Text: fmt.Sprintf("of %d", containers)}
	case cUnknown > 0:
		// No update is known, and for some of them nothing is known at all.
		t.Note = mark{Tone: toneNone, Text: fmt.Sprintf("%d of %d unchecked", cUnknown, containers)}
	}
	o.Tiles = append(o.Tiles, t)

	// Backups.
	t = tile{Label: "Backups late or failed", Value: bFailed + bNever + bLate, Href: p.Root + "backups",
		Note: mark{Tone: toneOK, Text: fmt.Sprintf("all %d fine", backups)}}
	var parts []string
	for _, c := range []struct {
		n    int
		word string
	}{{bFailed, "failed"}, {bNever, "never ran"}, {bLate, "late"}} {
		if c.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c.n, c.word))
		}
	}
	switch {
	case backups == 0:
		t.Note = mark{Tone: toneNone, Text: "none reported"}
	case len(parts) > 0:
		t.Note = mark{Tone: bWorst, Text: strings.Join(parts, ", ")}
	case bRun > 0:
		t.Note = mark{Tone: toneInfo, Text: fmt.Sprintf("%d running", bRun)}
	}
	o.Tiles = append(o.Tiles, t)
	return o
}

type updatesPage struct {
	page
	Systems []sysView
}

func (s *snapshot) updates(p page) updatesPage {
	return updatesPage{page: p, Systems: s.systemViews(p.Root)}
}

type backupsPage struct {
	page
	Rows    []backupView
	Summary []mark
	Without []sysView // systems that report no backup at all
}

func (s *snapshot) backups(p page) backupsPage {
	b := backupsPage{page: p}
	counts := map[string]int{}
	for _, sv := range s.systemViews(p.Root) {
		if len(sv.Backups) == 0 {
			b.Without = append(b.Without, sv)
		}
		for _, bv := range sv.Backups {
			counts[bv.State]++
			b.Rows = append(b.Rows, bv)
		}
	}
	sort.SliceStable(b.Rows, func(i, j int) bool {
		return b.Rows[i].status.rank() < b.Rows[j].status.rank()
	})
	// One mark per state, in the order of the rows, each as loud as its loudest row.
	for _, row := range b.Rows {
		if counts[row.State] > 0 {
			b.Summary = append(b.Summary, mark{Tone: row.status.Tone, Text: fmt.Sprintf("%d %s", counts[row.State], row.State)})
			counts[row.State] = 0
		}
	}
	return b
}

type systemPage struct {
	page
	S       sysView
	Raw     string // the stored report as JSON
	RawHref string
}
