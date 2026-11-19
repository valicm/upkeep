package web

import (
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
)

// This file reads single rows: one backup, one container, one package manager. What needs
// attention is model.Findings' decision, but a finding is a sentence about a system, and a
// table needs a word and a mark for every row. The rules here follow those in
// model/findings.go one by one, so a row never says something else than the finding about it.

// tone is the state a mark shows. Each tone has one colour and one shape in the stylesheet, and
// a mark always carries a word too, so nothing depends on colour alone.
type tone string

const (
	toneOK   tone = "ok"   // looked at, nothing to do
	toneInfo tone = "info" // something newer exists, or work is in progress
	toneWarn tone = "warn" // should be done
	toneCrit tone = "crit" // broken
	toneNone tone = "none" // not known: nobody looked, or it could not be told

	toneBlank tone = "blank" // nothing to say: the source does not report this at all
)

// mark is one word with a state.
type mark struct {
	Tone  tone
	Text  string
	Title string // one line more, shown on hover
}

// weight orders tones from calm to loud, to pick the worst of several.
func (t tone) weight() int {
	switch t {
	case toneCrit:
		return 4
	case toneWarn:
		return 3
	case toneInfo:
		return 2
	case toneOK:
		return 1
	}
	return 0
}

// clampSeverity keeps a severity inside the three known ones. A value from a newer build must
// not break the page: Severity.String panics outside its range.
func clampSeverity(s model.Severity) model.Severity {
	switch {
	case s < model.Info:
		return model.Info
	case s > model.Crit:
		return model.Crit
	}
	return s
}

func severityTone(s model.Severity) tone {
	switch clampSeverity(s) {
	case model.Crit:
		return toneCrit
	case model.Warn:
		return toneWarn
	}
	return toneInfo
}

// packageCounts reads a package manager's counts leniently: a list longer than the count
// wins, and flagged packages count when the report gives no security count.
func packageCounts(p *report.Packages) (pending, security int) {
	pending = max(p.Pending, len(p.Items))
	security = p.Security
	if security == 0 {
		for _, it := range p.Items {
			if it.Security {
				security++
			}
		}
	}
	return pending, min(security, pending)
}

// Backup states, as the backups page names them.
const (
	backupOK      = "ok"
	backupLate    = "late"
	backupFailed  = "failed"
	backupNever   = "never"
	backupRunning = "running"
)

// backupStatus is how one backup is doing.
type backupStatus struct {
	State    string
	Tone     tone
	Late     bool          // overdue as well: said next to "failed" and "running"
	LateTone tone          // late is a warning, twice the allowed age is broken
	Last     time.Time     // the success the age is counted from
	MaxAge   time.Duration // how old that success may be; 0 means any age
	Own      bool          // the backup set its limit itself, it is not the server's default
}

// readBackup reads one backup the way a person would: a run in progress is what is happening
// now, a failed run is the news until a run succeeds, and after that only age counts.
func readBackup(b report.Backup, now time.Time, p model.Policy) backupStatus {
	st := backupStatus{Last: b.LastSuccess, MaxAge: p.BackupMaxAge}
	if b.MaxAgeHours > 0 {
		st.MaxAge, st.Own = time.Duration(b.MaxAgeHours)*time.Hour, true
	}
	if st.Last.IsZero() && b.LastResult == "ok" {
		st.Last = b.LastRun // it says it worked, and this is the only time known
	}
	age := now.Sub(st.Last)
	older := func(limit time.Duration) bool { return !st.Last.IsZero() && st.MaxAge > 0 && age > limit }
	st.LateTone = toneWarn
	if older(2 * st.MaxAge) {
		st.LateTone = toneCrit
	}
	switch {
	case b.LastResult == "failed":
		st.State, st.Tone, st.Late = backupFailed, toneCrit, older(st.MaxAge)
	case b.LastResult == "running":
		// A run in progress may be the overdue one catching up, so being late is not held
		// against it. Twice the allowed age is: a backup that hangs stays "running" for ever.
		st.State, st.Tone, st.Late = backupRunning, toneInfo, older(2*st.MaxAge)
	case older(st.MaxAge):
		st.State, st.Tone = backupLate, st.LateTone
	case st.Last.IsZero():
		st.State, st.Tone = backupNever, toneWarn
	default:
		st.State, st.Tone = backupOK, toneOK
	}
	return st
}

// worst is the loudest thing the status says.
func (st backupStatus) worst() tone {
	if st.Late && st.LateTone.weight() > st.Tone.weight() {
		return st.LateTone
	}
	return st.Tone
}

// overdue reports whether the last success is older than allowed, whatever else is going on.
func (st backupStatus) overdue() bool { return st.State == backupLate || st.Late }

// rank sorts backups by what needs a person first: the loudest state on top, and among equals
// failed before late before never.
func (st backupStatus) rank() int {
	order := map[string]int{backupFailed: 0, backupLate: 1, backupNever: 2, backupRunning: 3, backupOK: 4}
	return (4-st.worst().weight())*10 + order[st.State]
}

// silent says whether a source stopped reporting.
func silent(received, now time.Time, p model.Policy) bool {
	return p.SilentAfter > 0 && !received.IsZero() && now.Sub(received) > p.SilentAfter
}

// imageRef is a container image reference taken apart for display.
type imageRef struct {
	Repo   string // "docker.io/gitea/gitea"
	Tag    string // "1.23.6", empty when the reference has none
	Digest string // "sha256:...", when the reference pins one
	Local  bool   // built on the machine: no registry the server can reach has it
}

func splitImage(s string) imageRef {
	var ref imageRef
	if at := strings.LastIndexByte(s, '@'); at >= 0 {
		s, ref.Digest = s[:at], s[at+1:]
	}
	// A colon before the last slash is a registry's port, not a tag.
	if colon := strings.LastIndexByte(s, ':'); colon > strings.LastIndexByte(s, '/') {
		s, ref.Tag = s[:colon], s[colon+1:]
	}
	ref.Repo = s
	// "localhost/" is where Podman puts what was built on the machine, and a registry on the
	// machine's own localhost is not one the server can ask either.
	host, _, hasHost := strings.Cut(s, "/")
	ref.Local = hasHost && (host == "localhost" || strings.HasPrefix(host, "localhost:"))
	return ref
}

// newer is one tag a registry has that is ahead of the running one.
type newer struct {
	Level string // "patch", "minor", "major"
	Tag   string
}

// imageState is what the dashboard says about one container's image.
type imageState struct {
	Newer   []newer
	Rebuilt bool   // the registry has another image under the running reference now
	Pending bool   // something newer exists: a tag, or a rebuild
	Unknown bool   // the registry was not asked, or could not be: nothing can be said
	Status  mark   // the word for it when nothing is newer, or why it is not known
	Problem string // why the registry could not be asked
	Note    string // a remark on a check that worked: the tag list may be incomplete
}

// imageStatus compares a container with what the registry said about its image.
func imageStatus(c report.Container, check model.ImageCheck, checked bool) imageState {
	ref := splitImage(c.Image)
	var st imageState
	if checked {
		for _, n := range []newer{{"patch", check.NewerPatch}, {"minor", check.NewerMinor}, {"major", check.NewerMajor}} {
			if n.Tag != "" {
				st.Newer = append(st.Newer, n)
			}
		}
		// Only known digests can disagree: an agent that could not tell the digest, or a
		// registry that was not reached, proves nothing. The rule is the findings' own.
		st.Rebuilt = model.Rebuilt(c, check)
		st.Problem = check.Error
		st.Note = check.Note
	}
	st.Pending = len(st.Newer) > 0 || st.Rebuilt
	switch {
	case st.Pending:
		// The chips say what is newer. That may be old news if the last check failed.
		if st.Problem != "" {
			st.Status = mark{toneNone, "last check failed", "what is shown comes from an earlier check"}
		}
	case ref.Local:
		st.Status = mark{toneNone, "local image", "built on the machine, no registry has it"}
		st.Problem = ""
	case ref.Tag == "" && ref.Digest != "":
		st.Status = mark{toneNone, "pinned by digest", "it cannot move to anything newer by itself"}
		st.Problem = ""
	case !checked:
		st.Unknown = true
		st.Status = mark{toneNone, "not checked", "the server has not asked the registry about this image yet"}
	case check.Error != "":
		st.Unknown = true
		st.Status = mark{toneNone, "check failed", "the registry could not be asked"}
	case check.TagDigest == "":
		// A check without an error and without a digest is one where no registry was asked.
		st.Unknown = true
		st.Status = mark{toneNone, "not checked", "no registry was asked about this image"}
	case !model.DigestKnown(c):
		// The tags were compared and none is newer. Whether this tag was rebuilt is another
		// question, and without the running image's digest it has no answer: not "up to date".
		st.Unknown = true
		st.Status = mark{toneNone, "no newer tag", "the report does not say which image the container runs, so a rebuilt tag would not be seen"}
	default:
		st.Status = mark{toneOK, "up to date", ""}
	}
	return st
}

// selfUpdate reads Podman's auto-update label (podman-auto-update(1)). "registry", or "image"
// as it was once called, pulls a rebuilt tag and restarts by itself. "local" only restarts
// when the image changes on the machine: it does not fetch anything.
func selfUpdate(c report.Container) (pulls bool, word string) {
	switch {
	case model.UpdatesItself(c):
		return true, "yes"
	case c.AutoUpdate == "local":
		return false, "local only"
	}
	return false, "no"
}
