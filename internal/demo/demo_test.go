package demo

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/store"
)

// lab is the demo as the store returns it, with the questions the tests ask of it.
type lab struct {
	now    time.Time
	states []model.SystemState
	checks map[string]model.ImageCheck
	policy model.Policy
}

func fill(t *testing.T, now time.Time) lab {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemory()
	if err := Fill(ctx, s, now); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	states, err := s.Systems(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checks, err := s.ImageChecks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return lab{now: now, states: states, checks: checks, policy: model.DefaultPolicy()}
}

func (l lab) anyContainer(match func(report.Container, model.ImageCheck, bool) bool) bool {
	for _, st := range l.states {
		for _, c := range st.Report.Containers {
			check, ok := l.checks[c.Image]
			if match(c, check, ok) {
				return true
			}
		}
	}
	return false
}

func (l lab) anySoftware(match func(report.System, report.Software) bool) bool {
	for _, st := range l.states {
		for _, sw := range st.Report.Software {
			if match(st.Report.System, sw) {
				return true
			}
		}
	}
	return false
}

func (l lab) anyBackup(match func(b report.Backup, age, allowed time.Duration) bool) bool {
	for _, st := range l.states {
		for _, b := range st.Report.Backups {
			allowed := l.policy.BackupMaxAge
			if b.MaxAgeHours > 0 {
				allowed = time.Duration(b.MaxAgeHours) * time.Hour
			}
			if match(b, l.now.Sub(b.LastSuccess), allowed) {
				return true
			}
		}
	}
	return false
}

func (l lab) anySystem(match func(model.SystemState) bool) bool {
	for _, st := range l.states {
		if match(st) {
			return true
		}
	}
	return false
}

// TestFillShowsEveryState is the demo's promise: whoever looks at it sees each state the
// dashboard can show at least once. It holds at any time of day, since everything in the demo
// is counted back from now.
func TestFillShowsEveryState(t *testing.T) {
	rebuilt := func(c report.Container, k model.ImageCheck, ok bool) bool {
		return ok && c.Digest != "" && k.TagDigest != "" && c.Digest != k.TagDigest
	}
	shows := []struct {
		name string
		in   func(lab) bool
	}{
		{"security updates", func(l lab) bool {
			return l.anySystem(func(st model.SystemState) bool {
				p := st.Report.Packages
				return p != nil && p.Security > 0 && p.Pending > p.Security
			})
		}},
		{"updates without a security one", func(l lab) bool {
			return l.anySystem(func(st model.SystemState) bool {
				p := st.Report.Packages
				return p != nil && p.Pending > 0 && p.Security == 0
			})
		}},
		{"a package manager with nothing pending", func(l lab) bool {
			return l.anySystem(func(st model.SystemState) bool {
				p := st.Report.Packages
				return p != nil && p.Pending == 0 && !p.RebootRequired
			})
		}},
		{"a waiting reboot and why", func(l lab) bool {
			return l.anySystem(func(st model.SystemState) bool {
				p := st.Report.Packages
				return p != nil && p.RebootRequired && p.RebootReason != ""
			})
		}},
		{"a container with a newer patch", func(l lab) bool {
			return l.anyContainer(func(_ report.Container, k model.ImageCheck, _ bool) bool { return k.NewerPatch != "" })
		}},
		{"a container with a newer minor", func(l lab) bool {
			return l.anyContainer(func(_ report.Container, k model.ImageCheck, _ bool) bool { return k.NewerMinor != "" })
		}},
		{"a container with a newer major and nothing smaller", func(l lab) bool {
			return l.anyContainer(func(_ report.Container, k model.ImageCheck, _ bool) bool {
				return k.NewerMajor != "" && k.NewerMinor == "" && k.NewerPatch == ""
			})
		}},
		{"a rebuilt tag on a container that updates itself", func(l lab) bool {
			return l.anyContainer(func(c report.Container, k model.ImageCheck, ok bool) bool {
				return rebuilt(c, k, ok) && c.AutoUpdate == "registry"
			})
		}},
		{"a rebuilt tag on a container that does not update itself", func(l lab) bool {
			return l.anyContainer(func(c report.Container, k model.ImageCheck, ok bool) bool {
				return rebuilt(c, k, ok) && c.AutoUpdate == ""
			})
		}},
		{"a container that is up to date", func(l lab) bool {
			return l.anyContainer(func(c report.Container, k model.ImageCheck, ok bool) bool {
				return ok && k.Error == "" && k.Tag != "" && c.Digest == k.TagDigest && k.NewerPatch+k.NewerMinor+k.NewerMajor == ""
			})
		}},
		{"an image no registry was asked about yet", func(l lab) bool {
			return l.anyContainer(func(c report.Container, _ model.ImageCheck, ok bool) bool {
				return !ok && !strings.HasPrefix(c.Image, "localhost/") && !strings.Contains(c.Image, "@")
			})
		}},
		{"a registry that could not be asked", func(l lab) bool {
			return l.anyContainer(func(c report.Container, k model.ImageCheck, ok bool) bool {
				return ok && k.Error != "" && !strings.HasPrefix(c.Image, "localhost/")
			})
		}},
		{"a local image, which has no check", func(l lab) bool {
			return l.anyContainer(func(c report.Container, _ model.ImageCheck, ok bool) bool {
				return c.Image == "localhost/medimorec-server:current" && !ok
			})
		}},
		{"an image pinned by digest, without a tag and without a check", func(l lab) bool {
			return l.anyContainer(func(c report.Container, _ model.ImageCheck, ok bool) bool {
				return strings.HasPrefix(c.Image, "ghcr.io/stryan/materia@sha256:") && len(c.Image) == len("ghcr.io/stryan/materia@sha256:")+64 && !ok
			})
		}},
		{"a firmware update with release notes", func(l lab) bool {
			return l.anySoftware(func(_ report.System, sw report.Software) bool {
				return sw.Kind == "firmware" && sw.UpdateAvailable && sw.Latest != sw.Installed && strings.HasPrefix(sw.URL, "https://")
			})
		}},
		{"firmware that is current", func(l lab) bool {
			return l.anySoftware(func(_ report.System, sw report.Software) bool {
				return sw.Kind == "firmware" && !sw.UpdateAvailable && sw.Latest == sw.Installed
			})
		}},
		{"a Home Assistant app update", func(l lab) bool {
			return l.anySoftware(func(sys report.System, sw report.Software) bool {
				return sys.Kind == "homeassistant" && sw.Kind == "app" && sw.UpdateAvailable
			})
		}},
		{"a Home Assistant core update", func(l lab) bool {
			return l.anySoftware(func(sys report.System, sw report.Software) bool {
				return sys.Kind == "homeassistant" && sw.Kind == "core" && sw.UpdateAvailable
			})
		}},
		{"a backup that is fine", func(l lab) bool {
			return l.anyBackup(func(b report.Backup, age, allowed time.Duration) bool {
				return b.LastResult == "ok" && !b.LastSuccess.IsZero() && age <= allowed
			})
		}},
		{"a backup that is late", func(l lab) bool {
			return l.anyBackup(func(b report.Backup, age, allowed time.Duration) bool {
				return b.LastResult == "ok" && !b.LastSuccess.IsZero() && age > allowed
			})
		}},
		{"a backup that failed", func(l lab) bool {
			return l.anyBackup(func(b report.Backup, _, _ time.Duration) bool {
				return b.LastResult == "failed" && b.Detail != "" && b.LastRun.After(b.LastSuccess)
			})
		}},
		{"a backup that is running", func(l lab) bool {
			return l.anyBackup(func(b report.Backup, age, allowed time.Duration) bool {
				return b.LastResult == "running" && age <= allowed
			})
		}},
		{"a backup that never ran", func(l lab) bool {
			return l.anyBackup(func(b report.Backup, _, _ time.Duration) bool { return b.LastSuccess.IsZero() && b.LastRun.IsZero() })
		}},
		{"a backup with its own allowed age", func(l lab) bool {
			return l.anyBackup(func(b report.Backup, _, _ time.Duration) bool { return b.MaxAgeHours > 0 })
		}},
		{"a system that has gone silent", func(l lab) bool {
			return l.anySystem(func(st model.SystemState) bool { return l.now.Sub(st.ReceivedAt) > l.policy.SilentAfter })
		}},
		{"a collector problem", func(l lab) bool {
			return l.anySystem(func(st model.SystemState) bool {
				return len(st.Report.Errors) > 0 && st.Report.Errors[0].Collector != "" && st.Report.Errors[0].Message != ""
			})
		}},
		{"a system with nothing to do", func(l lab) bool {
			return l.anySystem(func(st model.SystemState) bool {
				r := st.Report
				if r.Packages != nil || len(r.Containers) > 0 || len(r.Errors) > 0 || l.now.Sub(st.ReceivedAt) > l.policy.SilentAfter {
					return false
				}
				for _, sw := range r.Software {
					if sw.UpdateAvailable {
						return false
					}
				}
				return len(r.Software) > 0
			})
		}},
		{"a system that reports through an agent", func(l lab) bool {
			return l.anySystem(func(st model.SystemState) bool {
				return st.Report.System.Source == "agent" && st.Report.System.AgentVersion != ""
			})
		}},
		{"a system that is asked through a connector", func(l lab) bool {
			return l.anySystem(func(st model.SystemState) bool { return st.Report.System.Source == "connector" })
		}},
	}

	nows := []time.Time{
		time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC),
		time.Date(2027, 2, 28, 23, 59, 59, 0, time.FixedZone("CET", 3600)),
	}
	for _, now := range nows {
		l := fill(t, now)
		for _, s := range shows {
			t.Run(s.name+" at "+now.Format("2006-01-02"), func(t *testing.T) {
				if !s.in(l) {
					t.Errorf("the demo does not show %s", s.name)
				}
			})
		}
	}
}

// TestFillIsCoherent checks the demo against the rules a real report follows, so that it never
// shows the dashboard something a real source could not send.
func TestFillIsCoherent(t *testing.T) {
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	l := fill(t, now)

	var names []string
	inUse := map[string]bool{}
	for _, st := range l.states {
		r := st.Report
		name := r.System.Name
		names = append(names, name)
		if err := r.Validate(); err != nil {
			t.Errorf("%s: a server would refuse this report: %v", name, err)
		}
		if r.Schema != report.Schema {
			t.Errorf("%s: schema %d, want %d", name, r.Schema, report.Schema)
		}
		if r.Sent.IsZero() || r.Sent.After(st.ReceivedAt) || st.ReceivedAt.After(now) {
			t.Errorf("%s: sent %v, received %v, now %v are out of order", name, r.Sent, st.ReceivedAt, now)
		}
		if p := r.Packages; p != nil {
			security := 0
			for _, it := range p.Items {
				if it.Name == "" || it.Installed == "" || it.Candidate == "" || it.Installed == it.Candidate {
					t.Errorf("%s: package %+v is not an update", name, it)
				}
				if it.Security {
					security++
				}
			}
			if len(p.Items) != p.Pending || security != p.Security || p.Pending > report.MaxItems {
				t.Errorf("%s: %d pending and %d security, but %d and %d listed", name, p.Pending, p.Security, len(p.Items), security)
			}
			if p.RebootRequired != (p.RebootReason != "") {
				t.Errorf("%s: reboot %v with the reason %q", name, p.RebootRequired, p.RebootReason)
			}
			if p.ListsUpdated.IsZero() || p.ListsUpdated.After(now) {
				t.Errorf("%s: package lists updated at %v", name, p.ListsUpdated)
			}
		}
		seen := map[string]bool{}
		for _, c := range r.Containers {
			inUse[c.Image] = true
			if seen[c.Name] {
				t.Errorf("%s: two containers are called %s", name, c.Name)
			}
			seen[c.Name] = true
			if !strings.HasPrefix(c.Digest, "sha256:") || len(c.Digest) != len("sha256:")+64 || len(c.ImageID) != 64 {
				t.Errorf("%s/%s: digest %q or image id %q is not well-formed", name, c.Name, c.Digest, c.ImageID)
			}
			if c.State != "running" || c.Runtime != "podman" || c.StartedAt.IsZero() || c.StartedAt.After(st.ReceivedAt) {
				t.Errorf("%s/%s: state %q, runtime %q, started %v", name, c.Name, c.State, c.Runtime, c.StartedAt)
			}
		}
		for _, b := range r.Backups {
			if b.Name == "" || b.Kind == "" || b.LastResult == "" {
				t.Errorf("%s: backup %+v lacks a name, kind or result", name, b)
			}
			if b.LastSuccess.After(now) || b.LastRun.After(now) || b.LastSuccess.After(b.LastRun) && !b.LastRun.IsZero() {
				t.Errorf("%s/%s: last success %v and last run %v are out of order", name, b.Name, b.LastSuccess, b.LastRun)
			}
		}
		for _, sw := range r.Software {
			if sw.Name == "" || sw.Kind == "" || sw.Installed == "" || sw.UpdateAvailable != (sw.Latest != sw.Installed) {
				t.Errorf("%s: software %+v contradicts itself", name, sw)
			}
		}
	}

	want := "dns02 homeassistant opnsense opnsense02 ops01 server storage"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("systems = %q, want %q", got, want)
	}

	// The checks match the images: each check is about an image in use, and one image has none.
	unchecked := 0
	for image := range inUse {
		if _, ok := l.checks[image]; !ok {
			unchecked++
		}
	}
	// A local image, one pinned by digest, and one that was not asked about yet.
	if unchecked != 3 {
		t.Errorf("%d images in use have no check, want three", unchecked)
	}
	for image, check := range l.checks {
		if !inUse[image] {
			t.Errorf("a check for %s, which no container runs", image)
		}
		if check.Image != image || check.CheckedAt.IsZero() || check.CheckedAt.After(now) {
			t.Errorf("check of %s: image %q, checked at %v", image, check.Image, check.CheckedAt)
		}
		if check.Tag != "" && !strings.HasSuffix(image, ":"+check.Tag) {
			t.Errorf("check of %s names the tag %q", image, check.Tag)
		}
	}
}

func TestFillTwice(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	for range 2 {
		if err := Fill(ctx, s, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	states, _ := s.Systems(ctx)
	checks, _ := s.ImageChecks(ctx)
	if len(states) != 7 || len(checks) != 12 {
		t.Errorf("after filling twice: %d systems and %d checks, want 7 and 12", len(states), len(checks))
	}
}

// failing is a store that cannot write, to see what Fill says about it.
type failing struct {
	store.Store
	reports, checks error
}

func (f failing) SaveReport(ctx context.Context, r *report.Report, at time.Time) error {
	if f.reports != nil {
		return f.reports
	}
	return f.Store.SaveReport(ctx, r, at)
}

func (f failing) SaveImageCheck(context.Context, model.ImageCheck) error { return f.checks }

func TestFillReportsStoreErrors(t *testing.T) {
	full := errors.New("disk full")
	tests := []struct {
		name  string
		store store.Store
		want  string
	}{
		{"a report cannot be saved", failing{Store: store.NewMemory(), reports: full}, "save the demo report of server"},
		{"a check cannot be saved", failing{Store: store.NewMemory(), checks: full}, "save the demo check of docker.io/gitea/gitea:1.23.6"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Fill(context.Background(), tc.store, time.Now())
			if !errors.Is(err, full) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Fill = %v, want an error that wraps %q and says %q", err, full, tc.want)
			}
		})
	}
}
