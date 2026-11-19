package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
)

// One suite, run against every Store: whatever the dashboard sees with the in-memory store in
// its tests, a server on SQLite must show too.

var arrived = time.Date(2026, 11, 19, 6, 30, 15, 123456789, time.UTC)

// fullReport sets every field of the format, so that a store that drops one is caught.
func fullReport(name string) *report.Report {
	return &report.Report{
		Schema: report.Schema,
		System: report.System{
			Name: name, Kind: "linux", OS: "Debian GNU/Linux 13 (trixie)", OSVersion: "13.7",
			Kernel: "6.12.117+deb13-amd64", Arch: "amd64", Source: "agent", AgentVersion: "0.1.0 linux/amd64",
		},
		Sent: time.Date(2026, 11, 19, 7, 30, 14, 0, time.FixedZone("CET", 3600)),
		Packages: &report.Packages{
			Manager: "apt", Pending: 2, Security: 1,
			Items: []report.PackageUpdate{
				{Name: "openssl", Installed: "3.5.4-1~deb13u1", Candidate: "3.5.4-1~deb13u2", Security: true},
				{Name: "tzdata", Installed: "2026a-0+deb13u1", Candidate: "2026b-0+deb13u1"},
			},
			RebootRequired: true, RebootReason: "kernel 6.12.107 running, 6.12.117 installed",
			ListsUpdated: time.Date(2026, 11, 19, 5, 12, 0, 0, time.UTC),
		},
		Software: []report.Software{{
			Name: "OPNsense", Kind: "firmware", Installed: "26.10.1", Latest: "26.10.2", UpdateAvailable: true,
			URL: "https://docs.opnsense.org/releases.html", Detail: "needs a reboot",
		}},
		Containers: []report.Container{{
			Name: "gitea", Image: "docker.io/gitea/gitea:1.23.6", ImageID: "0c1d2e3f4a5b",
			Digest: "sha256:1f3c5a7e9b2d4f6081a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7", State: "running",
			StartedAt: time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC), AutoUpdate: "registry", Runtime: "podman",
		}},
		Backups: []report.Backup{{
			Name: "restic-backup", Kind: "restic", LastSuccess: time.Date(2026, 11, 19, 2, 14, 0, 0, time.UTC),
			LastRun: time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC), LastResult: "ok", MaxAgeHours: 26,
			Detail: "snapshot 1a2b3c4d, 41 GiB",
		}},
		Errors: []report.Problem{{Collector: "containers", Message: "podman ps: exit status 125"}},
	}
}

func smallReport(name string) *report.Report {
	return &report.Report{Schema: report.Schema, System: report.System{Name: name, Kind: "linux", Source: "agent"}, Sent: arrived}
}

// sameReport compares what the stores promise to keep: the report as its JSON.
func sameReport(t *testing.T, got report.Report, want *report.Report) {
	t.Helper()
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(g) != string(w) {
		t.Errorf("stored report differs\n got: %s\nwant: %s", g, w)
	}
}

func names(states []model.SystemState) []string {
	out := []string{}
	for _, s := range states {
		out = append(out, s.Report.System.Name)
	}
	return out
}

var storeSuite = []struct {
	name string
	run  func(t *testing.T, ctx context.Context, s Store)
}{
	{"an empty store has nothing and says so", func(t *testing.T, ctx context.Context, s Store) {
		systems, err := s.Systems(ctx)
		if err != nil || len(systems) != 0 {
			t.Errorf("Systems = %v, %v; want none", systems, err)
		}
		if _, err := s.System(ctx, "server"); !errors.Is(err, ErrNotFound) {
			t.Errorf("System of nobody: err = %v, want ErrNotFound", err)
		}
		checks, err := s.ImageChecks(ctx)
		if err != nil || checks == nil || len(checks) != 0 {
			t.Errorf("ImageChecks = %v, %v; want an empty map", checks, err)
		}
		if err := s.DeleteSystem(ctx, "server"); err != nil {
			t.Errorf("deleting a system nobody reported: %v", err)
		}
	}},
	{"a report comes back whole, with its arrival time", func(t *testing.T, ctx context.Context, s Store) {
		want := fullReport("server")
		if err := s.SaveReport(ctx, want, arrived); err != nil {
			t.Fatal(err)
		}
		got, err := s.System(ctx, "server")
		if err != nil {
			t.Fatal(err)
		}
		sameReport(t, got.Report, want)
		if !got.ReceivedAt.Equal(arrived) {
			t.Errorf("ReceivedAt = %v, want %v", got.ReceivedAt, arrived)
		}
		all, err := s.Systems(ctx)
		if err != nil || len(all) != 1 {
			t.Fatalf("Systems = %d systems, %v; want 1", len(all), err)
		}
		sameReport(t, all[0].Report, want)
		if !all[0].ReceivedAt.Equal(arrived) {
			t.Errorf("Systems: ReceivedAt = %v, want %v", all[0].ReceivedAt, arrived)
		}
	}},
	{"a later report replaces the earlier one", func(t *testing.T, ctx context.Context, s Store) {
		if err := s.SaveReport(ctx, fullReport("server"), arrived); err != nil {
			t.Fatal(err)
		}
		later := smallReport("server")
		later.System.OSVersion = "13.8"
		if err := s.SaveReport(ctx, later, arrived.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		all, err := s.Systems(ctx)
		if err != nil || len(all) != 1 {
			t.Fatalf("Systems = %d systems, %v; want 1", len(all), err)
		}
		sameReport(t, all[0].Report, later)
		if !all[0].ReceivedAt.Equal(arrived.Add(time.Hour)) {
			t.Errorf("ReceivedAt = %v, want an hour later", all[0].ReceivedAt)
		}
	}},
	{"systems are sorted by name", func(t *testing.T, ctx context.Context, s Store) {
		// Byte order, as Go compares strings: upper case first, "ž" after ASCII.
		for _, n := range []string{"pi", "opnsense02", "žaba", "Server", "opnsense01", "homeassistant"} {
			if err := s.SaveReport(ctx, smallReport(n), arrived); err != nil {
				t.Fatal(err)
			}
		}
		all, err := s.Systems(ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"Server", "homeassistant", "opnsense01", "opnsense02", "pi", "žaba"}
		if fmt.Sprint(names(all)) != fmt.Sprint(want) {
			t.Errorf("order = %v, want %v", names(all), want)
		}
	}},
	{"a name is only ever a name", func(t *testing.T, ctx context.Context, s Store) {
		odd := []string{`x'; DROP TABLE systems; --`, `a "quoted" name`, "%", "tab\there", "システム"}
		for _, n := range odd {
			if err := s.SaveReport(ctx, smallReport(n), arrived); err != nil {
				t.Fatalf("saving %q: %v", n, err)
			}
		}
		for _, n := range odd {
			got, err := s.System(ctx, n)
			if err != nil || got.Report.System.Name != n {
				t.Errorf("System(%q) = %q, %v", n, got.Report.System.Name, err)
			}
		}
		if all, err := s.Systems(ctx); err != nil || len(all) != len(odd) {
			t.Errorf("Systems = %d systems, %v; want %d", len(all), err, len(odd))
		}
	}},
	{"deleting forgets one system and no other", func(t *testing.T, ctx context.Context, s Store) {
		for _, n := range []string{"pi", "server"} {
			if err := s.SaveReport(ctx, smallReport(n), arrived); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.DeleteSystem(ctx, "pi"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.System(ctx, "pi"); !errors.Is(err, ErrNotFound) {
			t.Errorf("after deleting: err = %v, want ErrNotFound", err)
		}
		all, err := s.Systems(ctx)
		if err != nil || fmt.Sprint(names(all)) != "[server]" {
			t.Errorf("Systems = %v, %v; want [server]", names(all), err)
		}
	}},
	{"image checks are kept by image and replaced", func(t *testing.T, ctx context.Context, s Store) {
		gitea := model.ImageCheck{
			Image: "docker.io/gitea/gitea:1.23.6", Tag: "1.23.6",
			TagDigest:  "sha256:9a8b7c6d5e4f30211a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a8b",
			NewerPatch: "1.23.8", NewerMinor: "1.25.2", NewerMajor: "2.0.1", CheckedAt: arrived,
		}
		failed := model.ImageCheck{Image: "lscr.io/linuxserver/unifi-network-application:10.0.162-ls114", Error: "asking lscr.io: 503"}
		for _, c := range []model.ImageCheck{gitea, failed} {
			if err := s.SaveImageCheck(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		// Replaced in every field, also by an empty one.
		gitea = model.ImageCheck{
			Image: gitea.Image, Tag: "1.23", TagDigest: "sha256:" + strings.Repeat("0", 64),
			NewerPatch: "1.23.9", NewerMinor: "1.26.0", NewerMajor: "", CheckedAt: arrived.Add(6 * time.Hour),
			Error: "listing the tags of gitea/gitea: timeout",
			Note:  "only the first 10000 tags of docker.io/gitea/gitea were read, newer ones may be missing",
		}
		if err := s.SaveImageCheck(ctx, gitea); err != nil {
			t.Fatal(err)
		}
		checks, err := s.ImageChecks(ctx)
		if err != nil || len(checks) != 2 {
			t.Fatalf("ImageChecks = %d checks, %v; want 2", len(checks), err)
		}
		for _, want := range []model.ImageCheck{gitea, failed} {
			got := checks[want.Image]
			if !got.CheckedAt.Equal(want.CheckedAt) || got.CheckedAt.IsZero() != want.CheckedAt.IsZero() {
				t.Errorf("%s: CheckedAt = %v, want %v", want.Image, got.CheckedAt, want.CheckedAt)
			}
			got.CheckedAt, want.CheckedAt = time.Time{}, time.Time{}
			if got != want {
				t.Errorf("check differs\n got: %+v\nwant: %+v", got, want)
			}
		}
		// The map is the caller's: changing it must not change the store.
		delete(checks, gitea.Image)
		if again, _ := s.ImageChecks(ctx); len(again) != 2 {
			t.Errorf("the returned map is the store's own: %d checks left", len(again))
		}
	}},
	{"deleting forgets one image check and no other", func(t *testing.T, ctx context.Context, s Store) {
		for _, image := range []string{"docker.io/library/mongo:7.0.48", "docker.io/gitea/gitea:1.23.6"} {
			if err := s.SaveImageCheck(ctx, model.ImageCheck{Image: image, CheckedAt: arrived}); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.DeleteImageCheck(ctx, "docker.io/library/mongo:7.0.48"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteImageCheck(ctx, "docker.io/nobody/asked:1"); err != nil {
			t.Errorf("deleting a check that is not there: %v", err)
		}
		checks, err := s.ImageChecks(ctx)
		if _, left := checks["docker.io/gitea/gitea:1.23.6"]; err != nil || len(checks) != 1 || !left {
			t.Errorf("ImageChecks = %v, %v; want only gitea's", checks, err)
		}
	}},
	{"many writers and readers at once", func(t *testing.T, ctx context.Context, s Store) {
		var wg sync.WaitGroup
		errs := make(chan error, 200)
		for i := range 20 {
			wg.Go(func() {
				name := fmt.Sprintf("host%02d", i%5) // several writers per system
				for j := range 5 {
					if err := s.SaveReport(ctx, smallReport(name), arrived.Add(time.Duration(j)*time.Second)); err != nil {
						errs <- err
					}
					if err := s.SaveImageCheck(ctx, model.ImageCheck{Image: "docker.io/library/mongo:7.0." + fmt.Sprint(i)}); err != nil {
						errs <- err
					}
					if _, err := s.Systems(ctx); err != nil {
						errs <- err
					}
					if _, err := s.ImageChecks(ctx); err != nil {
						errs <- err
					}
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		all, err := s.Systems(ctx)
		if err != nil || len(all) != 5 {
			t.Errorf("Systems = %d systems, %v; want 5", len(all), err)
		}
		checks, err := s.ImageChecks(ctx)
		if err != nil || len(checks) != 20 {
			t.Errorf("ImageChecks = %d checks, %v; want 20", len(checks), err)
		}
	}},
}

func openTestSQLite(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "upkeep.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStore(t *testing.T) {
	stores := []struct {
		name string
		open func(t *testing.T) Store
	}{
		{"memory", func(*testing.T) Store { return NewMemory() }},
		{"sqlite", func(t *testing.T) Store { return openTestSQLite(t) }},
	}
	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			for _, tc := range storeSuite {
				t.Run(tc.name, func(t *testing.T) {
					s := st.open(t)
					defer s.Close()
					tc.run(t, t.Context(), s)
				})
			}
		})
	}
}

func TestKeyValue(t *testing.T) {
	stores := []struct {
		name string
		open func(t *testing.T) KeyValue
	}{
		{"memory", func(*testing.T) KeyValue { return NewMemoryValues() }},
		{"sqlite", func(t *testing.T) KeyValue { return openTestSQLite(t) }},
	}
	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			kv, ctx := st.open(t), t.Context()
			if v, err := kv.Value(ctx, "mail.sent"); v != "" || err != nil {
				t.Errorf("a value never set = %q, %v; want empty", v, err)
			}
			steps := []struct{ key, set, want string }{
				{"mail.sent", "2026-11-19T07:00:00Z", "2026-11-19T07:00:00Z"},
				{"mail.fingerprint", "abc", "abc"},
				{"mail.sent", "2026-11-20T07:00:00Z", "2026-11-20T07:00:00Z"},
				{"mail.fingerprint", "", ""},
				{"odd ' key %", "ž\n", "ž\n"},
			}
			for _, step := range steps {
				if err := kv.SetValue(ctx, step.key, step.set); err != nil {
					t.Fatal(err)
				}
				if v, err := kv.Value(ctx, step.key); v != step.want || err != nil {
					t.Errorf("Value(%q) = %q, %v; want %q", step.key, v, err, step.want)
				}
			}
			if v, _ := kv.Value(ctx, "mail.sent"); v != "2026-11-20T07:00:00Z" {
				t.Errorf("setting another key changed mail.sent to %q", v)
			}
		})
	}
}

func TestValuesOf(t *testing.T) {
	sq := openTestSQLite(t)
	if kv := ValuesOf(sq); kv != KeyValue(sq) {
		t.Error("the SQLite store keeps values itself and must be used for them")
	}
	if _, ok := ValuesOf(NewMemory()).(*MemoryValues); !ok {
		t.Error("the in-memory store needs a MemoryValues beside it")
	}
}
