package model

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// The inputs below are written by hand, not captured: Findings only sees reports, and these
// use the images, units and versions of the homelab upkeep was written for.

var now = time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

const (
	digestOld = "sha256:1f3c5a7e9b2d4f6081a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7"
	digestNew = "sha256:9a8b7c6d5e4f30211a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a8b"
)

// state builds a system that reported five minutes ago and is otherwise healthy.
func state(name string, change func(*report.Report)) SystemState {
	r := report.Report{
		Schema: report.Schema,
		System: report.System{Name: name, Kind: "linux", Source: "agent"},
		Sent:   now.Add(-5 * time.Minute),
	}
	if change != nil {
		change(&r)
	}
	return SystemState{Report: r, ReceivedAt: now.Add(-5 * time.Minute)}
}

func ago(d time.Duration) time.Time { return now.Add(-d) }

func TestFindings(t *testing.T) {
	gitea := "docker.io/gitea/gitea:1.23.6"
	adguard := "docker.io/adguard/adguardhome:latest"
	tests := []struct {
		name   string
		states []SystemState
		checks map[string]ImageCheck
		policy *Policy
		want   []Finding
	}{
		{
			name:   "nothing reported, nothing found",
			states: []SystemState{state("server", nil)},
		},
		{
			name: "a healthy system",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Packages = &report.Packages{Manager: "apt", ListsUpdated: ago(2 * time.Hour)}
				r.Containers = []report.Container{{Name: "gitea", Image: gitea, Digest: digestOld}}
				r.Software = []report.Software{{Name: "OPNsense", Installed: "26.10.1", Latest: "26.10.1"}}
				r.Backups = []report.Backup{{Name: "restic-backup", LastSuccess: ago(6 * time.Hour), LastRun: ago(6 * time.Hour), LastResult: "ok"}}
			})},
			checks: map[string]ImageCheck{gitea: {Image: gitea, Tag: "1.23.6", TagDigest: digestOld, CheckedAt: ago(time.Hour)}},
		},
		{
			name: "pending packages are info",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Packages = &report.Packages{Manager: "apt", Pending: 12, Items: []report.PackageUpdate{
					{Name: "bash"}, {Name: "curl"}, {Name: "libcurl4t64"}, {Name: "tzdata"}, {Name: "vim-common"},
					{Name: "vim-tiny"}, {Name: "xxd"}, {Name: "base-files"}, {Name: "libc6"}, {Name: "libc-bin"},
					{Name: "locales"}, {Name: "systemd"},
				}}
			})},
			want: []Finding{{"server", CategoryOS, Info, "12 package updates",
				"bash, curl, libcurl4t64, tzdata, vim-common, vim-tiny, xxd, base-files and 4 more"}},
		},
		{
			name: "one package, no list",
			states: []SystemState{state("pi", func(r *report.Report) {
				r.Packages = &report.Packages{Manager: "apt", Pending: 1}
			})},
			want: []Finding{{"pi", CategoryOS, Info, "1 package update", ""}},
		},
		{
			name: "a security update makes it a warning and is named first",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Packages = &report.Packages{Manager: "apt", Pending: 12, Security: 3, Items: []report.PackageUpdate{
					{Name: "bash"}, {Name: "openssl", Security: true}, {Name: "curl"}, {Name: "libssl3t64", Security: true},
					{Name: "linux-image-amd64", Security: true}, {Name: "tzdata"},
				}}
			})},
			want: []Finding{{"server", CategoryOS, Warn, "12 package updates, 3 security",
				"security: openssl, libssl3t64, linux-image-amd64; also bash, curl, tzdata and 6 more"}},
		},
		{
			name: "security is counted from the list when the count is missing",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Packages = &report.Packages{Manager: "pkg", Items: []report.PackageUpdate{{Name: "openssl", Security: true}, {Name: "curl", Security: true}}}
			})},
			want: []Finding{{"server", CategoryOS, Warn, "2 package updates, 2 security", "security: openssl, curl"}},
		},
		{
			name: "a waiting reboot is a warning",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Packages = &report.Packages{Manager: "apt", RebootRequired: true, RebootReason: "kernel 6.12.107 running, 6.12.117 installed"}
			})},
			want: []Finding{{"server", CategoryReboot, Warn, "reboot required", "kernel 6.12.107 running, 6.12.117 installed"}},
		},
		{
			name: "package lists older than three days are a warning",
			states: []SystemState{
				state("fresh", func(r *report.Report) {
					r.Packages = &report.Packages{Manager: "apt", ListsUpdated: ago(72 * time.Hour)}
				}),
				state("old", func(r *report.Report) {
					r.Packages = &report.Packages{Manager: "apt", ListsUpdated: ago(5*24*time.Hour + time.Hour)}
				}),
				state("unknown", func(r *report.Report) { r.Packages = &report.Packages{Manager: "apt"} }),
			},
			want: []Finding{{"old", CategoryOS, Warn, "package lists not refreshed since 2026-11-14",
				"5 days ago (apt); newer updates may exist that are not counted here"}},
		},
		{
			name: "a rebuilt tag is info and tells what to do",
			states: []SystemState{state("ops01", func(r *report.Report) {
				r.Containers = []report.Container{{Name: "adguardhome", Image: adguard, Digest: digestOld}}
			})},
			checks: map[string]ImageCheck{adguard: {Image: adguard, Tag: "latest", TagDigest: digestNew}},
			want: []Finding{{"ops01", CategoryContainer, Info, "adguardhome: tag latest was rebuilt",
				adguard + " is now sha256:9a8b7c6d5e4f, the container runs sha256:1f3c5a7e9b2d; pull the image and restart the container"}},
		},
		{
			name: "a rebuilt tag says when the container updates itself",
			states: []SystemState{state("ops01", func(r *report.Report) {
				r.Containers = []report.Container{{Name: "adguardhome", Image: adguard, Digest: digestOld, AutoUpdate: "registry"}}
			})},
			checks: map[string]ImageCheck{adguard: {Image: adguard, Tag: "latest", TagDigest: digestNew}},
			want: []Finding{{"ops01", CategoryContainer, Info, "adguardhome: tag latest was rebuilt",
				adguard + " is now sha256:9a8b7c6d5e4f, the container runs sha256:1f3c5a7e9b2d; it updates itself (auto-update registry)"}},
		},
		{
			name: "a digest that is not known on one side says nothing",
			states: []SystemState{state("ops01", func(r *report.Report) {
				r.Containers = []report.Container{
					{Name: "no-local-digest", Image: adguard},
					{Name: "no-registry-digest", Image: gitea, Digest: digestOld},
					{Name: "same", Image: "docker.io/library/mongo:7.0.48", Digest: strings.ToUpper(digestOld)},
				}
			})},
			checks: map[string]ImageCheck{
				adguard:                          {Image: adguard, Tag: "latest", TagDigest: digestNew},
				gitea:                            {Image: gitea, Tag: "1.23.6"},
				"docker.io/library/mongo:7.0.48": {Image: "docker.io/library/mongo:7.0.48", Tag: "7.0.48", TagDigest: digestOld},
			},
		},
		{
			name: "newer tags give one finding per container, the smallest step first",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Containers = []report.Container{
					{Name: "gitea", Image: gitea},
					{Name: "mariadb", Image: "docker.io/library/mariadb:11.4.13"},
					{Name: "uptime-kuma", Image: "docker.io/louislam/uptime-kuma:2"},
				}
			})},
			checks: map[string]ImageCheck{
				gitea:                               {Image: gitea, Tag: "1.23.6", NewerPatch: "1.23.8", NewerMinor: "1.25.2", NewerMajor: "2.0.1"},
				"docker.io/library/mariadb:11.4.13": {Image: "docker.io/library/mariadb:11.4.13", Tag: "11.4.13", NewerMinor: "11.8.9", NewerMajor: "12.1.2"},
				"docker.io/louislam/uptime-kuma:2":  {Image: "docker.io/louislam/uptime-kuma:2", Tag: "2", NewerMajor: "3"},
			},
			want: []Finding{
				{"server", CategoryContainer, Info, "gitea: 1.23.8 available", "patch update of " + gitea + "; also 1.25.2 (minor), 2.0.1 (major)"},
				{"server", CategoryContainer, Info, "mariadb: 11.8.9 available", "minor update of docker.io/library/mariadb:11.4.13; also 12.1.2 (major)"},
				{"server", CategoryContainer, Info, "uptime-kuma: 3 available", "major update of docker.io/louislam/uptime-kuma:2"},
			},
		},
		{
			name: "images nobody checked say nothing",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Containers = []report.Container{
					{Name: "materia", Image: "ghcr.io/stryan/materia@" + digestOld, Digest: digestOld},
					{Name: "medimorec", Image: "localhost/medimorec-server:current"},
				}
			})},
			checks: map[string]ImageCheck{gitea: {Image: gitea, Tag: "1.23.6", NewerPatch: "1.23.8"}},
		},
		{
			name: "a registry error is info, once per system, and keeps what was known",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Containers = []report.Container{
					{Name: "gitea", Image: gitea},
					{Name: "gitea-staging", Image: gitea},
					{Name: "adguardhome", Image: adguard},
				}
			})},
			checks: map[string]ImageCheck{
				gitea:   {Image: gitea, Tag: "1.23.6", NewerPatch: "1.23.8", Error: "asking registry-1.docker.io for tags:\n 429 Too Many Requests"},
				adguard: {Image: adguard, Error: "asking registry-1.docker.io: timeout"},
			},
			want: []Finding{
				{"server", CategoryContainer, Info, "2 images could not be checked", gitea + ": asking registry-1.docker.io for tags: 429 Too Many Requests (and 1 more)"},
				{"server", CategoryContainer, Info, "gitea-staging: 1.23.8 available", "patch update of " + gitea},
				{"server", CategoryContainer, Info, "gitea: 1.23.8 available", "patch update of " + gitea},
			},
		},
		{
			name: "software with an update is info",
			states: []SystemState{
				state("opnsense01", func(r *report.Report) {
					r.Software = []report.Software{
						{Name: "OPNsense", Kind: "firmware", Installed: "26.10.1", Latest: "26.10.2", UpdateAvailable: true, Detail: "12 packages, needs a reboot"},
						{Name: "os-wireguard", Kind: "plugin", Installed: "2.9", Latest: "2.9"},
					}
				}),
				state("homeassistant", func(r *report.Report) {
					r.Software = []report.Software{
						{Name: "Home Assistant Core", Kind: "core", Installed: "2026.11.1", Latest: "2026.11.3", UpdateAvailable: true, URL: "https://www.home-assistant.io/blog/categories/core/"},
						{Name: "Zigbee2MQTT", Kind: "app", UpdateAvailable: true},
					}
				}),
			},
			want: []Finding{
				{"homeassistant", CategorySoftware, Info, "Home Assistant Core 2026.11.3 available", "installed 2026.11.1; https://www.home-assistant.io/blog/categories/core/"},
				{"homeassistant", CategorySoftware, Info, "Zigbee2MQTT update available", ""},
				{"opnsense01", CategorySoftware, Info, "OPNsense 26.10.2 available", "installed 26.10.1; 12 packages, needs a reboot"},
			},
		},
		{
			name: "a failed backup is critical",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Backups = []report.Backup{
					{Name: "restic-backup", Kind: "restic", LastSuccess: ago(30 * time.Hour), LastRun: ago(6 * time.Hour), LastResult: "failed", Detail: "exit-code 3"},
					{Name: "restic-offsite", Kind: "restic", LastRun: ago(6 * time.Hour), LastResult: "failed"},
				}
			})},
			want: []Finding{
				{"server", CategoryBackup, Crit, "backup restic-backup failed", "last run 2026-11-19 02:00 UTC; exit-code 3; last success 2026-11-18 02:00 UTC"},
				{"server", CategoryBackup, Crit, "backup restic-offsite failed", "last run 2026-11-19 02:00 UTC; no successful run is known"},
			},
		},
		{
			name: "a backup older than its allowed age is a warning, at twice that critical",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Backups = []report.Backup{
					{Name: "at-the-limit", LastSuccess: ago(26 * time.Hour), LastResult: "ok"},
					{Name: "stale", LastSuccess: ago(30 * time.Hour), LastResult: "ok"},
					{Name: "very-stale", LastSuccess: ago(53 * time.Hour), LastResult: "unknown"},
					{Name: "weekly-fine", LastSuccess: ago(5 * 24 * time.Hour), LastResult: "ok", MaxAgeHours: 192},
					{Name: "weekly-stale", LastSuccess: ago(9 * 24 * time.Hour), LastResult: "ok", MaxAgeHours: 192},
				}
			})},
			want: []Finding{
				{"server", CategoryBackup, Crit, "backup very-stale last succeeded 2026-11-17", "2 days ago, at 03:00 UTC; allowed age is 26 hours"},
				{"server", CategoryBackup, Warn, "backup stale last succeeded 2026-11-18", "30 hours ago, at 02:00 UTC; allowed age is 26 hours"},
				{"server", CategoryBackup, Warn, "backup weekly-stale last succeeded 2026-11-10", "9 days ago, at 08:00 UTC; allowed age is 8 days"},
			},
		},
		{
			name: "a backup that never succeeded is a warning",
			states: []SystemState{state("pi", func(r *report.Report) {
				r.Backups = []report.Backup{
					{Name: "restic-backup", Kind: "systemd", LastResult: "unknown", Detail: "the unit never ran"},
					{Name: "homeassistant automatic backup", Kind: "homeassistant"},
				}
			})},
			want: []Finding{
				{"pi", CategoryBackup, Warn, "backup homeassistant automatic backup never succeeded", "no successful run is known"},
				{"pi", CategoryBackup, Warn, "backup restic-backup never succeeded", "the unit never ran"},
			},
		},
		{
			name: "a running backup is nothing, unless it has been failing to finish for twice its age",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Backups = []report.Backup{
					{Name: "first-run", LastRun: ago(time.Minute), LastResult: "running"},
					{Name: "long-run", LastSuccess: ago(30 * time.Hour), LastRun: ago(4 * time.Hour), LastResult: "running"},
					{Name: "hung", LastSuccess: ago(4 * 24 * time.Hour), LastRun: ago(3 * 24 * time.Hour), LastResult: "running"},
				}
			})},
			want: []Finding{{"server", CategoryBackup, Crit, "backup hung last succeeded 2026-11-15",
				"4 days ago, at 08:00 UTC; allowed age is 26 hours; a run is in progress"}},
		},
		{
			name: "a backup that says ok but only knows its last run is judged by that",
			states: []SystemState{state("server", func(r *report.Report) {
				r.Backups = []report.Backup{
					{Name: "recent", LastRun: ago(2 * time.Hour), LastResult: "ok"},
					{Name: "old", LastRun: ago(40 * time.Hour), LastResult: "ok"},
					{Name: "no-times", LastResult: "ok"},
				}
			})},
			want: []Finding{{"server", CategoryBackup, Warn, "backup old last succeeded 2026-11-17", "40 hours ago, at 16:00 UTC; allowed age is 26 hours"}},
		},
		{
			name: "a silent source is critical, and what it said last still counts",
			states: []SystemState{
				{Report: state("server", nil).Report, ReceivedAt: ago(2 * time.Hour)},
				{Report: state("pi", func(r *report.Report) {
					r.Packages = &report.Packages{Manager: "apt", Pending: 2}
				}).Report, ReceivedAt: ago(5*time.Hour + 10*time.Minute)},
				{Report: state("opnsense01", func(r *report.Report) { r.System.Source = "connector" }).Report, ReceivedAt: ago(3 * 24 * time.Hour)},
			},
			want: []Finding{
				{"opnsense01", CategorySource, Crit, "no report since 2026-11-16 08:00 UTC", "silent for 3 days; the connector should report at least every 2 hours"},
				{"pi", CategorySource, Crit, "no report since 2026-11-19 02:50 UTC", "silent for 5 hours; the agent should report at least every 2 hours"},
				{"pi", CategoryOS, Info, "2 package updates", ""},
			},
		},
		{
			name:   "silence is not judged when the policy turns it off",
			policy: &Policy{BackupMaxAge: 26 * time.Hour},
			states: []SystemState{{Report: state("pi", nil).Report, ReceivedAt: ago(30 * 24 * time.Hour)}},
		},
		{
			name: "a collector or connector problem is a warning",
			states: []SystemState{
				state("server", func(r *report.Report) {
					r.Errors = []report.Problem{
						{Collector: "containers", Message: "podman ps: exit status 125:\n  cannot connect to Podman socket"},
						{Message: "something broke"},
					}
				}),
				state("opnsense02", func(r *report.Report) {
					r.System.Source = "connector"
					r.Errors = []report.Problem{{Collector: ConnectorProblem, Message: "asking for the firmware status: 401 Unauthorized"}}
				}),
			},
			want: []Finding{
				{"opnsense02", CategorySource, Warn, "connector failed", "asking for the firmware status: 401 Unauthorized"},
				{"server", CategorySource, Warn, "a collector failed", "something broke"},
				{"server", CategorySource, Warn, "collector containers failed", "podman ps: exit status 125: cannot connect to Podman socket"},
			},
		},
		{
			name: "sorted by severity, then system, then category",
			states: []SystemState{
				state("zeta", func(r *report.Report) {
					r.Backups = []report.Backup{{Name: "restic-backup", LastRun: ago(time.Hour), LastResult: "failed"}}
				}),
				state("beta", func(r *report.Report) {
					r.Packages = &report.Packages{Manager: "apt", Pending: 3, Security: 1, RebootRequired: true}
					r.Containers = []report.Container{{Name: "gitea", Image: gitea}}
					r.Software = []report.Software{{Name: "restic", Latest: "0.18.1", UpdateAvailable: true}}
					r.Backups = []report.Backup{{Name: "restic-offsite", LastSuccess: ago(30 * time.Hour), LastResult: "ok"}}
					r.Errors = []report.Problem{{Collector: "backup", Message: "systemctl show: timeout"}}
				}),
				state("alpha", func(r *report.Report) {
					r.Packages = &report.Packages{Manager: "apt", Pending: 1}
					r.Backups = []report.Backup{{Name: "restic-backup", LastSuccess: ago(30 * time.Hour), LastResult: "ok"}}
				}),
			},
			checks: map[string]ImageCheck{gitea: {Image: gitea, Tag: "1.23.6", NewerPatch: "1.23.8"}},
			want: []Finding{
				{"zeta", CategoryBackup, Crit, "backup restic-backup failed", "last run 2026-11-19 07:00 UTC; no successful run is known"},
				{"alpha", CategoryBackup, Warn, "backup restic-backup last succeeded 2026-11-18", "30 hours ago, at 02:00 UTC; allowed age is 26 hours"},
				// Within one system and severity: source, backup, reboot, os, software, container.
				{"beta", CategorySource, Warn, "collector backup failed", "systemctl show: timeout"},
				{"beta", CategoryBackup, Warn, "backup restic-offsite last succeeded 2026-11-18", "30 hours ago, at 02:00 UTC; allowed age is 26 hours"},
				{"beta", CategoryReboot, Warn, "reboot required", ""},
				{"beta", CategoryOS, Warn, "3 package updates, 1 security", ""},
				{"alpha", CategoryOS, Info, "1 package update", ""},
				{"beta", CategorySoftware, Info, "restic 0.18.1 available", ""},
				{"beta", CategoryContainer, Info, "gitea: 1.23.8 available", "patch update of " + gitea},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := DefaultPolicy()
			if tt.policy != nil {
				p = *tt.policy
			}
			got := Findings(tt.states, tt.checks, now, p)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findings differ\n got:\n%s\nwant:\n%s", dump(got), dump(tt.want))
			}
		})
	}
}

// Titles must not change with the clock alone: the "on change" mail compares them.
func TestFindingsTitlesDoNotAge(t *testing.T) {
	states := []SystemState{
		{Report: state("pi", func(r *report.Report) {
			r.Packages = &report.Packages{Manager: "apt", Pending: 2, ListsUpdated: ago(10 * 24 * time.Hour)}
			r.Backups = []report.Backup{{Name: "restic-backup", LastSuccess: ago(10 * 24 * time.Hour), LastResult: "ok"}}
		}).Report, ReceivedAt: ago(9 * 24 * time.Hour)},
	}
	first := Findings(states, nil, now, DefaultPolicy())
	later := Findings(states, nil, now.Add(31*time.Hour), DefaultPolicy())
	if len(first) != 4 || len(first) != len(later) {
		t.Fatalf("want 4 findings both times, got %d and %d", len(first), len(later))
	}
	for i := range first {
		if first[i].Title != later[i].Title || first[i].Severity != later[i].Severity {
			t.Errorf("finding %d changed with time alone: %q then %q", i, first[i].Title, later[i].Title)
		}
	}
}

func TestOneLine(t *testing.T) {
	long := strings.Repeat("é", 400)
	got := oneLine(long)
	if len(got) > maxLine+len("…") || !strings.HasSuffix(got, "…") || strings.ContainsRune(got, '�') {
		t.Errorf("a long message was not cut cleanly: %d bytes", len(got))
	}
	if got := oneLine("  a\n\tb  "); got != "a b" {
		t.Errorf("got %q", got)
	}
}

func dump(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString("  " + f.Severity.String() + " | " + f.System + " | " + string(f.Category) + " | " + f.Title + " | " + f.Detail + "\n")
	}
	return b.String()
}

// An image for several architectures is known to the runtime by more than one digest, and the
// registry names only one of them for the tag. Comparing one digest with one digest called
// every such image rebuilt; the tag only moved when it points at none of the image's digests.
func TestRebuilt(t *testing.T) {
	const index, variant, other = digestOld, digestNew, "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	tests := []struct {
		name      string
		c         report.Container
		tagDigest string
		rebuilt   bool
		known     bool
	}{
		{name: "the one digest is the tag's", c: report.Container{Digest: index}, tagDigest: index, known: true},
		{name: "the one digest is not the tag's", c: report.Container{Digest: index}, tagDigest: other, rebuilt: true, known: true},
		{name: "upper and lower case are the same digest", c: report.Container{Digest: strings.ToUpper(index)}, tagDigest: index, known: true},
		{name: "pulled as the variant, the tag names the set", c: report.Container{Digest: variant, Digests: []string{index, variant}}, tagDigest: index, known: true},
		{name: "no single digest, the tag names one of them", c: report.Container{Digests: []string{index, variant}}, tagDigest: variant, known: true},
		{name: "the tag names none of them", c: report.Container{Digest: index, Digests: []string{index, variant}}, tagDigest: other, rebuilt: true, known: true},
		{name: "no single digest and the tag names none", c: report.Container{Digests: []string{index, variant}}, tagDigest: other, rebuilt: true, known: true},
		{name: "the agent knows no digest: nothing can disagree", c: report.Container{}, tagDigest: index},
		{name: "empty entries are no digest", c: report.Container{Digests: []string{""}}, tagDigest: index},
		{name: "the registry named no digest: nothing can disagree", c: report.Container{Digest: index}, known: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Rebuilt(tc.c, ImageCheck{TagDigest: tc.tagDigest}); got != tc.rebuilt {
				t.Errorf("Rebuilt = %v, want %v", got, tc.rebuilt)
			}
			if got := DigestKnown(tc.c); got != tc.known {
				t.Errorf("DigestKnown = %v, want %v", got, tc.known)
			}
		})
	}
}

func TestRebuiltFindings(t *testing.T) {
	const mongo = "docker.io/library/mongo:7.0.48"
	pinned := mongo + "@" + digestOld
	checks := map[string]ImageCheck{
		mongo:  {Image: mongo, Tag: "7.0.48", TagDigest: digestNew},
		pinned: {Image: pinned, Tag: "7.0.48", TagDigest: digestNew},
	}
	st := state("server", func(r *report.Report) {
		r.Containers = []report.Container{
			// Current: the registry's digest is one of the two the runtime knows the image by.
			{Name: "current", Image: mongo, Digest: digestOld, Digests: []string{digestOld, digestNew}},
			{Name: "moved", Image: mongo, Digests: []string{digestOld}},
			{Name: "moved-auto", Image: mongo, Digest: digestOld, AutoUpdate: "registry"},
			{Name: "pinned", Image: pinned, Digest: digestOld},
		}
	})
	got := map[string]string{}
	for _, f := range Findings([]SystemState{st}, checks, now, DefaultPolicy()) {
		got[f.Title] = f.Detail
	}
	want := map[string]string{
		"moved: tag 7.0.48 was rebuilt":      "pull the image and restart the container",
		"moved-auto: tag 7.0.48 was rebuilt": "it updates itself (auto-update registry)",
		"pinned: tag 7.0.48 was rebuilt":     "pinned to its digest and only moves when the pin is changed",
	}
	if len(got) != len(want) {
		t.Errorf("findings: %v", got)
	}
	for title, part := range want {
		if !strings.Contains(got[title], part) || !strings.Contains(got[title], "the container runs sha256:1f3c5a7e9b2d") {
			t.Errorf("%q: detail %q, want it to say %q and which digest runs", title, got[title], part)
		}
	}
}

// A package on hold gets no security update either, so it is worth a line. What the
// distribution is still phasing in is not.
func TestHeldBackFinding(t *testing.T) {
	names := func(n int) []report.PackageUpdate {
		var out []report.PackageUpdate
		for i := range n {
			out = append(out, report.PackageUpdate{Name: "pkg" + string(rune('a'+i)), Reason: "held"})
		}
		return out
	}
	tests := []struct {
		name string
		kept []report.PackageUpdate
		want *Finding
	}{
		{name: "nothing kept"},
		{name: "only phased updates", kept: []report.PackageUpdate{{Name: "distro-info", Reason: "phased"}}},
		{
			name: "held and kept back, phased left out",
			kept: []report.PackageUpdate{
				{Name: "libssl3t64", Reason: "held"}, {Name: "tzdata", Reason: "held"},
				{Name: "linux-image-cloud-amd64", Reason: "kept back"}, {Name: "distro-info", Reason: "phased"},
			},
			want: &Finding{System: "server", Category: CategoryOS, Severity: Info, Title: "3 package updates held back",
				Detail: "on hold: libssl3t64, tzdata; kept back, their dependencies cannot be met: linux-image-cloud-amd64"},
		},
		{
			name: "a reason a newer agent may send counts as kept back",
			kept: []report.PackageUpdate{{Name: "nginx", Reason: "locked"}},
			want: &Finding{System: "server", Category: CategoryOS, Severity: Info, Title: "1 package update held back",
				Detail: "kept back, their dependencies cannot be met: nginx"},
		},
		{
			name: "a long list is cut",
			kept: names(11),
			want: &Finding{System: "server", Category: CategoryOS, Severity: Info, Title: "11 package updates held back",
				Detail: "on hold: pkga, pkgb, pkgc, pkgd, pkge, pkgf, pkgg, pkgh and 3 more"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := state("server", func(r *report.Report) {
				r.Packages = &report.Packages{Manager: "apt", ListsUpdated: ago(time.Hour), KeptBack: tc.kept}
			})
			got := Findings([]SystemState{st}, nil, now, DefaultPolicy())
			switch {
			case tc.want == nil && len(got) != 0:
				t.Errorf("findings: %s", dump(got))
			case tc.want != nil && (len(got) != 1 || got[0] != *tc.want):
				t.Errorf("findings:\n%s\nwant:\n%s", dump(got), dump([]Finding{*tc.want}))
			}
		})
	}
}

func TestSeverityString(t *testing.T) {
	for sev, want := range map[Severity]string{Info: "info", Warn: "warn", Crit: "crit", -1: "info", 7: "crit"} {
		if got := sev.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(sev), got, want)
		}
	}
}
