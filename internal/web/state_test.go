package web

import (
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
)

func TestRelTime(t *testing.T) {
	const day = 24 * time.Hour
	tests := []struct {
		ago  time.Duration
		want string
	}{
		{0, "just now"},
		{59 * time.Second, "just now"},
		{time.Minute, "1 min ago"},
		{59*time.Minute + 59*time.Second, "59 min ago"},
		{time.Hour, "1 h ago"},
		{3*time.Hour + 20*time.Minute, "3 h ago"},
		{26 * time.Hour, "26 h ago"},
		{47 * time.Hour, "47 h ago"},
		{2 * day, "2 d ago"},
		{13*day + 23*time.Hour, "13 d ago"},
		{14 * day, "2 wk ago"},
		{59 * day, "8 wk ago"},
		{60 * day, "2 mo ago"},
		{400 * day, "13 mo ago"},
		{730 * day, "2 y ago"},
		// A clock that runs ahead of the server's.
		{-30 * time.Second, "just now"},
		{-5 * time.Minute, "in 5 min"},
		{-3 * time.Hour, "in 3 h"},
	}
	for _, tc := range tests {
		if got := relTime(testNow.Add(-tc.ago), testNow); got != tc.want {
			t.Errorf("relTime(%v ago) = %q, want %q", tc.ago, got, tc.want)
		}
	}
}

func TestTimeView(t *testing.T) {
	zagreb := time.FixedZone("CET", 3600)
	tests := []struct {
		name string
		t    time.Time
		now  time.Time
		want timeView
	}{
		{"never", time.Time{}, testNow, timeView{Zero: true, Rel: "never"}},
		{
			"the exact time is in the server's zone, the machine-readable one in UTC",
			time.Date(2026, 11, 19, 6, 30, 0, 0, time.UTC), testNow.In(zagreb),
			timeView{Rel: "3 h ago", Exact: "2026-11-19 07:30:00 CET", ISO: "2026-11-19T06:30:00Z"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := newTimeView(tc.t, tc.now); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSpan(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{45 * time.Second, "45 s"},
		{26 * time.Hour, "26 h"},
		{48 * time.Hour, "2 d"},
		{192 * time.Hour, "8 d"},
		{720 * time.Hour, "4 wk"},
	}
	for _, tc := range tests {
		if got := span(tc.d); got != tc.want {
			t.Errorf("span(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// The images are the ones in use on the machines this was written for.
func TestSplitImage(t *testing.T) {
	const sum = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
	tests := []struct {
		image string
		want  imageRef
	}{
		{"docker.io/gitea/gitea:1.23.6", imageRef{Repo: "docker.io/gitea/gitea", Tag: "1.23.6"}},
		{"docker.io/library/mariadb:11.4.13", imageRef{Repo: "docker.io/library/mariadb", Tag: "11.4.13"}},
		{"docker.io/photoprism/photoprism:251130", imageRef{Repo: "docker.io/photoprism/photoprism", Tag: "251130"}},
		{"lscr.io/linuxserver/unifi-network-application:10.0.162-ls114", imageRef{Repo: "lscr.io/linuxserver/unifi-network-application", Tag: "10.0.162-ls114"}},
		{"docker.io/adguard/adguardhome:latest", imageRef{Repo: "docker.io/adguard/adguardhome", Tag: "latest"}},
		{"docker.io/louislam/uptime-kuma:2", imageRef{Repo: "docker.io/louislam/uptime-kuma", Tag: "2"}},
		{"ghcr.io/stryan/materia@" + sum, imageRef{Repo: "ghcr.io/stryan/materia", Digest: sum}},
		{"ghcr.io/stryan/materia:v0.5.0@" + sum, imageRef{Repo: "ghcr.io/stryan/materia", Tag: "v0.5.0", Digest: sum}},
		{"localhost/medimorec-server:current", imageRef{Repo: "localhost/medimorec-server", Tag: "current", Local: true}},
		// A registry on the reporting machine's own localhost is not one the server can ask.
		{"localhost:5000/thing:1", imageRef{Repo: "localhost:5000/thing", Tag: "1", Local: true}},
		{"localhost.example/thing:1", imageRef{Repo: "localhost.example/thing", Tag: "1"}},
		{"registry.example:5000/thing", imageRef{Repo: "registry.example:5000/thing"}},
		{"alpine", imageRef{Repo: "alpine"}},
		{"", imageRef{}},
	}
	for _, tc := range tests {
		if got := splitImage(tc.image); got != tc.want {
			t.Errorf("splitImage(%q) = %+v, want %+v", tc.image, got, tc.want)
		}
	}
}

func TestImageStatus(t *testing.T) {
	const (
		pulled  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		rebuilt = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	tests := []struct {
		name        string
		c           report.Container
		check       *model.ImageCheck
		wantNewer   []newer
		wantRebuilt bool
		wantPending bool
		wantStatus  string
		wantTone    tone
		wantProblem string
	}{
		{
			name:  "nothing newer",
			c:     report.Container{Image: "docker.io/henrygd/beszel:0.21.2", Digest: pulled},
			check: &model.ImageCheck{TagDigest: pulled}, wantStatus: "up to date", wantTone: toneOK,
		},
		{
			name:      "a newer patch and minor",
			c:         report.Container{Image: "docker.io/gitea/gitea:1.23.6", Digest: pulled},
			check:     &model.ImageCheck{TagDigest: pulled, NewerPatch: "1.23.8", NewerMinor: "1.27.3"},
			wantNewer: []newer{{"patch", "1.23.8"}, {"minor", "1.27.3"}}, wantPending: true,
		},
		{
			name:      "a newer major only",
			c:         report.Container{Image: "docker.io/library/mongo:7.0.48", Digest: pulled},
			check:     &model.ImageCheck{TagDigest: pulled, NewerMajor: "9.0.8"},
			wantNewer: []newer{{"major", "9.0.8"}}, wantPending: true,
		},
		{
			name:  "the tag was rebuilt",
			c:     report.Container{Image: "docker.io/adguard/adguardhome:latest", Digest: pulled},
			check: &model.ImageCheck{TagDigest: rebuilt}, wantRebuilt: true, wantPending: true,
		},
		{
			name:  "the agent could not tell the digest: no claim about a rebuild",
			c:     report.Container{Image: "docker.io/adguard/adguardhome:latest"},
			check: &model.ImageCheck{TagDigest: rebuilt}, wantStatus: "no newer tag", wantTone: toneNone,
		},
		{
			// Podman knows an image for several architectures by the digest of the whole set and
			// by the one of this machine's variant; the registry names the set's.
			name:  "one of the image's digests is what the tag points at",
			c:     report.Container{Image: "docker.io/library/mongo:7.0.48", Digest: pulled, Digests: []string{pulled, rebuilt}},
			check: &model.ImageCheck{TagDigest: rebuilt}, wantStatus: "up to date", wantTone: toneOK,
		},
		{
			name:  "no single digest could be named, and one of them is what the tag points at",
			c:     report.Container{Image: "docker.io/library/mongo:7.0.48", Digests: []string{pulled, rebuilt}},
			check: &model.ImageCheck{TagDigest: rebuilt}, wantStatus: "up to date", wantTone: toneOK,
		},
		{
			name:  "none of the image's digests is what the tag points at",
			c:     report.Container{Image: "docker.io/library/mongo:7.0.48", Digests: []string{pulled, "sha256:3333"}},
			check: &model.ImageCheck{TagDigest: rebuilt}, wantRebuilt: true, wantPending: true,
		},
		{
			name:  "the registry gave no digest: no claim about a rebuild, and none that all is well",
			c:     report.Container{Image: "docker.io/adguard/adguardhome:latest", Digest: pulled},
			check: &model.ImageCheck{}, wantStatus: "not checked", wantTone: toneNone,
		},
		{
			name:       "nobody asked the registry yet",
			c:          report.Container{Image: "ghcr.io/bakito/adguardhome-sync:v0.8.2", Digest: pulled},
			wantStatus: "not checked", wantTone: toneNone,
		},
		{
			name:  "the registry could not be asked",
			c:     report.Container{Image: "docker.io/restic/rest-server:0.14.0", Digest: pulled},
			check: &model.ImageCheck{Error: "429 Too Many Requests"}, wantStatus: "check failed", wantTone: toneNone, wantProblem: "429 Too Many Requests",
		},
		{
			name:      "the last check failed but an earlier one found something",
			c:         report.Container{Image: "docker.io/gitea/gitea:1.23.6", Digest: pulled},
			check:     &model.ImageCheck{NewerPatch: "1.23.8", Error: "timeout"},
			wantNewer: []newer{{"patch", "1.23.8"}}, wantPending: true, wantStatus: "last check failed", wantTone: toneNone, wantProblem: "timeout",
		},
		{
			name:  "a local image, whatever the check says",
			c:     report.Container{Image: "localhost/medimorec-server:current", Digest: pulled},
			check: &model.ImageCheck{Error: "localhost is not a registry"}, wantStatus: "local image", wantTone: toneNone,
		},
		{
			name:       "a local image without a check",
			c:          report.Container{Image: "localhost/medimorec-server:current"},
			wantStatus: "local image", wantTone: toneNone,
		},
		{
			name:       "pinned by digest: no registry is asked, so there is no check",
			c:          report.Container{Image: "ghcr.io/stryan/materia@" + pulled, Digest: pulled},
			wantStatus: "pinned by digest", wantTone: toneNone,
		},
		{
			name:  "pinned by digest, with the empty check the registry client gives for it",
			c:     report.Container{Image: "ghcr.io/stryan/materia@" + pulled, Digest: pulled},
			check: &model.ImageCheck{}, wantStatus: "pinned by digest", wantTone: toneNone,
		},
		{
			name:  "digests are compared without regard to case, like model.Findings does",
			c:     report.Container{Image: "docker.io/henrygd/beszel:0.21.2", Digest: "sha256:ABCDEF"},
			check: &model.ImageCheck{TagDigest: "sha256:abcdef"}, wantStatus: "up to date", wantTone: toneOK,
		},
		{
			name:  "a check that asked nobody: an address the registry client calls local",
			c:     report.Container{Image: "127.0.0.1:5000/thing:1", Digest: pulled},
			check: &model.ImageCheck{Tag: "1"}, wantStatus: "not checked", wantTone: toneNone,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var check model.ImageCheck
			if tc.check != nil {
				check = *tc.check
			}
			got := imageStatus(tc.c, check, tc.check != nil)
			if len(got.Newer) != len(tc.wantNewer) {
				t.Fatalf("newer = %v, want %v", got.Newer, tc.wantNewer)
			}
			for i := range got.Newer {
				if got.Newer[i] != tc.wantNewer[i] {
					t.Errorf("newer[%d] = %v, want %v", i, got.Newer[i], tc.wantNewer[i])
				}
			}
			if got.Rebuilt != tc.wantRebuilt || got.Pending != tc.wantPending {
				t.Errorf("rebuilt %v, pending %v; want %v, %v", got.Rebuilt, got.Pending, tc.wantRebuilt, tc.wantPending)
			}
			if got.Status.Text != tc.wantStatus || (tc.wantStatus != "" && got.Status.Tone != tc.wantTone) {
				t.Errorf("status = %q (%s), want %q (%s)", got.Status.Text, got.Status.Tone, tc.wantStatus, tc.wantTone)
			}
			if got.Problem != tc.wantProblem {
				t.Errorf("problem = %q, want %q", got.Problem, tc.wantProblem)
			}
		})
	}
}

func TestSelfUpdate(t *testing.T) {
	// The values are those Podman knows for io.containers.autoupdate (podman-auto-update(1)).
	tests := []struct {
		label     string
		wantPulls bool
		wantWord  string
	}{
		{"registry", true, "yes"},
		{"image", true, "yes"},
		{"local", false, "local only"},
		{"", false, "no"},
		{"disabled", false, "no"},
		{"something else", false, "no"},
	}
	for _, tc := range tests {
		pulls, word := selfUpdate(report.Container{AutoUpdate: tc.label})
		if pulls != tc.wantPulls || word != tc.wantWord {
			t.Errorf("selfUpdate(%q) = %v, %q; want %v, %q", tc.label, pulls, word, tc.wantPulls, tc.wantWord)
		}
	}
}

func TestReadBackup(t *testing.T) {
	policy := model.DefaultPolicy() // a backup may be 26 h old
	ago := func(h int) time.Time { return testNow.Add(-time.Duration(h) * time.Hour) }
	tests := []struct {
		name      string
		b         report.Backup
		policy    model.Policy
		wantState string
		wantTone  tone
		wantLate  bool
		wantWorst tone
	}{
		{"fine", report.Backup{LastSuccess: ago(7), LastResult: "ok"}, policy, backupOK, toneOK, false, toneOK},
		{"fine at the limit", report.Backup{LastSuccess: ago(26), LastResult: "ok"}, policy, backupOK, toneOK, false, toneOK},
		{"late", report.Backup{LastSuccess: ago(27), LastResult: "ok"}, policy, backupLate, toneWarn, false, toneWarn},
		{"late without a result", report.Backup{LastSuccess: ago(50)}, policy, backupLate, toneWarn, false, toneWarn},
		{"twice the allowed age is broken", report.Backup{LastSuccess: ago(53), LastResult: "ok"}, policy, backupLate, toneCrit, false, toneCrit},
		{"its own limit allows more", report.Backup{LastSuccess: ago(80), MaxAgeHours: 192}, policy, backupOK, toneOK, false, toneOK},
		{"its own limit allows less", report.Backup{LastSuccess: ago(7), MaxAgeHours: 6}, policy, backupLate, toneWarn, false, toneWarn},
		{"failed, the last good one still young", report.Backup{LastSuccess: ago(20), LastRun: ago(1), LastResult: "failed"}, policy, backupFailed, toneCrit, false, toneCrit},
		{"failed, and the last good one too old", report.Backup{LastSuccess: ago(53), LastRun: ago(5), LastResult: "failed"}, policy, backupFailed, toneCrit, true, toneCrit},
		{"failed and never succeeded", report.Backup{LastRun: ago(5), LastResult: "failed"}, policy, backupFailed, toneCrit, false, toneCrit},
		{"never", report.Backup{LastResult: "unknown"}, policy, backupNever, toneWarn, false, toneWarn},
		{"never, nothing known at all", report.Backup{}, policy, backupNever, toneWarn, false, toneWarn},
		{"it says ok and only the run is known", report.Backup{LastRun: ago(3), LastResult: "ok"}, policy, backupOK, toneOK, false, toneOK},
		{"it says ok, but that run is long ago", report.Backup{LastRun: ago(30), LastResult: "ok"}, policy, backupLate, toneWarn, false, toneWarn},
		{"running", report.Backup{LastSuccess: ago(24), LastRun: ago(0), LastResult: "running"}, policy, backupRunning, toneInfo, false, toneInfo},
		{"running, and overdue: it may be catching up", report.Backup{LastSuccess: ago(30), LastRun: ago(0), LastResult: "running"}, policy, backupRunning, toneInfo, false, toneInfo},
		{"running for ever does not hide a backup that is long overdue", report.Backup{LastSuccess: ago(60), LastRun: ago(40), LastResult: "running"}, policy, backupRunning, toneInfo, true, toneCrit},
		{"running for the first time", report.Backup{LastResult: "running"}, policy, backupRunning, toneInfo, false, toneInfo},
		{"a result this build does not know", report.Backup{LastSuccess: ago(3), LastResult: "skipped"}, policy, backupOK, toneOK, false, toneOK},
		{"no allowed age at all: nothing is ever late", report.Backup{LastSuccess: ago(9000), LastResult: "ok"}, model.Policy{}, backupOK, toneOK, false, toneOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := readBackup(tc.b, testNow, tc.policy)
			if st.State != tc.wantState || st.Tone != tc.wantTone || st.Late != tc.wantLate || st.worst() != tc.wantWorst {
				t.Errorf("state %q (%s), late %v, worst %s; want %q (%s), %v, %s",
					st.State, st.Tone, st.Late, st.worst(), tc.wantState, tc.wantTone, tc.wantLate, tc.wantWorst)
			}
		})
	}
}

// TestBackupRank is the order of the backups page.
func TestBackupRank(t *testing.T) {
	policy := model.DefaultPolicy()
	ago := func(h int) time.Time { return testNow.Add(-time.Duration(h) * time.Hour) }
	inOrder := []report.Backup{
		{Name: "failed", LastSuccess: ago(3), LastResult: "failed"},
		{Name: "twice too old", LastSuccess: ago(60), LastResult: "ok"},
		{Name: "running but twice too old", LastSuccess: ago(60), LastResult: "running"},
		{Name: "late", LastSuccess: ago(30), LastResult: "ok"},
		{Name: "never", LastResult: "unknown"},
		{Name: "running", LastSuccess: ago(3), LastResult: "running"},
		{Name: "fine", LastSuccess: ago(3), LastResult: "ok"},
	}
	for i := 1; i < len(inOrder); i++ {
		a, b := readBackup(inOrder[i-1], testNow, policy), readBackup(inOrder[i], testNow, policy)
		if a.rank() >= b.rank() {
			t.Errorf("%q (rank %d) should come before %q (rank %d)", inOrder[i-1].Name, a.rank(), inOrder[i].Name, b.rank())
		}
	}
}

func TestPackageCounts(t *testing.T) {
	item := func(security bool) report.PackageUpdate { return report.PackageUpdate{Name: "x", Security: security} }
	tests := []struct {
		name         string
		p            report.Packages
		wantPending  int
		wantSecurity int
	}{
		{"as reported", report.Packages{Pending: 12, Security: 3}, 12, 3},
		{"a list longer than the count", report.Packages{Pending: 1, Items: []report.PackageUpdate{item(false), item(false)}}, 2, 0},
		{"no security count, but flagged packages", report.Packages{Pending: 2, Items: []report.PackageUpdate{item(true), item(false)}}, 2, 1},
		{"more security updates than updates", report.Packages{Pending: 2, Security: 5}, 2, 2},
		{"nothing", report.Packages{}, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pending, security := packageCounts(&tc.p)
			if pending != tc.wantPending || security != tc.wantSecurity {
				t.Errorf("got %d pending, %d security; want %d, %d", pending, security, tc.wantPending, tc.wantSecurity)
			}
		})
	}
}

func TestSilent(t *testing.T) {
	policy := model.DefaultPolicy() // silent after 2 h
	tests := []struct {
		ago  time.Duration
		want bool
	}{
		{0, false},
		{2 * time.Hour, false},
		{2*time.Hour + time.Second, true},
		{74 * time.Hour, true},
		{-time.Hour, false},
	}
	for _, tc := range tests {
		if got := silent(testNow.Add(-tc.ago), testNow, policy); got != tc.want {
			t.Errorf("silent(%v ago) = %v, want %v", tc.ago, got, tc.want)
		}
	}
	// A threshold of zero switches the rule off, and a time nobody knows proves nothing.
	if silent(testNow.Add(-9000*time.Hour), testNow, model.Policy{}) {
		t.Error("silent without a threshold")
	}
	if silent(time.Time{}, testNow, policy) {
		t.Error("silent without a time of the last report")
	}
}

func TestWebLink(t *testing.T) {
	tests := map[string]string{
		"https://docs.opnsense.org/releases/BE_26.10.html":      "https://docs.opnsense.org/releases/BE_26.10.html",
		"http://homeassistant.local:8123/config/updates":        "http://homeassistant.local:8123/config/updates",
		" https://www.home-assistant.io/latest-release-notes/ ": "https://www.home-assistant.io/latest-release-notes/",
		"":                               "",
		"javascript:alert(1)":            "",
		"JaVaScRiPt:alert(1)":            "",
		"data:text/html,<script>":        "",
		"//evil.example/x":               "",
		"/config/updates":                "",
		"ftp://example.org/notes.txt":    "",
		"https:///no-host":               "",
		"https://exa mple.org/":          "",
		"vbscript:msgbox(1)":             "",
		"\x01javascript:alert(1)":        "",
		"https://example.org/\"onclick=": "https://example.org/%22onclick=",
	}
	for raw, want := range tests {
		if got := webLink(raw); got != want {
			t.Errorf("webLink(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestAnchors(t *testing.T) {
	ids := anchors{}
	tests := []struct{ name, want string }{
		{"server", "sys-server"},
		{"Server", "sys-server-2"},
		{"my host", "sys-my-host"},
		{"my-host", "sys-my-host-2"},
		{"my_host.lan", "sys-my_host.lan"},
		{`"><script>`, "sys----script-"},
		{"čćž", "sys----"},
		{"", "sys-"},
	}
	for _, tc := range tests {
		if got := ids.id("sys-", tc.name); got != tc.want {
			t.Errorf("id(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestClampSeverity(t *testing.T) {
	tests := []struct {
		in       model.Severity
		wantTone tone
		wantWord string
		wantBand string
	}{
		{model.Info, toneInfo, "to know", "Worth knowing"},
		{model.Warn, toneWarn, "to do", "Should be done"},
		{model.Crit, toneCrit, "broken", "Broken"},
		// Values no build knows today must not panic and must not look harmless.
		{model.Severity(7), toneCrit, "broken", "Broken"},
		{model.Severity(-1), toneInfo, "to know", "Worth knowing"},
	}
	for _, tc := range tests {
		if got := severityTone(tc.in); got != tc.wantTone {
			t.Errorf("severityTone(%d) = %q, want %q", tc.in, got, tc.wantTone)
		}
		if got := severityWord(tc.in); got != tc.wantWord {
			t.Errorf("severityWord(%d) = %q, want %q", tc.in, got, tc.wantWord)
		}
		if got := bandTitle(tc.in); got != tc.wantBand {
			t.Errorf("bandTitle(%d) = %q, want %q", tc.in, got, tc.wantBand)
		}
	}
}

func TestCount(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{{0, "0 packages"}, {1, "1 package"}, {2, "2 packages"}}
	for _, tc := range tests {
		if got := count(tc.n, "package", "packages"); got != tc.want {
			t.Errorf("count(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
