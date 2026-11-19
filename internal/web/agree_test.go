package web

import (
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
)

// worstFinding is the loudest thing model.Findings says about one category of one system.
func worstFinding(st model.SystemState, c model.Category, now time.Time, p model.Policy) tone {
	worst := toneOK
	for _, f := range model.Findings([]model.SystemState{st}, nil, now, p) {
		if f.Category == c && severityTone(f.Severity).weight() > worst.weight() {
			worst = severityTone(f.Severity)
		}
	}
	return worst
}

// loud keeps what a finding can say of a row's state: a finding has no word for "fine" or for
// "running", so both count as nothing found.
func loud(t tone) tone {
	if t == toneWarn || t == toneCrit {
		return t
	}
	return toneOK
}

// TestRowsAgreeWithFindings is the one test here that looks at the real model.Findings on
// purpose. The rules for a single row (state.go) repeat what model/findings.go decides about a
// system, because that package does not export them. If this test fails, the two have drifted
// apart and a row would be coloured differently from the finding about it: bring state.go back
// in line, or better, let model export the rule.
func TestRowsAgreeWithFindings(t *testing.T) {
	ago := func(h int) time.Time { return testNow.Add(-time.Duration(h) * time.Hour) }
	policies := map[string]model.Policy{
		"default policy": model.DefaultPolicy(),
		"strict policy":  {SilentAfter: 30 * time.Minute, BackupMaxAge: 6 * time.Hour},
		"no thresholds":  {},
	}

	backups := []report.Backup{
		{Name: "fine", LastSuccess: ago(3), LastRun: ago(3), LastResult: "ok"},
		{Name: "at the default limit", LastSuccess: ago(26), LastResult: "ok"},
		{Name: "late", LastSuccess: ago(30), LastResult: "ok"},
		{Name: "twice too old", LastSuccess: ago(53), LastResult: "ok"},
		{Name: "no result", LastSuccess: ago(30)},
		{Name: "own limit, fine", LastSuccess: ago(80), MaxAgeHours: 192, LastResult: "ok"},
		{Name: "own limit, late", LastSuccess: ago(7), MaxAgeHours: 6, LastResult: "ok"},
		{Name: "failed", LastSuccess: ago(3), LastRun: ago(1), LastResult: "failed"},
		{Name: "failed and old", LastSuccess: ago(90), LastRun: ago(1), LastResult: "failed"},
		{Name: "failed, never succeeded", LastRun: ago(1), LastResult: "failed"},
		{Name: "never", LastResult: "unknown"},
		{Name: "nothing known"},
		{Name: "ok, only the run is known", LastRun: ago(3), LastResult: "ok"},
		{Name: "ok, but the run is old", LastRun: ago(30), LastResult: "ok"},
		{Name: "running", LastSuccess: ago(20), LastRun: ago(0), LastResult: "running"},
		{Name: "running and late", LastSuccess: ago(30), LastRun: ago(0), LastResult: "running"},
		{Name: "running and twice too old", LastSuccess: ago(60), LastRun: ago(40), LastResult: "running"},
		{Name: "running for the first time", LastResult: "running"},
	}
	for policyName, p := range policies {
		for _, b := range backups {
			t.Run("backup "+b.Name+", "+policyName, func(t *testing.T) {
				st := model.SystemState{
					Report:     report.Report{System: report.System{Name: "x", Source: "agent"}, Backups: []report.Backup{b}},
					ReceivedAt: testNow,
				}
				row := loud(readBackup(b, testNow, p).worst())
				if found := worstFinding(st, model.CategoryBackup, testNow, p); row != found {
					t.Errorf("the row says %q, the findings say %q", row, found)
				}
			})
		}

		for _, quiet := range []time.Duration{0, 29 * time.Minute, 31 * time.Minute, 2 * time.Hour, 2*time.Hour + time.Second, 74 * time.Hour} {
			t.Run("last report "+quiet.String()+" ago, "+policyName, func(t *testing.T) {
				st := model.SystemState{
					Report:     report.Report{System: report.System{Name: "x", Source: "agent"}},
					ReceivedAt: testNow.Add(-quiet),
				}
				row := toneOK
				if silent(st.ReceivedAt, testNow, p) {
					row = toneCrit
				}
				if found := worstFinding(st, model.CategorySource, testNow, p); row != found {
					t.Errorf("the row says %q, the findings say %q", row, found)
				}
			})
		}
	}

	// Packages with fresh lists: what is pending decides alone.
	item := func(security bool) report.PackageUpdate {
		return report.PackageUpdate{Name: "x", Installed: "1", Candidate: "2", Security: security}
	}
	packages := map[string]report.Packages{
		"nothing pending":                       {Manager: "apt"},
		"updates":                               {Manager: "apt", Pending: 4},
		"security updates":                      {Manager: "apt", Pending: 12, Security: 3},
		"flagged packages, no count":            {Manager: "apt", Pending: 2, Items: []report.PackageUpdate{item(true), item(false)}},
		"a list longer than the count":          {Manager: "apt", Items: []report.PackageUpdate{item(false)}},
		"more security updates than updates":    {Manager: "apt", Security: 2},
		"a security list longer than the count": {Manager: "apt", Items: []report.PackageUpdate{item(true)}},
	}
	for name, p := range packages {
		t.Run("packages: "+name, func(t *testing.T) {
			p.ListsUpdated = testNow
			st := model.SystemState{
				Report:     report.Report{System: report.System{Name: "x", Source: "agent"}, Packages: &p},
				ReceivedAt: testNow,
			}
			pending, security := packageCounts(&p)
			row := toneOK
			switch {
			case security > 0:
				row = toneWarn
			case pending > 0:
				row = toneInfo
			}
			found := toneOK
			for _, f := range model.Findings([]model.SystemState{st}, nil, testNow, model.DefaultPolicy()) {
				if f.Category == model.CategoryOS {
					found = severityTone(f.Severity)
				}
			}
			if row != found {
				t.Errorf("the row says %q, the findings say %q", row, found)
			}
		})
	}

	// Containers: a row has something newer exactly when the findings name the container.
	const pulled, other = "sha256:1111", "sha256:2222"
	containers := []struct {
		name  string
		c     report.Container
		check *model.ImageCheck
	}{
		{"up to date", report.Container{Image: "docker.io/a/b:1.0.0", Digest: pulled}, &model.ImageCheck{TagDigest: pulled}},
		{"a newer patch", report.Container{Image: "docker.io/a/b:1.0.0", Digest: pulled}, &model.ImageCheck{TagDigest: pulled, NewerPatch: "1.0.1"}},
		{"a newer major", report.Container{Image: "docker.io/a/b:1.0.0", Digest: pulled}, &model.ImageCheck{TagDigest: pulled, NewerMajor: "2.0.0"}},
		{"rebuilt", report.Container{Image: "docker.io/a/b:latest", Digest: pulled}, &model.ImageCheck{TagDigest: other}},
		{"rebuilt, digests differ in case only", report.Container{Image: "docker.io/a/b:latest", Digest: "sha256:ABCD"}, &model.ImageCheck{TagDigest: "sha256:abcd"}},
		{"no digest from the agent", report.Container{Image: "docker.io/a/b:latest"}, &model.ImageCheck{TagDigest: other}},
		{"no digest from the registry", report.Container{Image: "docker.io/a/b:latest", Digest: pulled}, &model.ImageCheck{}},
		{"never checked", report.Container{Image: "docker.io/a/b:latest", Digest: pulled}, nil},
	}
	for _, tc := range containers {
		t.Run("container: "+tc.name, func(t *testing.T) {
			tc.c.Name = "thing"
			checks := map[string]model.ImageCheck{}
			var check model.ImageCheck
			if tc.check != nil {
				check = *tc.check
				checks[tc.c.Image] = check
			}
			st := model.SystemState{
				Report:     report.Report{System: report.System{Name: "x", Source: "agent"}, Containers: []report.Container{tc.c}},
				ReceivedAt: testNow,
			}
			found := false
			for _, f := range model.Findings([]model.SystemState{st}, checks, testNow, model.DefaultPolicy()) {
				found = found || f.Category == model.CategoryContainer
			}
			if row := imageStatus(tc.c, check, tc.check != nil).Pending; row != found {
				t.Errorf("the row has something newer: %v; the findings name the container: %v", row, found)
			}
		})
	}
}
