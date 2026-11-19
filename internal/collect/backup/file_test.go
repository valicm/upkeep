package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// These files are made by the test: what counts is their time and size, and a capture could
// not keep either.
func TestFileBackup(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 11, d, 2, 15, 0, 0, time.UTC) }
	root := t.TempDir()
	put := func(name string, bytes int, mod time.Time) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, make([]byte, bytes), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	// An appliance that drops one file a night.
	put("opnsense/config-2026-11-16.xml", 150000, day(16))
	put("opnsense/config-2026-11-17.xml", 150200, day(17))
	put("opnsense/config-2026-11-18.xml", 1500000, day(18))
	put("opnsense/notes.txt", 10, day(19))
	put("opnsense/.config-2026-11-19.xml.part", 4096, day(19)) // a transfer in progress
	put("opnsense/old/config-2026-11-20.xml", 9, day(20))      // one level only
	// One whose latest run left an empty file.
	put("switch/running-config-1.cfg", 20480, day(14))
	put("switch/running-config-2.cfg", 0, day(15))
	// One that has only ever left empty files.
	put("broken/a.tar", 0, day(10))
	// A single file that is overwritten every time.
	put("ha/latest.tar", 44023414784>>20, day(18))
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		path    string
		want    report.Backup
		wantErr string
	}{
		{name: "a pattern", path: "opnsense/config-*.xml",
			want: report.Backup{LastSuccess: day(18), LastRun: day(18), LastResult: "ok", Detail: "config-2026-11-18.xml, 1.4 MiB"}},
		{name: "a directory: its files, not hidden ones, not those further down", path: "opnsense",
			want: report.Backup{LastSuccess: day(19), LastRun: day(19), LastResult: "ok", Detail: "notes.txt, 10 B"}},
		{name: "a pattern that matches directories", path: "o*",
			want: report.Backup{LastSuccess: day(19), LastRun: day(19), LastResult: "ok", Detail: "notes.txt, 10 B"}},
		{name: "one file", path: "ha/latest.tar",
			want: report.Backup{LastSuccess: day(18), LastRun: day(18), LastResult: "ok", Detail: "latest.tar, 41 KiB"}},
		{name: "the newest file is empty", path: "switch/*.cfg",
			want: report.Backup{LastSuccess: day(14), LastRun: day(15), LastResult: "failed", Detail: "running-config-2.cfg is empty"}},
		{name: "only empty files", path: "broken",
			want: report.Backup{LastRun: day(10), LastResult: "failed", Detail: "a.tar is empty"}},
		{name: "nothing matches", path: "opnsense/*.tar.gz",
			want: report.Backup{LastResult: "unknown", Detail: "no file matches " + filepath.Join(root, "opnsense/*.tar.gz")}},
		{name: "an empty directory", path: "empty",
			want: report.Backup{LastResult: "unknown", Detail: "no file matches " + filepath.Join(root, "empty")}},
		{name: "a path that is not there", path: "nas-not-mounted/backup.tar",
			want: report.Backup{LastResult: "unknown", Detail: "no file matches " + filepath.Join(root, "nas-not-mounted/backup.tar")}},
		{name: "a pattern that is not one", path: "opnsense/[",
			want:    report.Backup{LastResult: "unknown", Detail: "could not look for " + filepath.Join(root, "opnsense/[")},
			wantErr: "the pattern is not valid"},
		{name: "a file used as a directory", path: "ha/latest.tar/x",
			want:    report.Backup{LastResult: "unknown", Detail: "could not look for " + filepath.Join(root, "ha/latest.tar/x")},
			wantErr: "not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.want.Name, tc.want.Kind, tc.want.MaxAgeHours = "appliance", "file", 26
			got, err := fileBackup(FileJob{Name: "appliance", Path: filepath.Join(root, tc.path), MaxAgeHours: 26})
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatal(err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error %v, want one containing %q", err, tc.wantErr)
			}
			if asJSON(t, got) != asJSON(t, tc.want) {
				t.Errorf("got %s\nwant %s", asJSON(t, got), asJSON(t, tc.want))
			}
		})
	}
}
