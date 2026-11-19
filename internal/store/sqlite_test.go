package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
)

// What only the SQLite store can be asked: does it survive a restart, is the file what the
// server promises (WAL, a schema version), and does it refuse what it cannot read.

func TestSQLiteSurvivesReopen(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "upkeep.db")
	s, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	want := fullReport("server")
	check := model.ImageCheck{Image: "docker.io/henrygd/beszel:0.21.2", Tag: "0.21.2", NewerPatch: "0.21.4", CheckedAt: arrived}
	if err := errors.Join(
		s.SaveReport(ctx, want, arrived),
		s.SaveImageCheck(ctx, check),
		s.SetValue(ctx, "mail.sent", "2026-11-19T07:00:00Z"),
		s.Close(),
	); err != nil {
		t.Fatal(err)
	}

	s, err = OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.System(ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	sameReport(t, got.Report, want)
	if !got.ReceivedAt.Equal(arrived) {
		t.Errorf("ReceivedAt = %v, want %v", got.ReceivedAt, arrived)
	}
	checks, err := s.ImageChecks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c := checks[check.Image]; c.NewerPatch != "0.21.4" || !c.CheckedAt.Equal(arrived) {
		t.Errorf("the check did not survive: %+v", c)
	}
	if v, err := s.Value(ctx, "mail.sent"); v != "2026-11-19T07:00:00Z" || err != nil {
		t.Errorf("the value did not survive: %q, %v", v, err)
	}
}

func TestSQLiteFile(t *testing.T) {
	ctx := t.Context()
	// A directory name SQLite's URI syntax would trip over if the path were not escaped.
	dir := filepath.Join(t.TempDir(), "data #1?x=y %41")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "upkeep.db")
	s, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the database is not where it was asked to be: %v", err)
	}
	var mode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q, %v; want wal", mode, err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != len(migrations) {
		t.Errorf("user_version = %d, %v; want %d", version, err, len(migrations))
	}
	var timeout int
	if err := s.db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != 5000 {
		t.Errorf("busy_timeout = %d, %v; want 5000", timeout, err)
	}
}

func TestSQLiteRefuses(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name    string
		prepare func(t *testing.T) string // returns the path to open
		want    string                    // must be in the error
	}{
		{
			name: "a database written by a newer upkeep",
			prepare: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "upkeep.db")
				s, err := OpenSQLite(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.ExecContext(ctx, `PRAGMA user_version = 99`); err != nil {
					t.Fatal(err)
				}
				s.Close()
				return path
			},
			want: "newer upkeep",
		},
		{
			name:    "a directory that does not exist",
			prepare: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing", "upkeep.db") },
			want:    "missing",
		},
		{
			name: "a file that is not a database",
			prepare: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "upkeep.db")
				if err := os.WriteFile(path, []byte(strings.Repeat("this is not a database\n", 100)), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			want: "opening the database",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.prepare(t)
			s, err := OpenSQLite(ctx, path)
			if err == nil {
				s.Close()
				t.Fatal("opened without an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not say %q", err, tt.want)
			}
		})
	}
}

func TestSQLiteStopsWithItsContext(t *testing.T) {
	s := openTestSQLite(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.SaveReport(ctx, smallReport("server"), arrived); !errors.Is(err, context.Canceled) {
		t.Errorf("SaveReport with a cancelled context: %v", err)
	}
	if _, err := s.Systems(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Systems with a cancelled context: %v", err)
	}
}

// A report that cannot be read must be named, not skipped: silently dropping a system from
// the dashboard is the one thing this program must not do.
func TestSQLiteNamesABrokenRow(t *testing.T) {
	ctx := t.Context()
	s := openTestSQLite(t)
	if err := s.SaveReport(ctx, smallReport("server"), arrived); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE systems SET report = '{"schema": "one"' WHERE name = 'server'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Systems(ctx); err == nil || !strings.Contains(err.Error(), "server") {
		t.Errorf("Systems = %v; want an error naming the system", err)
	}
	if _, err := s.System(ctx, "server"); err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		t.Errorf("System = %v; want an error that is not 'not found'", err)
	}
}

func TestTimeText(t *testing.T) {
	tests := []struct {
		name string
		in   time.Time
		text string
	}{
		{"never", time.Time{}, ""},
		{"utc", time.Date(2026, 11, 19, 6, 30, 15, 0, time.UTC), "2026-11-19T06:30:15Z"},
		{"another zone becomes utc", time.Date(2026, 11, 19, 7, 30, 15, 5000, time.FixedZone("CET", 3600)), "2026-11-19T06:30:15.000005Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := formatTime(tt.in)
			if text != tt.text {
				t.Errorf("formatTime = %q, want %q", text, tt.text)
			}
			back, err := parseTime(text)
			if err != nil || !back.Equal(tt.in) {
				t.Errorf("parseTime(%q) = %v, %v; want %v", text, back, err, tt.in)
			}
		})
	}
	if _, err := parseTime("yesterday"); err == nil {
		t.Error("parseTime accepted nonsense")
	}
}

// A database a version 1 server left behind is brought up to date, and what it held is still
// there: a server is upgraded by replacing its binary.
func TestSQLiteUpgradesAnOlderFile(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "upkeep.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		migrations[0],
		`PRAGMA user_version = 1`,
		`INSERT INTO image_checks (image, tag, tag_digest, newer_patch, newer_minor, newer_major, checked_at, error)
		 VALUES ('docker.io/gitea/gitea:1.23.6', '1.23.6', 'sha256:aa', '1.23.8', '', '', '2026-11-19T06:30:15Z', '')`,
	} {
		if _, err := old.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checks, err := s.ImageChecks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := checks["docker.io/gitea/gitea:1.23.6"]
	if got.NewerPatch != "1.23.8" || got.Note != "" || got.CheckedAt.IsZero() {
		t.Errorf("the old check after the upgrade: %+v", got)
	}
	got.Note = "a remark"
	if err := s.SaveImageCheck(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.ImageChecks(ctx); again[got.Image].Note != "a remark" {
		t.Errorf("the note was not kept: %+v", again[got.Image])
	}
}
