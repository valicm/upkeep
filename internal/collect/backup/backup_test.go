package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/valicm/upkeep/internal/report"
)

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// check compares what a run said went wrong with what a case expects: an error returned, which
// is for a run that found nothing, or a problem left in the report beside what was found.
func check(t *testing.T, r *report.Report, err error, wantErr, wantProblem string) {
	t.Helper()
	switch {
	case wantErr == "" && err != nil:
		t.Fatalf("Collect: %v", err)
	case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
		t.Fatalf("Collect: error %v\nwant one containing %q", err, wantErr)
	}
	var problems []string
	for _, p := range r.Errors {
		if p.Collector != "backup" {
			t.Errorf("a problem under the name %q: %s", p.Collector, p.Message)
		}
		problems = append(problems, p.Message)
	}
	switch all := strings.Join(problems, "\n"); {
	case wantProblem == "" && all != "":
		t.Errorf("problems in the report: %s", all)
	case wantProblem != "" && !strings.Contains(all, wantProblem):
		t.Errorf("problems in the report: %q\nwant one containing %q", all, wantProblem)
	}
}

// The opinionated default: with nothing configured, a unit called restic-backup.service is
// reported when the machine has one.
func TestDefaultUnit(t *testing.T) {
	answer := func(file string) runner {
		return func(_ context.Context, _ time.Duration, _ []string, name string, args ...string) (output, error) {
			if name != "systemctl" || args[len(args)-1] != "restic-backup.service" {
				t.Errorf("ran %s %v", name, args)
			}
			return output{stdout: readFile(t, file)}, nil
		}
	}
	never := func(context.Context, time.Duration, []string, string, ...string) (output, error) {
		t.Error("a command was run")
		return output{}, nil
	}
	off := false
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dump.sql"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		cfg  Config
		run  runner
		want []string // names of the backups reported
	}{
		{name: "the machine has the unit", run: answer("testdata/systemd/logrotate.txt"), want: []string{"restic-backup"}},
		{name: "the machine has no such unit", run: answer("testdata/systemd/not-found.txt")},
		{name: "the machine has no systemd", run: func(context.Context, time.Duration, []string, string, ...string) (output, error) {
			return output{}, fmt.Errorf("systemctl is %w", errNotInstalled)
		}},
		{name: "systemd cannot be asked", run: func(context.Context, time.Duration, []string, string, ...string) (output, error) {
			return output{exit: 1, stderr: []byte("Failed to connect to bus: No such file or directory\n")}, nil
		}},
		{name: "something else is configured", cfg: Config{File: []FileJob{{Name: "dump", Path: filepath.Join(dir, "dump.sql")}}}, run: never, want: []string{"dump"}},
		{name: "switched off", cfg: Config{Enabled: &off}, run: never},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("STATE_DIRECTORY", "")
			c := New(tc.cfg).(*collector)
			c.run = tc.run
			var r report.Report
			if err := c.Collect(context.Background(), &r); err != nil {
				t.Fatalf("Collect: %v", err)
			}
			var names []string
			for _, b := range r.Backups {
				names = append(names, b.Name)
			}
			if strings.Join(names, ",") != strings.Join(tc.want, ",") {
				t.Errorf("backups %v, want %v", names, tc.want)
			}
			if len(tc.want) == 0 && r.Backups != nil {
				t.Error("Backups is not nil: an empty part means this source does not look")
			}
		})
	}

	t.Run("what the default reports", func(t *testing.T) {
		t.Setenv("STATE_DIRECTORY", "")
		c := New(Config{}).(*collector)
		c.run = answer("testdata/systemd/plocate-updatedb.txt")
		var r report.Report
		if err := c.Collect(context.Background(), &r); err != nil {
			t.Fatal(err)
		}
		want := []report.Backup{{Name: "restic-backup", Kind: "systemd", LastResult: "ok",
			LastSuccess: utc("2026-11-18 23:25:16"), LastRun: utc("2026-11-18 23:25:16"), Detail: "took 1m59s"}}
		if got := asJSON(t, r.Backups); got != asJSON(t, want) {
			t.Errorf("got %s\nwant %s", got, asJSON(t, want))
		}
	})
}

// Once the default unit was reported, a run in which systemd does not answer says so instead of
// dropping the backup; a unit that was removed goes without a word.
func TestDefaultUnitOnceSeen(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", "")
	dir := t.TempDir()
	look := func(out output, runErr error, wantProblem string) []report.Backup {
		t.Helper()
		c := New(Config{StateDir: dir}).(*collector)
		c.run = func(context.Context, time.Duration, []string, string, ...string) (output, error) { return out, runErr }
		var r report.Report
		check(t, &r, c.Collect(context.Background(), &r), "", wantProblem)
		return r.Backups
	}
	seen := utc("2026-11-18 23:25:16")
	silent := errors.New("systemctl did not finish within 15s")

	if got := look(output{stdout: readFile(t, "testdata/systemd/plocate-updatedb.txt")}, nil, ""); len(got) != 1 || got[0].LastResult != "ok" {
		t.Fatalf("the first look: %s", asJSON(t, got))
	}

	got := look(output{}, silent, "backup restic-backup: asking systemd about restic-backup.service: systemctl did not finish within 15s")
	want := []report.Backup{{Name: "restic-backup", Kind: "systemd", LastSuccess: seen, LastRun: seen, LastResult: "unknown",
		Detail: "systemd could not be asked about restic-backup.service"}}
	if asJSON(t, got) != asJSON(t, want) {
		t.Errorf("systemd does not answer: %s\nwant %s", asJSON(t, got), asJSON(t, want))
	}

	if got := look(output{stdout: readFile(t, "testdata/systemd/not-found.txt")}, nil, ""); got != nil {
		t.Errorf("the unit was removed: %s", asJSON(t, got))
	}
	if got := look(output{}, silent, ""); got != nil {
		t.Errorf("after the removal nothing is expected of systemd: %s", asJSON(t, got))
	}
}

// A job that is configured wrongly is left out and said so at every run; the others still run.
func TestConfigProblems(t *testing.T) {
	dir := t.TempDir()
	good := FileJob{Name: "dump", Path: filepath.Join(dir, "dump.sql")}
	cases := []struct {
		name    string
		cfg     Config
		wantErr string // a problem in the report: the job that is configured well is found
	}{
		{"systemd job without a unit", Config{Systemd: []SystemdJob{{Name: "x"}}}, `backup "x" in the configuration is left out: it has no unit`},
		{"systemd job naming the timer", Config{Systemd: []SystemdJob{{Unit: "restic-backup.timer"}}}, `backup "restic-backup.timer" in the configuration is left out: its unit must be the service that does the backup, not the timer around it`},
		{"file job without a path", Config{File: []FileJob{{Name: "x"}}}, "it has no path"},
		{"restic job without a repository", Config{Restic: []ResticJob{{Name: "x", PasswordFile: "/p"}}}, "it needs env_file, or repository_file (or repository) with password_file"},
		{"restic job without a password", Config{Restic: []ResticJob{{Name: "x", Repository: "/srv/repo"}}}, "it needs password_file (or env_file)"},
		{"restic job with two repositories", Config{Restic: []ResticJob{{Name: "x", Repository: "/a", RepositoryFile: "/b", PasswordFile: "/p"}}}, "it has both repository and repository_file"},
		{"negative age", Config{File: []FileJob{{Name: "x", Path: "/x", MaxAgeHours: -1}}}, "max_age_hours must not be negative"},
		{"two jobs with one name", Config{Restic: []ResticJob{{Name: "dump", EnvFile: "/etc/restic/env"}}}, `backup "dump" in the configuration is left out: another backup has the same name`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("STATE_DIRECTORY", "")
			tc.cfg.File = append([]FileJob{good}, tc.cfg.File...)
			c := New(tc.cfg).(*collector)
			c.run = func(context.Context, time.Duration, []string, string, ...string) (output, error) {
				t.Error("a command was run for a job that is left out")
				return output{}, nil
			}
			for range 2 {
				var r report.Report
				check(t, &r, c.Collect(context.Background(), &r), "", tc.wantErr)
				if len(r.Backups) != 1 || r.Backups[0].Name != "dump" {
					t.Errorf("backups %s, want only the one that is configured well", asJSON(t, r.Backups))
				}
			}
		})
	}
}

// With nothing to report, what is wrong is the collector's error, on one line.
func TestOnlyProblems(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", "")
	c := New(Config{
		Systemd: []SystemdJob{{Name: "a"}},
		File:    []FileJob{{Name: "b"}},
	})
	var r report.Report
	err := c.Collect(context.Background(), &r)
	const want = `backup "a" in the configuration is left out: it has no unit; backup "b" in the configuration is left out: it has no path`
	if err == nil || err.Error() != want {
		t.Errorf("error %v\nwant  %s", err, want)
	}
	if r.Backups != nil || r.Errors != nil {
		t.Errorf("the report was touched: %s", asJSON(t, r))
	}
}

// The configuration file as its owner writes it, read with the library the agent uses.
func TestConfigFromTOML(t *testing.T) {
	const file = `
[backups]
enabled = true

[[backups.systemd]]
unit = "restic-backup.service"
max_age_hours = 26

[[backups.file]]
name = "opnsense config"
path = "/srv/backups/opnsense/config-*.xml"
max_age_hours = 48

[[backups.restic]]
name = "storage pi"
env_file = "/var/lib/materia/components/restic-backup/restic-backup.env"
host = "server"
tag = "nightly"

[[backups.restic]]
name = "local copy"
repository_file = "/etc/restic/repository"
password_file = "/etc/restic/password"
`
	var got struct {
		Backups Config `toml:"backups"`
	}
	if err := toml.Unmarshal([]byte(file), &got); err != nil {
		t.Fatal(err)
	}
	on := true
	want := Config{
		Enabled: &on,
		Systemd: []SystemdJob{{Unit: "restic-backup.service", MaxAgeHours: 26}},
		File:    []FileJob{{Name: "opnsense config", Path: "/srv/backups/opnsense/config-*.xml", MaxAgeHours: 48}},
		Restic: []ResticJob{
			{Name: "storage pi", EnvFile: "/var/lib/materia/components/restic-backup/restic-backup.env", Host: "server", Tag: "nightly"},
			{Name: "local copy", RepositoryFile: "/etc/restic/repository", PasswordFile: "/etc/restic/password"},
		},
	}
	if asJSON(t, got.Backups) != asJSON(t, want) {
		t.Errorf("got %s\nwant %s", asJSON(t, got.Backups), asJSON(t, want))
	}
	c := New(got.Backups).(*collector)
	if len(c.invalid) != 0 || len(c.systemd) != 1 || c.systemd[0].Name != "restic-backup" || len(c.file) != 1 || len(c.restic) != 2 {
		t.Errorf("the collector made of it: %+v", c)
	}

	var none struct {
		Backups Config `toml:"backups"`
	}
	if err := toml.Unmarshal([]byte("[backups]\nenabled = false\n"), &none); err != nil {
		t.Fatal(err)
	}
	if New(none.Backups).(*collector).enabled {
		t.Error("enabled = false did not switch the collector off")
	}
	if !New(Config{}).(*collector).enabled {
		t.Error("the collector is off without being told so")
	}
}

func TestStateDirectory(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", "/var/lib/upkeep:/var/lib/other")
	if got := New(Config{}).(*collector).stateDir; got != "/var/lib/upkeep" {
		t.Errorf("state directory %q, want systemd's first", got)
	}
	if got := New(Config{StateDir: "/srv/state"}).(*collector).stateDir; got != "/srv/state" {
		t.Errorf("state directory %q, want the configured one", got)
	}
}

func TestStateFile(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", "")
	dir := t.TempDir()
	path := filepath.Join(dir, stateFile)
	state := "succeeded.txt"
	collect := func(wantProblem string) {
		t.Helper()
		c := New(Config{StateDir: dir, Systemd: []SystemdJob{{Unit: "restic-backup.service"}}}).(*collector)
		c.run = systemctl(t, "restic-backup.service", &state)
		var r report.Report
		check(t, &r, c.Collect(context.Background(), &r), "", wantProblem)
		if len(r.Backups) != 1 || r.Backups[0].LastResult != "ok" {
			t.Errorf("backups %s, want the one job reported", asJSON(t, r.Backups))
		}
	}

	collect("")
	const want = `{
  "jobs": {
    "systemd:restic-backup.service": {
      "last_success": "2026-11-18T23:49:07Z",
      "last_run": "2026-11-18T23:49:07Z",
      "last_result": "ok",
      "detail": "took 2s"
    }
  }
}
`
	if got := string(readFile(t, path)); got != want {
		t.Errorf("state file:\n%s\nwant:\n%s", got, want)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %v, error %v; want 0600", info.Mode().Perm(), err)
	}

	// A run that changes nothing must not write: the directory may be on an SD card.
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	collect("")
	if info, _ := os.Stat(path); !info.ModTime().Equal(old) {
		t.Error("the state file was written again although nothing changed")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 1 {
		t.Errorf("files left in the state directory: %v", left)
	}

	// A damaged file is said once and replaced; the backup is reported all the same.
	if err := os.WriteFile(path, []byte("{half"), 0o600); err != nil {
		t.Fatal(err)
	}
	collect("is damaged and will be replaced")
	if got := string(readFile(t, path)); got != want {
		t.Errorf("state file after the damage:\n%s", got)
	}
	collect("")

	// A state directory that cannot be used is a problem, not a reason to stop reporting.
	dir = filepath.Join(path, "below-a-file")
	collect("remembering the backups seen: mkdir " + path + ": not a directory")
}

func TestSize(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"}, {1023, "1023 B"}, {1024, "1.0 KiB"}, {200000, "195 KiB"}, {355757, "347 KiB"},
		{1500000, "1.4 MiB"}, {44023414784, "41 GiB"}, {5 << 40, "5.0 TiB"},
	}
	for _, tc := range cases {
		if got := size(tc.n); got != tc.want {
			t.Errorf("size(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// execute against real commands: what a command prints and how it ends must come back as it was.
func TestExecute(t *testing.T) {
	ctx := context.Background()
	out, err := execute(ctx, 10*time.Second, nil, "sh", "-c", "echo out; echo err >&2; exit 3")
	if err != nil || out.exit != 3 || string(out.stdout) != "out\n" || string(out.stderr) != "err\n" {
		t.Errorf("a command that fails: %+v, %v", out, err)
	}
	out, err = execute(ctx, 10*time.Second, []string{"UPKEEP_TEST=from the job"}, "sh", "-c", `echo "$UPKEEP_TEST"`)
	if err != nil || out.exit != 0 || string(out.stdout) != "from the job\n" {
		t.Errorf("a command with its own environment: %+v, %v", out, err)
	}
	if _, err = execute(ctx, 10*time.Second, nil, "upkeep-test-no-such-command"); !errors.Is(err, errNotInstalled) {
		t.Errorf("a command that is not there: %v", err)
	}
	start := time.Now()
	_, err = execute(ctx, 200*time.Millisecond, nil, "sleep", "30")
	if err == nil || err.Error() != "sleep did not finish within 200ms" {
		t.Errorf("a command that hangs: %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("gave up after %s", took)
	}
	gone, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = execute(gone, 10*time.Second, nil, "sleep", "30"); !errors.Is(err, context.Canceled) {
		t.Errorf("the agent is stopping: %v", err)
	}
}
