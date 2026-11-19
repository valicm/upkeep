package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// The files under testdata/systemd are what "systemctl show" printed for real units;
// testdata/SOURCES.txt says which and how they were brought into each state.

func utc(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		panic(err)
	}
	return t
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestUnitVerdict(t *testing.T) {
	cases := []struct {
		file string // under testdata/systemd
		what string
		want verdict
	}{
		{"logrotate.txt", "a timer's oneshot that worked", verdict{"ok", utc("2026-11-18 23:19:02"), "took 0s"}},
		{"plocate-updatedb.txt", "a longer one", verdict{"ok", utc("2026-11-18 23:25:16"), "took 1m59s"}},
		{"fstrim.txt", "one from days ago", verdict{"ok", utc("2026-11-15 23:49:53"), "took 9m32s"}},
		{"never-ran.txt", "loaded, not run since boot", verdict{}},
		{"succeeded.txt", "exit 0", verdict{"ok", utc("2026-11-18 23:49:07"), "took 2s"}},
		{"running.txt", "in its main command", verdict{"running", utc("2026-11-18 23:49:09"), ""}},
		{"running-pre.txt", "in a step before it", verdict{"running", utc("2026-11-18 23:49:13"), ""}},
		{"failed.txt", "exit 3", verdict{"failed", utc("2026-11-18 23:49:17"), "exit-code 3"}},
		{"failed-reset.txt", "exit 3, then systemctl reset-failed: systemd says success again", verdict{"failed", utc("2026-11-18 23:49:17"), "exit-code 3"}},
		{"pre-failed.txt", "ExecStartPre failed", verdict{"failed", utc("2026-11-18 23:49:18"), "exit-code in a step before the main command"}},
		{"pre-failed-reset.txt", "the same after reset-failed", verdict{"failed", utc("2026-11-18 23:49:18"), "ended before the main command ran"}},
		{"signal.txt", "killed", verdict{"failed", utc("2026-11-18 23:49:19"), "signal 9 (KILL)"}},
		{"timeout.txt", "ran into TimeoutStartSec", verdict{"failed", utc("2026-11-18 23:49:20"), "timeout"}},
		{"success-exit-status.txt", "exit 3 with SuccessExitStatus=3", verdict{"ok", utc("2026-11-18 23:49:24"), "took 1s"}},
		{"simple-running.txt", "a service that is not a oneshot, at work", verdict{"running", utc("2026-11-18 23:49:25"), ""}},
		{"remain-after-exit.txt", "a oneshot with RemainAfterExit, done", verdict{"ok", utc("2026-11-18 23:49:25"), "took 2s"}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			u, err := parseUnit(string(readFile(t, filepath.Join("testdata/systemd", tc.file))))
			if err != nil {
				t.Fatal(err)
			}
			if u.load != "loaded" {
				t.Errorf("LoadState %q, want loaded", u.load)
			}
			got := u.verdict()
			if got.result != tc.want.result || !got.started.Equal(tc.want.started) || got.detail != tc.want.detail {
				t.Errorf("%s:\n got %+v\nwant %+v", tc.what, got, tc.want)
			}
		})
	}
}

func TestParseUnit(t *testing.T) {
	u, err := parseUnit(string(readFile(t, "testdata/systemd/not-found.txt")))
	if err != nil || u.load != "not-found" {
		t.Errorf("a unit that does not exist: load %q, error %v", u.load, err)
	}

	bad := []struct{ name, out, wantErr string }{
		{"nothing", "", "did not say what state"},
		{"an error message instead", "Failed to connect to bus: No such file or directory\n", "did not say what state"},
		// What systemctl prints without TZ=UTC. Go would read "CET" as if it were UTC.
		{"local time", "LoadState=loaded\nActiveState=inactive\nInactiveExitTimestamp=Thu 2026-11-19 00:19:02 CET\n", `"Thu 2026-11-19 00:19:02 CET" is not in UTC`},
		{"not a time", "LoadState=loaded\nActiveState=inactive\nInactiveExitTimestamp=soon UTC\n", "not in the form systemctl prints"},
		{"not a number", "LoadState=loaded\nActiveState=inactive\nExecMainStatus=three\n", "reading ExecMainStatus"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseUnit(tc.out); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestServiceName(t *testing.T) {
	cases := []struct{ in, want, problem string }{
		{"restic-backup.service", "restic-backup.service", ""},
		{"restic-backup", "restic-backup.service", ""},
		{" borg@nas.service ", "borg@nas.service", ""},
		{"backup.daily", "backup.daily.service", ""},
		{"restic-backup.timer", "restic-backup.timer", "not the timer around it"},
		{"", "", "it has no unit"},
		{"--user", "--user", "not a unit name"},
		{"/etc/systemd/system/x.service", "/etc/systemd/system/x.service", "not a unit name"},
	}
	for _, tc := range cases {
		got, problem := serviceName(tc.in)
		if got != tc.want || (tc.problem == "") != (problem == "") || !strings.Contains(problem, tc.problem) {
			t.Errorf("serviceName(%q) = %q, %q; want %q, a problem containing %q", tc.in, got, problem, tc.want, tc.problem)
		}
	}
}

// systemctl answers as the real one did, with the file named by *state.
func systemctl(t *testing.T, unit string, state *string) runner {
	return func(_ context.Context, _ time.Duration, env []string, name string, args ...string) (output, error) {
		want := []string{"show", "--no-pager", "--property=" + shown, "--", unit}
		if name != "systemctl" || strings.Join(args, " ") != strings.Join(want, " ") {
			t.Errorf("ran %s %v, want systemctl %v", name, args, want)
		}
		if !contains(env, "TZ=UTC") {
			t.Error("systemctl was not told to print UTC")
		}
		return output{stdout: readFile(t, filepath.Join("testdata/systemd", *state))}, nil
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// What systemd forgets, the state file keeps: the last run that worked, across a later failure
// and across a restart of the machine and of the agent.
func TestSystemdBackupRemembers(t *testing.T) {
	const noRun = "no run since the machine started, and none seen before that"
	type step struct {
		state string // the file systemctl answers with
		what  string
		want  report.Backup
	}
	backup := func(success, run, result, detail string) report.Backup {
		b := report.Backup{Name: "nightly", Kind: "systemd", LastResult: result, MaxAgeHours: 30, Detail: detail}
		if success != "" {
			b.LastSuccess = utc(success)
		}
		if run != "" {
			b.LastRun = utc(run)
		}
		return b
	}
	sequences := []struct {
		name     string
		stateDir bool // false: the agent has no state directory and one collector lives on
		steps    []step
	}{
		{
			name: "success, failure, reboot, next run", stateDir: true,
			steps: []step{
				{"succeeded.txt", "the first look finds a run that worked", backup("2026-11-18 23:49:07", "2026-11-18 23:49:07", "ok", "took 2s")},
				{"succeeded.txt", "looking again changes nothing", backup("2026-11-18 23:49:07", "2026-11-18 23:49:07", "ok", "took 2s")},
				{"failed.txt", "the next run fails: the success before it is still known", backup("2026-11-18 23:49:07", "2026-11-18 23:49:17", "failed", "exit-code 3")},
				{"failed-reset.txt", "reset-failed does not turn it into a success", backup("2026-11-18 23:49:07", "2026-11-18 23:49:17", "failed", "exit-code 3")},
				{"never-ran.txt", "after a reboot systemd knows nothing; the failure still stands", backup("2026-11-18 23:49:07", "2026-11-18 23:49:17", "failed", "exit-code 3")},
				{"running-pre.txt", "a run in progress is running, with the old success", backup("2026-11-18 23:49:07", "2026-11-18 23:49:13", "running", "")},
				{"never-ran.txt", "the machine went down in that run, which so has no result: the one before it stands", backup("2026-11-18 23:49:07", "2026-11-18 23:49:17", "failed", "exit-code 3")},
				{"running.txt", "the next attempt", backup("2026-11-18 23:49:07", "2026-11-18 23:49:09", "running", "")},
				{"success-exit-status.txt", "and it worked", backup("2026-11-18 23:49:24", "2026-11-18 23:49:24", "ok", "took 1s")},
			},
		},
		{
			name: "before any success was seen", stateDir: true,
			steps: []step{
				{"never-ran.txt", "nothing known at all", backup("", "", "unknown", noRun)},
				{"running.txt", "the first run ever, in progress", backup("", "2026-11-18 23:49:09", "running", "")},
				{"timeout.txt", "it fails: there is no success to report", backup("", "2026-11-18 23:49:20", "failed", "timeout")},
				{"never-ran.txt", "reboot: still a failure, still no success", backup("", "2026-11-18 23:49:20", "failed", "timeout")},
				{"succeeded.txt", "the first success", backup("2026-11-18 23:49:07", "2026-11-18 23:49:07", "ok", "took 2s")},
			},
		},
		{
			name: "without a state directory the memory lasts as long as the process", stateDir: false,
			steps: []step{
				{"succeeded.txt", "", backup("2026-11-18 23:49:07", "2026-11-18 23:49:07", "ok", "took 2s")},
				{"signal.txt", "", backup("2026-11-18 23:49:07", "2026-11-18 23:49:19", "failed", "signal 9 (KILL)")},
			},
		},
	}
	for _, seq := range sequences {
		t.Run(seq.name, func(t *testing.T) {
			t.Setenv("STATE_DIRECTORY", "")
			cfg := Config{Systemd: []SystemdJob{{Name: "nightly", Unit: "restic-backup", MaxAgeHours: 30}}}
			if seq.stateDir {
				cfg.StateDir = filepath.Join(t.TempDir(), "state") // not there yet: the collector makes it
			}
			var state string
			fresh := func() *collector {
				c := New(cfg).(*collector)
				c.run = systemctl(t, "restic-backup.service", &state)
				return c
			}
			c := fresh()
			for i, s := range seq.steps {
				if seq.stateDir {
					c = fresh() // as if the agent had been restarted
				}
				state = s.state
				var r report.Report
				if err := c.Collect(context.Background(), &r); err != nil {
					t.Fatalf("step %d (%s): %v", i+1, s.state, err)
				}
				if len(r.Backups) != 1 {
					t.Fatalf("step %d (%s): %d backups, want 1", i+1, s.state, len(r.Backups))
				}
				if got, want := asJSON(t, r.Backups[0]), asJSON(t, s.want); got != want {
					t.Errorf("step %d (%s): %s\n got %s\nwant %s", i+1, s.state, s.what, got, want)
				}
			}
		})
	}
}

func TestSystemdBackupThatCannotBeAsked(t *testing.T) {
	answer := func(out output, err error) runner {
		return func(context.Context, time.Duration, []string, string, ...string) (output, error) { return out, err }
	}
	const noAnswer = "systemd could not be asked about restic-backup.service"
	cases := []struct {
		name       string
		run        runner
		wantErr    string // a problem in the report, beside the backup as it is remembered
		wantDetail string
	}{
		{"the unit does not exist", answer(output{stdout: readFile(t, "testdata/systemd/not-found.txt")}, nil),
			"backup nightly: systemd has no usable unit restic-backup.service (it is not-found)",
			"systemd has no usable unit restic-backup.service (it is not-found)"},
		{"no systemd on this machine", answer(output{}, fmt.Errorf("systemctl is %w", errNotInstalled)),
			"asking systemd about restic-backup.service: systemctl is not installed", noAnswer},
		{"systemctl fails", answer(output{exit: 1, stderr: []byte("System has not been booted with systemd as init system (PID 1). Can't operate.\nFailed to connect to bus: Host is down\n")}, nil),
			"systemctl ended with status 1: Failed to connect to bus: Host is down", noAnswer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// A success seen earlier must survive a run in which systemd cannot be asked.
			seen := "succeeded.txt"
			before := New(Config{StateDir: dir, Systemd: []SystemdJob{{Name: "nightly", Unit: "restic-backup.service"}}}).(*collector)
			before.run = systemctl(t, "restic-backup.service", &seen)
			if err := before.Collect(context.Background(), &report.Report{}); err != nil {
				t.Fatal(err)
			}

			c := New(Config{StateDir: dir, Systemd: []SystemdJob{{Name: "nightly", Unit: "restic-backup.service"}}}).(*collector)
			c.run = tc.run
			var r report.Report
			check(t, &r, c.Collect(context.Background(), &r), "", tc.wantErr)
			want := report.Backup{Name: "nightly", Kind: "systemd", LastResult: "unknown",
				LastSuccess: utc("2026-11-18 23:49:07"), LastRun: utc("2026-11-18 23:49:07"),
				Detail: tc.wantDetail}
			if len(r.Backups) != 1 || asJSON(t, r.Backups[0]) != asJSON(t, want) {
				t.Errorf("backups %s\nwant one: %s", asJSON(t, r.Backups), asJSON(t, want))
			}
		})
	}
}

// The command line the collector uses, tried on the real systemctl where there is one.
func TestRealSystemctl(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("no systemctl on this machine")
	}
	c := New(Config{}).(*collector)
	u, err := c.showUnit(context.Background(), "upkeep-test-no-such-unit.service")
	if err != nil {
		t.Skipf("systemd cannot be asked here: %v", err)
	}
	if u.load != "not-found" || u.active != "inactive" || !u.started.IsZero() {
		t.Errorf("a unit that does not exist: %+v", u)
	}
}
