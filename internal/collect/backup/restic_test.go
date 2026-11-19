package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// The files under testdata/restic are what restic 0.18.0, the version in Debian 13, printed
// for a repository made for this purpose; testdata/SOURCES.txt has the details.

// The credentials the tests give restic. None of them may ever show in a report or an error.
const (
	restPassword = "rest-server-pw-7f3a"
	repoPassword = "repository-pw-91bc"
	envFile      = "# written by the homelab's restic-backup component\n" +
		"RESTIC_REPOSITORY=rest:http://server:" + restPassword + "@127.0.0.1:8000/server/\n" +
		"RESTIC_PASSWORD=" + repoPassword + "\n" +
		"RESTIC_CACHE_DIR=/var/cache/restic\n"
)

func TestResticBackup(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", "")
	dir := t.TempDir()
	env := filepath.Join(dir, "restic-backup.env")
	if err := os.WriteFile(env, []byte(envFile), 0o600); err != nil {
		t.Fatal(err)
	}
	file := func(name string) []byte { return readFile(t, filepath.Join("testdata/restic", name)) }
	newest := time.Date(2026, 11, 18, 23, 50, 26, 871915251, time.UTC)
	nightly := time.Date(2026, 11, 18, 23, 50, 23, 180364971, time.UTC)
	const cannot = "the repository could not be read"

	cases := []struct {
		name     string
		job      ResticJob
		out      output // what restic printed and how it ended
		runErr   error  // or why it did not end
		wantArgs string
		wantEnv  []string
		want     report.Backup
		wantErr  string // a problem in the report, beside the backup as it is remembered
	}{
		{
			name:     "the newest snapshot of all",
			job:      ResticJob{EnvFile: env},
			out:      output{stdout: file("latest-all.json")},
			wantArgs: "snapshots --json --no-lock --latest 1",
			wantEnv: []string{
				"RESTIC_REPOSITORY=rest:http://server:" + restPassword + "@127.0.0.1:8000/server/",
				"RESTIC_PASSWORD=" + repoPassword,
				"RESTIC_CACHE_DIR=/var/cache/restic",
			},
			want: report.Backup{LastSuccess: newest, LastRun: newest, LastResult: "ok", Detail: "snapshot e0bc8a50, 195 KiB"},
		},
		{
			name:     "one host",
			job:      ResticJob{EnvFile: env, Host: "server"},
			out:      output{stdout: file("latest-host-server.json")},
			wantArgs: "snapshots --json --no-lock --latest 1 --host server",
			want:     report.Backup{LastSuccess: newest, LastRun: newest, LastResult: "ok", Detail: "snapshot e0bc8a50, 195 KiB"},
		},
		{
			name:     "one host and one tag, repository and password from files",
			job:      ResticJob{RepositoryFile: "/etc/restic/repository", PasswordFile: "/etc/restic/password", Host: "server", Tag: "nightly"},
			out:      output{stdout: file("latest-host-server-tag-nightly.json")},
			wantArgs: "snapshots --json --no-lock --latest 1 --host server --tag nightly",
			wantEnv:  []string{"RESTIC_REPOSITORY_FILE=/etc/restic/repository", "RESTIC_PASSWORD_FILE=/etc/restic/password"},
			want:     report.Backup{LastSuccess: nightly, LastRun: nightly, LastResult: "ok", Detail: "snapshot 83f0630d, 347 KiB"},
		},
		{
			name:    "a repository named in the configuration",
			job:     ResticJob{Repository: "/srv/restic", PasswordFile: "/etc/restic/password"},
			out:     output{stdout: file("latest-all.json")},
			wantEnv: []string{"RESTIC_REPOSITORY=/srv/restic", "RESTIC_PASSWORD_FILE=/etc/restic/password"},
			want:    report.Backup{LastSuccess: newest, LastRun: newest, LastResult: "ok", Detail: "snapshot e0bc8a50, 195 KiB"},
		},
		{
			name: "a host that has no snapshot",
			job:  ResticJob{EnvFile: env, Host: "nobody"},
			out:  output{stdout: file("latest-host-nobody.json")},
			want: report.Backup{LastResult: "unknown", Detail: "the repository has no snapshot of host nobody"},
		},
		{
			name: "a new repository",
			job:  ResticJob{EnvFile: env, Tag: "nightly"},
			out:  output{stdout: file("empty.json")},
			want: report.Backup{LastResult: "unknown", Detail: "the repository has no snapshot with tag nightly"},
		},
		{
			name:    "wrong password",
			job:     ResticJob{EnvFile: env},
			out:     output{exit: 12, stderr: file("wrong-password.stderr")},
			want:    report.Backup{LastResult: "unknown", Detail: cannot},
			wantErr: "backup storage: asking restic for the snapshots: restic ended with status 12: Fatal: wrong password or no key found",
		},
		{
			name:    "no repository there",
			job:     ResticJob{EnvFile: env},
			out:     output{exit: 10, stderr: file("no-repo.stderr")},
			want:    report.Backup{LastResult: "unknown", Detail: cannot},
			wantErr: "restic ended with status 10: Fatal: repository does not exist: unable to open config file: stat /work/no-such-repo/config: no such file or directory",
		},
		{
			// The repository's server is down: restic retries until it is stopped. The reason
			// is in its retries, not in its last word ("context canceled").
			name:    "the server does not answer",
			job:     ResticJob{EnvFile: env},
			out:     output{stderr: file("unreachable.stderr")},
			runErr:  errors.New("restic did not finish within 2m0s"),
			want:    report.Backup{LastResult: "unknown", Detail: cannot},
			wantErr: `asking restic for the snapshots: restic did not finish within 2m0s: Head "http://***@127.0.0.1:9/backupuser/config": dial tcp 127.0.0.1:9: connect: connection refused`,
		},
		{
			name:    "restic is not installed",
			job:     ResticJob{EnvFile: env},
			runErr:  fmt.Errorf("restic is %w", errNotInstalled),
			want:    report.Backup{LastResult: "unknown", Detail: cannot},
			wantErr: "backup storage: asking restic for the snapshots: restic is not installed",
		},
		{
			name:    "something else than a list",
			job:     ResticJob{EnvFile: env},
			out:     output{stdout: []byte("repository 1a2b3c4d opened\n")},
			want:    report.Backup{LastResult: "unknown", Detail: cannot},
			wantErr: "its answer is not the list expected",
		},
		{
			// What restic prints is not trusted to be free of secrets.
			name: "an error that spells out the credentials",
			job:  ResticJob{EnvFile: env},
			out: output{exit: 1, stderr: []byte("Fatal: unable to open repository at rest:http://server:" + restPassword +
				"@127.0.0.1:8000/server/: password " + repoPassword + " rejected, " + restPassword + " too\n")},
			want:    report.Backup{LastResult: "unknown", Detail: cannot},
			wantErr: "restic ended with status 1: Fatal: unable to open repository at ***: password *** rejected, *** too",
		},
		{
			name:    "an environment file that is not there",
			job:     ResticJob{EnvFile: filepath.Join(dir, "missing.env")},
			want:    report.Backup{LastResult: "unknown", Detail: cannot},
			wantErr: "backup storage: reading restic's settings: open " + filepath.Join(dir, "missing.env"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.job.Name, tc.job.MaxAgeHours = "storage", 30
			tc.want.Name, tc.want.Kind, tc.want.MaxAgeHours = "storage", "restic", 30
			c := New(Config{Restic: []ResticJob{tc.job}}).(*collector)
			ran := false
			c.run = func(_ context.Context, timeout time.Duration, env []string, name string, args ...string) (output, error) {
				ran = true
				if name != "restic" || timeout != resticTimeout {
					t.Errorf("ran %s for at most %s", name, timeout)
				}
				if got := strings.Join(args, " "); tc.wantArgs != "" && got != tc.wantArgs {
					t.Errorf("arguments %q, want %q", got, tc.wantArgs)
				}
				for _, a := range args {
					if strings.Contains(a, "Password") || strings.Contains(a, "-pw-") || strings.Contains(a, "://") {
						t.Errorf("argument %q: credentials belong in the environment", a)
					}
				}
				for _, want := range tc.wantEnv {
					if !contains(env, want) {
						t.Errorf("the environment lacks %s", strings.SplitN(want, "=", 2)[0])
					}
				}
				return tc.out, tc.runErr
			}
			var r report.Report
			check(t, &r, c.Collect(context.Background(), &r), "", tc.wantErr)
			if len(r.Backups) != 1 || asJSON(t, r.Backups[0]) != asJSON(t, tc.want) {
				t.Errorf("backups %s\nwant one: %s", asJSON(t, r.Backups), asJSON(t, tc.want))
			}
			if !ran && !strings.Contains(tc.name, "environment file") {
				t.Error("restic was not run")
			}
			said := asJSON(t, r)
			for _, secret := range []string{restPassword, repoPassword} {
				if strings.Contains(said, secret) {
					t.Errorf("a credential got out: %s", strings.ReplaceAll(said, secret, "<HERE>"))
				}
			}
		})
	}
}

// A repository that cannot be reached today still has the backup it had yesterday.
func TestResticBackupRemembers(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", "")
	dir := t.TempDir()
	answers := []struct {
		out  output
		err  error
		want string // last result
	}{
		{out: output{stdout: readFile(t, "testdata/restic/latest-host-server.json")}, want: "ok"},
		{out: output{stderr: readFile(t, "testdata/restic/unreachable.stderr")}, err: errors.New("restic did not finish within 2m0s"), want: "unknown"},
		{out: output{exit: 12, stderr: readFile(t, "testdata/restic/wrong-password.stderr")}, want: "unknown"},
	}
	newest := time.Date(2026, 11, 18, 23, 50, 26, 871915251, time.UTC)
	for i, a := range answers {
		c := New(Config{StateDir: dir, Restic: []ResticJob{{Name: "storage", Repository: "/srv/restic", PasswordFile: "/etc/restic/password"}}}).(*collector)
		c.run = func(context.Context, time.Duration, []string, string, ...string) (output, error) { return a.out, a.err }
		var r report.Report
		if err := c.Collect(context.Background(), &r); err != nil || (len(r.Errors) != 0) != (a.want != "ok") {
			t.Errorf("run %d: error %v, problems %v", i+1, err, r.Errors)
		}
		if len(r.Backups) != 1 || r.Backups[0].LastResult != a.want || !r.Backups[0].LastSuccess.Equal(newest) {
			t.Errorf("run %d: %s\nwant result %q and the last success of the first run", i+1, asJSON(t, r.Backups), a.want)
		}
	}
	if raw := string(readFile(t, filepath.Join(dir, stateFile))); !strings.Contains(raw, `"restic:storage"`) || strings.Contains(raw, "/srv/restic") {
		t.Errorf("the state file must name the job and not the repository:\n%s", raw)
	}
}

func TestParseEnv(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string // NAME=value pairs, one per line
		wantErr string
	}{
		{name: "the homelab's file", in: envFile,
			want: "RESTIC_REPOSITORY=rest:http://server:" + restPassword + "@127.0.0.1:8000/server/\nRESTIC_PASSWORD=" + repoPassword + "\nRESTIC_CACHE_DIR=/var/cache/restic"},
		{name: "comments and blank lines", in: "# one\n; two\n\n  \nA=1\n", want: "A=1"},
		{name: "quotes", in: "A=\"with space\"\nB='single $HOME'\nC=\"say \\\"hi\\\" \\\\ \\$x\"\nD=\"\"\n",
			want: "A=with space\nB=single $HOME\nC=say \"hi\" \\ $x\nD="},
		{name: "what stays as it is", in: "A=a=b#c\nB=  padded  \nC=it's\nD=\"open\n",
			want: "A=a=b#c\nB=padded\nC=it's\nD=\"open"},
		{name: "a file a shell also reads", in: "export AWS_ACCESS_KEY_ID=abc\n", want: "AWS_ACCESS_KEY_ID=abc"},
		{name: "no newline at the end", in: "A=1", want: "A=1"},
		{name: "empty", in: "", want: ""},
		// The line's text is not repeated: it may be the password.
		{name: "a line that is no assignment", in: "A=1\n" + repoPassword + "\n", wantErr: "line 2 is not NAME=value"},
		{name: "a name that is none", in: "MY-VAR=" + repoPassword + "\n", wantErr: "line 1 is not NAME=value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vars, err := parseEnv(strings.NewReader(tc.in))
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, v := range vars {
				got = append(got, v.name+"="+v.value)
			}
			if strings.Join(got, "\n") != tc.want {
				t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), tc.want)
			}
		})
	}
}

func TestResticMessage(t *testing.T) {
	secrets := []string{"rest:http://server:" + restPassword + "@127.0.0.1:8000/server/", repoPassword, "/var/cache/restic", "abc"}
	cases := []struct {
		name     string
		stderr   string
		finished bool
		want     string
	}{
		{"restic's last word", string(readFile(t, "testdata/restic/wrong-password.stderr")), true, "Fatal: wrong password or no key found"},
		{"only its first line", string(readFile(t, "testdata/restic/no-repo.stderr")), true,
			"Fatal: repository does not exist: unable to open config file: stat /work/no-such-repo/config: no such file or directory"},
		{"stopped while it retried", string(readFile(t, "testdata/restic/unreachable.stderr")), false,
			`Head "http://***@127.0.0.1:9/backupuser/config": dial tcp 127.0.0.1:9: connect: connection refused`},
		{"finished after retries", string(readFile(t, "testdata/restic/unreachable.stderr")), true, "Fatal: unable to open config file: context canceled"},
		{"plain text", "warning: something\nFatal: no such thing\n", true, "Fatal: no such thing"},
		{"nothing", "", true, ""},
		{"the password alone", "bad key " + repoPassword + "\n", true, "bad key ***"},
		{"the password inside an address", "open http://server:" + restPassword + "@host/x\n", true, "open http://***@host/x"},
		{"an address with other credentials", "open s3:https://key:secretsecret@s3.example/bucket\n", true, "open s3:https://***@s3.example/bucket"},
		{"a short value is left alone", "abc is not secret here\n", true, "abc is not secret here"},
		{"terminal codes", "\x1b[2Ksignal interrupt received, cleaning up\n", true, "signal interrupt received, cleaning up"},
		{"a very long line", strings.Repeat("x", 500) + "\n", true, strings.Repeat("x", 300) + "..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resticMessage([]byte(tc.stderr), secrets, tc.finished); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// The whole way with the real restic, where it is installed: a repository in a temporary
// directory, one backup, and the collector's look at it. No network is involved.
func TestRealRestic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped with -short: restic derives its key slowly on purpose")
	}
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("no restic on this machine")
	}
	t.Setenv("STATE_DIRECTORY", "")
	dir := t.TempDir()
	repo, password, wrong, data := filepath.Join(dir, "repo"), filepath.Join(dir, "password"), filepath.Join(dir, "wrong"), filepath.Join(dir, "data")
	for path, content := range map[string]string{password: repoPassword + "\n", wrong: "not it\n", filepath.Join(data, "file.txt"): "something to back up\n"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The collector passes its own environment on, so the cache stays out of the home directory.
	t.Setenv("RESTIC_CACHE_DIR", filepath.Join(dir, "cache"))
	restic := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "restic", append([]string{"--repo", repo, "--password-file", password, "--quiet"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("restic %v: %v\n%s", args, err, out)
		}
	}
	restic("init")
	started := time.Now().Add(-time.Second)
	restic("backup", "--host", "testhost", "--tag", "nightly", data)

	look := func(j ResticJob, wantProblem string) report.Backup {
		t.Helper()
		j.Name = "real"
		var r report.Report
		check(t, &r, New(Config{Restic: []ResticJob{j}}).Collect(context.Background(), &r), "", wantProblem)
		if len(r.Backups) != 1 {
			t.Fatalf("%d backups, want 1", len(r.Backups))
		}
		return r.Backups[0]
	}

	b := look(ResticJob{Repository: repo, PasswordFile: password, Host: "testhost", Tag: "nightly"}, "")
	if b.LastResult != "ok" || b.LastSuccess.Before(started) || time.Since(b.LastSuccess) > time.Minute || !strings.HasPrefix(b.Detail, "snapshot ") {
		t.Errorf("the backup just made: %s", asJSON(t, b))
	}
	if locks, _ := os.ReadDir(filepath.Join(repo, "locks")); len(locks) != 0 {
		t.Errorf("%d locks left in the repository", len(locks))
	}

	env := filepath.Join(dir, "env")
	if err := os.WriteFile(env, []byte("RESTIC_REPOSITORY="+repo+"\nRESTIC_PASSWORD='"+repoPassword+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b = look(ResticJob{EnvFile: env}, ""); b.LastResult != "ok" {
		t.Errorf("with an environment file: %s", asJSON(t, b))
	}
	if b = look(ResticJob{Repository: repo, PasswordFile: password, Host: "another"}, ""); b.LastResult != "unknown" || b.Detail != "the repository has no snapshot of host another" {
		t.Errorf("a host without snapshots: %s", asJSON(t, b))
	}
	if b = look(ResticJob{Repository: repo, PasswordFile: wrong}, "restic ended with status 12: Fatal: wrong password or no key found"); b.LastResult != "unknown" {
		t.Errorf("the wrong password: %s", asJSON(t, b))
	}
	if b = look(ResticJob{Repository: filepath.Join(dir, "no-repo"), PasswordFile: password}, "restic ended with status 10: Fatal: repository does not exist"); b.LastResult != "unknown" {
		t.Errorf("no repository: %s", asJSON(t, b))
	}
}
