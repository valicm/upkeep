package ospkg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// Where every file under testdata comes from is in testdata/README.

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// answers maps a full command line to what the command printed. A command that is not in the
// map fails the test: the exact command lines are part of what is tested.
type answers map[string]output

// fakeMachine is a machine that has the given commands and files, and no others.
type fakeMachine struct {
	t       *testing.T
	root    string
	goos    string
	answers answers
	ran     []string
}

func newFake(t *testing.T, goos string, a answers) *fakeMachine {
	return &fakeMachine{t: t, root: t.TempDir(), goos: goos, answers: a}
}

func (f *fakeMachine) machine() *machine {
	return &machine{
		root: f.root, goos: f.goos, goarch: "amd64", tmp: f.t.TempDir(),
		run: func(_ context.Context, c command) (output, error) {
			line := c.String()
			// dnf gets a log directory that is new on every run.
			if i := strings.Index(line, "--setopt=logdir="); i >= 0 {
				rest := line[i:]
				line = line[:i] + "--setopt=logdir=LOG" + rest[strings.Index(rest, " "):]
			}
			f.ran = append(f.ran, line)
			out, ok := f.answers[line]
			if !ok {
				f.t.Errorf("unexpected command: %s", line)
				return output{}, errors.New("run " + line + ": command not found")
			}
			return out, nil
		},
		have: func(name string) bool {
			for line := range f.answers {
				if strings.HasPrefix(line, name+" ") {
					return true
				}
			}
			return false
		},
		uname: func(context.Context) (string, error) { return "", errors.New("no uname in tests") },
	}
}

// file writes a file under the fake root, with the given modification time unless it is zero.
func (f *fakeMachine) file(path, content string, mtime time.Time) {
	f.t.Helper()
	full := filepath.Join(f.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(full, mtime, mtime); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fakeMachine) collect(cfg Config) (*report.Report, error) {
	r := &report.Report{}
	err := (&collector{cfg: cfg, m: f.machine()}).Collect(context.Background(), r)
	return r, err
}

func day(d int, hour int) time.Time { return time.Date(2026, 11, d, hour, 0, 0, 0, time.UTC) }

const debianOSRelease = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\n"

func find(items []report.PackageUpdate, name string) (report.PackageUpdate, bool) {
	for _, it := range items {
		if it.Name == name {
			return it, true
		}
	}
	return report.PackageUpdate{}, false
}

func TestManagerDetection(t *testing.T) {
	tests := []struct {
		name      string
		goos      string
		osRelease string
		files     []string // exist on the machine
		commands  []string
		cfg       Config
		want      string // the manager's name
		wantErr   string // or a part of the error
	}{
		{name: "debian", goos: "linux", osRelease: "ID=debian\n", commands: []string{"apt-get"}, want: "apt"},
		{name: "ubuntu is like debian", goos: "linux", osRelease: "ID=ubuntu\nID_LIKE=debian\n", commands: []string{"apt-get"}, want: "apt"},
		{name: "raspbian", goos: "linux", osRelease: "ID=raspbian\nID_LIKE=debian\n", commands: []string{"apt-get"}, want: "apt"},
		{name: "fedora", goos: "linux", osRelease: "ID=fedora\n", commands: []string{"dnf"}, want: "dnf"},
		{
			// Fedora packages apt and dpkg as tools; they are not its package manager.
			name: "fedora with apt installed", goos: "linux", osRelease: "ID=fedora\n",
			files: []string{"/var/lib/dpkg/status", "/usr/lib/sysimage/rpm/rpmdb.sqlite"}, commands: []string{"apt-get", "dnf"}, want: "dnf",
		},
		{name: "alma is like rhel", goos: "linux", osRelease: "ID=almalinux\nID_LIKE=\"rhel centos fedora\"\n", commands: []string{"dnf"}, want: "dnf"},
		{name: "alpine", goos: "linux", osRelease: "ID=alpine\n", commands: []string{"apk"}, want: "apk"},
		{name: "freebsd", goos: "freebsd", osRelease: "ID=freebsd\n", commands: []string{"pkg"}, want: "pkg"},
		{name: "opnsense has no os-release", goos: "freebsd", commands: []string{"pkg"}, want: "pkg"},
		{
			name: "unknown system, found by its database", goos: "linux", osRelease: "ID=something\n",
			files: []string{"/var/lib/dpkg/status"}, commands: []string{"apt-get"}, want: "apt",
		},
		{name: "configured", goos: "linux", osRelease: "ID=debian\n", commands: []string{"apt-get", "apk"}, cfg: Config{Manager: "APK"}, want: "apk"},
		{name: "configured but missing", goos: "linux", osRelease: "ID=debian\n", commands: []string{"apt-get"}, cfg: Config{Manager: "dnf"}, wantErr: "not installed"},
		{name: "configured nonsense", goos: "linux", cfg: Config{Manager: "yum"}, wantErr: "unknown package manager"},
		{name: "nothing at all", goos: "linux", osRelease: "ID=homeassistant\n", wantErr: "no package manager found"},
		{name: "the system's manager is not installed", goos: "linux", osRelease: "ID=debian\n", wantErr: "no package manager found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := answers{}
			for _, c := range tt.commands {
				a[c+" "] = output{}
			}
			f := newFake(t, tt.goos, a)
			if tt.osRelease != "" {
				f.file("/etc/os-release", tt.osRelease, time.Time{})
			}
			for _, p := range tt.files {
				f.file(p, "", time.Time{})
			}
			mgr, err := (&collector{cfg: tt.cfg, m: f.machine()}).manager()
			switch {
			case tt.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %v, want one with %q", err, tt.wantErr)
				}
			case err != nil:
				t.Error(err)
			case mgr.name() != tt.want:
				t.Errorf("got %s, want %s", mgr.name(), tt.want)
			}
		})
	}
}

// A machine without a package manager is an error for the agent to report, and leaves the
// report without a Packages part: nobody looked.
func TestNoPackageManager(t *testing.T) {
	f := newFake(t, "linux", answers{})
	r, err := f.collect(Config{})
	if err == nil || r.Packages != nil {
		t.Fatalf("err %v, packages %+v", err, r.Packages)
	}
}

func TestItemsAreCappedAndSecurityComesFirst(t *testing.T) {
	var b strings.Builder
	const total = report.MaxItems + 40
	for i := 0; i < total; i++ {
		origin := "Debian:13.7/stable"
		if i%50 == 0 {
			origin = "Debian-Security:13/stable-security"
		}
		b.WriteString("Inst pkg" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + strconv.Itoa(i) + " [1.0] (1.1 " + origin + " [amd64])\n")
	}
	b.WriteString(strconv.Itoa(total) + " upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")

	f := newFake(t, "linux", answers{aptSimulate.String(): {stdout: b.String()}})
	f.file("/etc/os-release", debianOSRelease, time.Time{})
	f.file("/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease", "", day(18, 8))
	r, err := f.collect(Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := r.Packages
	if p.Pending != total || len(p.Items) != report.MaxItems {
		t.Fatalf("pending %d with %d items, want %d with %d", p.Pending, len(p.Items), total, report.MaxItems)
	}
	wantSecurity := (total + 49) / 50
	if p.Security != wantSecurity {
		t.Errorf("security %d, want %d", p.Security, wantSecurity)
	}
	for i, it := range p.Items {
		if it.Security != (i < wantSecurity) {
			t.Fatalf("item %d (%s) security=%v: security updates must lead the list", i, it.Name, it.Security)
		}
	}
}

func TestFailure(t *testing.T) {
	c := command{name: "apt-get", args: []string{"-s", "dist-upgrade"}}
	tests := []struct {
		name string
		out  output
		want string
	}{
		{
			"apt's error lines", output{code: 100, stderr: "W: something minor\nE: First problem.\nE: Second problem.\n"},
			"apt-get -s dist-upgrade: exit status 100: First problem.; Second problem.",
		},
		{
			"no marked lines: the end of the output", output{code: 1, stderr: "one\ntwo\nthree\nfour\n"},
			"apt-get -s dist-upgrade: exit status 1: two; three; four",
		},
		{"silence", output{code: 3}, "apt-get -s dist-upgrade: exit status 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := failure(c, tt.out).Error(); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
	long := failure(c, output{code: 1, stderr: "E: " + strings.Repeat("x", 5000)}).Error()
	if len(long) > 600 {
		t.Errorf("a long message is not cut: %d bytes", len(long))
	}
}

// The real runner, with harmless commands every Unix has.
func TestRunCommand(t *testing.T) {
	ctx := context.Background()

	out, err := runCommand(ctx, command{name: "sh", args: []string{"-c", "echo out; echo err >&2; echo \"$LC_ALL/$ASSUME_ALWAYS_YES\"; exit 100"}, timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("a non-zero exit must not be an error: %v", err)
	}
	if out.code != 100 || out.stderr != "err\n" || out.stdout != "out\nC/\n" {
		t.Errorf("got %+v", out)
	}

	if _, err := runCommand(ctx, command{name: "upkeep-no-such-command", timeout: time.Second}); err == nil || !strings.Contains(err.Error(), "command not found") {
		t.Errorf("missing command: %v", err)
	}

	start := time.Now()
	_, err = runCommand(ctx, command{name: "sleep", args: []string{"30"}, timeout: 200 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "no answer within") {
		t.Errorf("timeout: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("the command was not stopped at its timeout: %s", time.Since(start))
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := runCommand(cancelled, command{name: "sleep", args: []string{"30"}, timeout: time.Minute}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestCappedBuffer(t *testing.T) {
	c := &capped{left: 5}
	for _, s := range []string{"abc", "defg", "hij"} {
		if n, err := c.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v: a full buffer must not stop the command", s, n, err)
		}
	}
	if c.buf.String() != "abcde" {
		t.Errorf("got %q", c.buf.String())
	}
}
