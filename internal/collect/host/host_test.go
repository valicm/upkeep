package host

import (
	"context"
	"errors"
	"testing"

	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/version"
)

// Where the files under testdata come from is in testdata/README.

func TestCollect(t *testing.T) {
	noUname := func(context.Context) (string, error) { return "", errors.New("no uname here") }
	tests := []struct {
		dir   string
		goos  string
		arch  string
		uname func(context.Context) (string, error)
		want  report.System
	}{
		{
			dir: "debian-13.0", goos: "linux", arch: "amd64", uname: noUname,
			want: report.System{Kind: "linux", OS: "Debian GNU/Linux 13 (trixie)", OSVersion: "13.0", Kernel: "6.12.38+deb13-cloud-amd64", Arch: "amd64"},
		},
		{
			dir: "debian-13.7", goos: "linux", arch: "arm64", uname: noUname,
			want: report.System{Kind: "linux", OS: "Debian GNU/Linux 13 (trixie)", OSVersion: "13.7", Kernel: "6.12.117+deb13-cloud-amd64", Arch: "arm64"},
		},
		{
			dir: "debian-12.11", goos: "linux", arch: "amd64", uname: noUname,
			want: report.System{Kind: "linux", OS: "Debian GNU/Linux 12 (bookworm)", OSVersion: "12.11", Kernel: "6.1.0-37-amd64", Arch: "amd64"},
		},
		{
			// Ubuntu's /etc/debian_version says "trixie/sid": it must not win.
			dir: "ubuntu-24.04", goos: "linux", arch: "amd64", uname: noUname,
			want: report.System{Kind: "linux", OS: "Ubuntu 24.04 LTS", OSVersion: "24.04", Kernel: "6.8.0-31-generic", Arch: "amd64"},
		},
		{
			dir: "alpine-3.20", goos: "linux", arch: "arm", uname: noUname,
			want: report.System{Kind: "linux", OS: "Alpine Linux v3.20", OSVersion: "3.20.0", Kernel: "6.6.31-0-lts", Arch: "arm"},
		},
		{
			dir: "fedora-43", goos: "linux", arch: "amd64", uname: noUname,
			want: report.System{Kind: "linux", OS: "Fedora Linux 43 (Workstation Edition)", OSVersion: "43", Kernel: "7.2.15-100.fc43.x86_64", Arch: "amd64"},
		},
		{
			// FreeBSD has no /proc: the kernel release comes from uname.
			dir: "freebsd-14.3", goos: "freebsd", arch: "amd64",
			uname: func(context.Context) (string, error) { return "14.3-RELEASE-p7\n", nil },
			want:  report.System{Kind: "freebsd", OS: "FreeBSD 14.3-RELEASE-p7", OSVersion: "14.3-RELEASE-p7", Kernel: "14.3-RELEASE-p7", Arch: "amd64"},
		},
		{
			// Nothing to read and nothing to run still gives a report that can be sent.
			dir: "empty", goos: "linux", arch: "amd64", uname: noUname,
			want: report.System{Kind: "linux", Arch: "amd64"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			c := &collector{root: "testdata/" + tt.dir, goos: tt.goos, arch: tt.arch, uname: tt.uname}
			r := report.Report{System: report.System{Name: "kept"}}
			if err := c.Collect(context.Background(), &r); err != nil {
				t.Fatal(err)
			}
			tt.want.Name = "kept" // the name is the agent's, the collector must leave it
			tt.want.Source = "agent"
			tt.want.AgentVersion = version.String()
			if r.System != tt.want {
				t.Errorf("got  %+v\nwant %+v", r.System, tt.want)
			}
		})
	}
}

func TestOSVersion(t *testing.T) {
	tests := []struct {
		name   string
		rel    map[string]string
		debian string
		want   string
	}{
		{"debian point release", map[string]string{"ID": "debian", "VERSION_ID": "13"}, "13.7", "13.7"},
		{"debian testing has no VERSION_ID", map[string]string{"ID": "debian"}, "forky/sid", "forky/sid"},
		{"debian without the file", map[string]string{"ID": "debian", "VERSION_ID": "13"}, "", "13"},
		{"raspbian", map[string]string{"ID": "raspbian", "ID_LIKE": "debian", "VERSION_ID": "12"}, "12.12", "12.12"},
		{"ubuntu ignores debian_version", map[string]string{"ID": "ubuntu", "ID_LIKE": "debian", "VERSION_ID": "24.04"}, "trixie/sid", "24.04"},
		{"freebsd keeps the patch level", map[string]string{"ID": "freebsd", "VERSION_ID": "14.3", "VERSION": "14.3-RELEASE-p7"}, "", "14.3-RELEASE-p7"},
		{"only VERSION", map[string]string{"ID": "x", "VERSION": "7 (Core)"}, "", "7 (Core)"},
		{"nothing", map[string]string{}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := osVersion(tt.rel, tt.debian); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnquote(t *testing.T) {
	tests := []struct{ in, want string }{
		{`debian`, "debian"},
		{`"Debian GNU/Linux 13 (trixie)"`, "Debian GNU/Linux 13 (trixie)"},
		{`'single'`, "single"},
		{`"a \"quoted\" \$word"`, `a "quoted" $word`},
		{`""`, ""},
		{`"`, `"`},
		{`  43  `, "43"},
	}
	for _, tt := range tests {
		if got := unquote(tt.in); got != tt.want {
			t.Errorf("unquote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// The real collector must work on the machine the tests run on, whatever that is.
func TestNewOnThisMachine(t *testing.T) {
	c := New(Config{})
	if c.Name() != "host" {
		t.Errorf("name %q", c.Name())
	}
	var r report.Report
	if err := c.Collect(context.Background(), &r); err != nil {
		t.Fatal(err)
	}
	if r.System.Kind == "" || r.System.Arch == "" || r.System.Source != "agent" || r.System.Kernel == "" {
		t.Errorf("incomplete: %+v", r.System)
	}
}
