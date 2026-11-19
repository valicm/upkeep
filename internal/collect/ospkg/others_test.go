package ospkg

import (
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// The command lines the dnf collector must use on a machine with dnf 5.
const (
	dnf5Check    = "dnf5 --cacheonly --setopt=cachedir=/var/cache/libdnf5 --setopt=build_cache=false --setopt=logdir=LOG check-upgrade"
	dnf5Security = dnf5Check + " --security"
	rpmInstalled = `rpm -qa --qf %{NAME}.%{ARCH}\t%{EVR}\t%{INSTALLTIME}\n`
)

func TestDnf(t *testing.T) {
	f := newFake(t, "linux", answers{
		"dnf ":       {}, // Fedora has both names
		dnf5Check:    {code: 100, stdout: fixture(t, "dnf/dnf5-check-upgrade.txt"), stderr: "Updating and loading repositories:\nRepositories loaded.\n"},
		dnf5Security: {code: 100, stdout: fixture(t, "dnf/dnf5-check-upgrade-security.txt")},
		rpmInstalled: {stdout: fixture(t, "dnf/dnf5-rpm-qa.txt")},
	})
	f.file("/etc/os-release", "ID=fedora\nVERSION_ID=43\n", time.Time{})
	f.file("/proc/sys/kernel/osrelease", "7.2.11-100.fc43.x86_64\n", time.Time{})
	for _, k := range []string{"0-rescue-35a5eec22b48439eb708b29369f28ed6", "7.2.10-100.fc43.x86_64", "7.2.11-100.fc43.x86_64", "7.2.15-100.fc43.x86_64"} {
		f.file("/boot/vmlinuz-"+k, "", time.Time{})
	}
	// The times as they were in root's cache: metadata fetched in the morning, found
	// unchanged in the evening, which dnf records on the primary file.
	f.file("/var/cache/libdnf5/updates-431245df5652aba0/repodata/repomd.xml", "", day(18, 11))
	f.file("/var/cache/libdnf5/updates-431245df5652aba0/repodata/8af1-primary.xml.zck", "", day(18, 18))
	f.file("/var/cache/libdnf5/fedora-fe4b228be7d3c150/repodata/repomd.xml", "", day(2, 16))

	r, err := f.collect(Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := r.Packages
	if p.Manager != "dnf" || p.Pending != 23 || p.Security != 12 || len(r.Errors) != 0 {
		t.Fatalf("manager %s, pending %d, security %d, errors %+v", p.Manager, p.Pending, p.Security, r.Errors)
	}
	if !p.ListsUpdated.Equal(day(18, 18)) {
		t.Errorf("lists updated %s", p.ListsUpdated)
	}
	if !p.RebootRequired || p.RebootReason != "kernel 7.2.11-100.fc43.x86_64 running, 7.2.15-100.fc43.x86_64 installed" {
		t.Errorf("reboot %v %q", p.RebootRequired, p.RebootReason)
	}
	for _, want := range []report.PackageUpdate{
		{Name: "7zip", Installed: "26.04-1.fc43", Candidate: "26.06-1.fc43"},
		{Name: "ImageMagick", Installed: "1:7.1.2.34-1.fc43", Candidate: "1:7.1.2.35-1.fc43"},      // with an epoch
		{Name: "composer", Installed: "2.10.3-1.fc43", Candidate: "2.11.1-1.fc43", Security: true}, // noarch
		{Name: "SDL3", Installed: "3.4.18-1.fc43", Candidate: "3.4.20-1.fc43"},
		{Name: "SDL3.i686", Installed: "3.4.18-1.fc43", Candidate: "3.4.20-1.fc43"}, // a second architecture keeps its suffix
		// Three kernels are installed; the newest of them is "the installed version".
		{Name: "kernel-core", Installed: "7.2.15-100.fc43", Candidate: "7.3.4-100.fc43", Security: true},
		// Listed once, although the section on replaced packages names it again.
		{Name: "kernel-headers", Installed: "7.2.4-100.fc43", Candidate: "7.3.3-100.fc43", Security: true},
	} {
		if it, ok := find(p.Items, want.Name); !ok || it != want {
			t.Errorf("got %+v (found %v), want %+v", it, ok, want)
		}
	}
	if !p.Items[0].Security || p.Items[len(p.Items)-1].Security {
		t.Error("security updates must come first")
	}
}

func TestDnfOutcomes(t *testing.T) {
	tests := []struct {
		name     string
		answers  answers
		pending  int
		security int
		wantErr  string
	}{
		{
			name:    "nothing to do: exit code 0",
			answers: answers{dnf5Check: {stdout: "", stderr: "Updating and loading repositories:\nRepositories loaded.\n"}},
		},
		{
			// What dnf 5 said on the workstation when it was not given root's cache.
			name:    "no cache",
			answers: answers{dnf5Check: {code: 1, stderr: "Updating and loading repositories:\nCache-only enabled but no cache for repository \"fedora\"\n"}},
			wantErr: `exit status 1: Updating and loading repositories:; Cache-only enabled but no cache for repository "fedora"`,
		},
		{
			name: "the security question fails: updates are reported unmarked",
			answers: answers{
				dnf5Check:    {code: 100, stdout: fixture(t, "dnf/dnf5-check-upgrade.txt")},
				dnf5Security: {code: 1, stderr: "something went wrong\n"},
				rpmInstalled: {code: 1},
			},
			pending: 23,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t, "linux", tt.answers)
			if _, ok := tt.answers[dnf5Check]; ok {
				tt.answers["dnf "] = output{}
			}
			f.file("/etc/os-release", "ID=fedora\n", time.Time{})
			f.file("/proc/sys/kernel/osrelease", "7.2.15-100.fc43.x86_64\n", time.Time{})
			r, err := f.collect(Config{})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v, want one with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Packages.Pending != tt.pending || r.Packages.Security != tt.security {
				t.Errorf("pending %d, security %d; want %d and %d", r.Packages.Pending, r.Packages.Security, tt.pending, tt.security)
			}
		})
	}
}

// dnf 4, as on RHEL and its rebuilds: there is no dnf5 command, and -C reads root's cache.
// The fixtures are AlmaLinux 9.3 asked by the user "nobody".
func TestDnf4(t *testing.T) {
	f := newFake(t, "linux", answers{
		"dnf -C -q check-update":            {code: 100, stdout: fixture(t, "dnf/dnf4-check-update.txt")},
		"dnf -C -q check-update --security": {code: 100, stdout: fixture(t, "dnf/dnf4-check-update-security.txt")},
		rpmInstalled:                        {stdout: fixture(t, "dnf/dnf4-rpm-qa.txt")},
	})
	f.file("/etc/os-release", "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n", time.Time{})
	f.file("/proc/sys/kernel/osrelease", "5.14.0-362.24.1.el9_3.x86_64\n", time.Time{})
	f.file("/var/cache/dnf/baseos-09b2e93483836b7c/repodata/repomd.xml", "", day(19, 0))
	f.file("/var/cache/dnf/appstream-0a8174e0a3d29b90/repodata/repomd.xml", "", day(18, 12))

	r, err := f.collect(Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := r.Packages
	if p.Manager != "dnf" || p.Pending != 118 || p.Security != 67 || !p.ListsUpdated.Equal(day(19, 0)) || p.RebootRequired {
		t.Fatalf("%+v", p)
	}
	for _, want := range []report.PackageUpdate{
		{Name: "glibc", Installed: "2.34-83.el9_3.12", Candidate: "2.34-290.el9_9", Security: true},
		{Name: "vim-minimal", Installed: "2:8.2.2637-20.el9_1", Candidate: "2:8.2.2637-43.el9_9", Security: true},
		{Name: "tzdata", Installed: "2024a-1.el9", Candidate: "2026f-1.el9_9"},
	} {
		if it, ok := find(p.Items, want.Name); !ok || it != want {
			t.Errorf("got %+v (found %v), want %+v", it, ok, want)
		}
	}
}

func TestDnfShortName(t *testing.T) {
	tests := []struct{ name, goarch, want string }{
		{"kernel-core.x86_64", "amd64", "kernel-core"},
		{"composer.noarch", "amd64", "composer"},
		{"SDL3.i686", "amd64", "SDL3.i686"},
		{"kernel-core.aarch64", "arm64", "kernel-core"},
		{"containerd.io.x86_64", "amd64", "containerd.io"},
		{"glibc.riscv64", "riscv64", "glibc"},
	}
	for _, tt := range tests {
		if got := dnfShortName(tt.name, tt.goarch); got != tt.want {
			t.Errorf("%s on %s: got %q, want %q", tt.name, tt.goarch, got, tt.want)
		}
	}
}

func TestApk(t *testing.T) {
	version := apkVersion.String()
	t.Run("alpine 3.20 with ten updates", func(t *testing.T) {
		f := newFake(t, "linux", answers{version: {stdout: fixture(t, "apk/version.txt")}})
		f.file("/etc/os-release", "ID=alpine\nVERSION_ID=3.20.0\n", time.Time{})
		f.file("/var/cache/apk/APKINDEX.e0297a25.tar.gz", "", day(18, 23))
		f.file("/var/cache/apk/APKINDEX.f86367c4.tar.gz", "", day(18, 22))
		r, err := f.collect(Config{})
		if err != nil {
			t.Fatal(err)
		}
		p := r.Packages
		if p.Manager != "apk" || p.Pending != 10 || p.Security != 0 || p.RebootRequired || !p.ListsUpdated.Equal(day(18, 23)) {
			t.Fatalf("%+v", p)
		}
		for _, want := range []report.PackageUpdate{
			{Name: "busybox", Installed: "1.36.1-r28", Candidate: "1.36.1-r31"},
			{Name: "apk-tools", Installed: "2.14.4-r0", Candidate: "2.14.13-r0"},                 // a dash in the name
			{Name: "ca-certificates-bundle", Installed: "20240226-r0", Candidate: "20261020-r0"}, // two of them
			{Name: "libcrypto3", Installed: "3.3.0-r2", Candidate: "3.3.7-r0"},
		} {
			if it, ok := find(p.Items, want.Name); !ok || it != want {
				t.Errorf("got %+v (found %v), want %+v", it, ok, want)
			}
		}
	})
	t.Run("the same packages as apk list -u names them", func(t *testing.T) {
		// A second view of the same machine, to check the names and versions were cut right.
		items := parseApkVersion(fixture(t, "apk/version.txt"))
		list := fixture(t, "apk/list-u.txt")
		for _, it := range items {
			want := it.Name + "-" + it.Candidate + " "
			from := "[upgradable from: " + it.Name + "-" + it.Installed + "]"
			if !strings.Contains(list, want) || !strings.Contains(list, from) {
				t.Errorf("%+v is not in apk list -u", it)
			}
		}
	})
	t.Run("no index: nobody ran apk update", func(t *testing.T) {
		// As a fresh container image is: apk prints a warning and an empty list.
		f := newFake(t, "linux", answers{version: {
			stdout: "Installed:                                Available:\n",
			stderr: "WARNING: opening from cache https://dl-cdn.alpinelinux.org/alpine/v3.20/main: No such file or directory\n",
		}})
		f.file("/etc/os-release", "ID=alpine\n", time.Time{})
		r, err := f.collect(Config{})
		if err != nil {
			t.Fatal(err)
		}
		// "0 pending" alone would be a false all-clear: the problem has to come with it.
		if r.Packages.Pending != 0 || !r.Packages.ListsUpdated.IsZero() || len(r.Errors) != 1 || !strings.Contains(r.Errors[0].Message, "apk: there is no package index") {
			t.Errorf("packages %+v, errors %+v", r.Packages, r.Errors)
		}
	})
	t.Run("apk fails", func(t *testing.T) {
		f := newFake(t, "linux", answers{version: {code: 99, stderr: "ERROR: Unable to read database state: No such file or directory\n"}})
		f.file("/etc/os-release", "ID=alpine\n", time.Time{})
		f.file("/var/cache/apk/APKINDEX.e0297a25.tar.gz", "", day(18, 23))
		if _, err := f.collect(Config{}); err == nil || !strings.Contains(err.Error(), "exit status 99: ERROR: Unable to read database state") {
			t.Errorf("err %v", err)
		}
	})
}

func TestPkg(t *testing.T) {
	const (
		upgrade = "pkg upgrade -n -U"
		audit   = "pkg audit -q"
		version = "freebsd-version -kr"
	)
	tests := []struct {
		name     string
		answers  answers
		pending  int
		security int
		has      []report.PackageUpdate
		reboot   string
		wantErr  string
	}{
		{
			name: "opnsense, several repositories, a locked package",
			answers: answers{
				upgrade: {stdout: fixture(t, "pkg/upgrade-opnsense.txt")},
				audit:   {code: 1, stdout: fixture(t, "pkg/audit-q.txt")}, // 1: "there are vulnerable packages"
				version: {stdout: fixture(t, "pkg/freebsd-version-kr-reboot.txt")},
			},
			pending: 6, security: 2,
			has: []report.PackageUpdate{
				{Name: "curl", Installed: "8.10.1", Candidate: "8.11.1", Security: true},
				{Name: "expat", Installed: "2.6.3", Candidate: "2.6.4", Security: true},
				{Name: "opnsense", Installed: "26.10", Candidate: "26.10.1"},
				{Name: "py311-certifi", Installed: "2024.8.30", Candidate: "2024.12.14"},
			},
			reboot: "kernel 14.3-RELEASE-p5 running, 14.3-RELEASE-p7 installed",
		},
		{
			name: "one repository: no name in brackets",
			answers: answers{
				upgrade: {stdout: fixture(t, "pkg/upgrade-single-repo.txt")},
				// Without the list of vulnerabilities pkg says so on stderr; nothing is marked.
				audit:   {code: 1, stderr: "pkg: vulnxml file vuln.xml does not exist. Try running 'pkg audit -F' first\n"},
				version: {stdout: fixture(t, "pkg/freebsd-version-kr-same.txt")},
			},
			pending: 2,
			has:     []report.PackageUpdate{{Name: "vim", Installed: "9.1.0764", Candidate: "9.1.0916,1"}},
		},
		{
			// Word for word what pkg's own test suite expects pkg to print.
			name: "output from pkg's tests",
			answers: answers{
				upgrade: {stdout: fixture(t, "pkg/upgrade-upstream-test.txt")},
				audit:   {},
				version: {stdout: fixture(t, "pkg/freebsd-version-kr-same.txt")},
			},
			pending: 1,
			has:     []report.PackageUpdate{{Name: "myplop", Installed: "1", Candidate: "2"}},
		},
		{
			name: "up to date",
			answers: answers{
				upgrade: {stdout: fixture(t, "pkg/upgrade-none.txt")},
				version: {stdout: fixture(t, "pkg/freebsd-version-kr-same.txt")},
			},
		},
		{
			// Older versions of pkg end a dry run that found something with 1.
			name: "updates with exit code 1",
			answers: answers{
				upgrade: {code: 1, stdout: fixture(t, "pkg/upgrade-single-repo.txt")},
				audit:   {},
				version: {code: 1},
			},
			pending: 2,
		},
		{
			// The message of FreeBSD's /usr/sbin/pkg when pkg itself was never installed.
			name: "pkg not installed yet",
			answers: answers{upgrade: {code: 1, stderr: "The package management tool is not yet installed on your system.\n" +
				"Please set ASSUME_ALWAYS_YES=yes environment variable to be able to bootstrap in non interactive (stdin not being a tty)\n"}},
			wantErr: "pkg: pkg upgrade -n -U: exit status 1: The package management tool is not yet installed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t, "freebsd", tt.answers)
			f.file("/var/db/pkg/repos/OPNsense/db", "", day(17, 3))
			f.file("/var/db/pkg/repos/FreeBSD/db", "", day(16, 3))
			r, err := f.collect(Config{})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v, want one with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p := r.Packages
			if p.Manager != "pkg" || p.Pending != tt.pending || p.Security != tt.security || !p.ListsUpdated.Equal(day(17, 3)) {
				t.Errorf("%+v", p)
			}
			if p.RebootRequired != (tt.reboot != "") || p.RebootReason != tt.reboot {
				t.Errorf("reboot %v %q, want %q", p.RebootRequired, p.RebootReason, tt.reboot)
			}
			for _, want := range tt.has {
				if it, ok := find(p.Items, want.Name); !ok || it != want {
					t.Errorf("got %+v (found %v), want %+v", it, ok, want)
				}
			}
		})
	}
}

func TestParsePkgLocked(t *testing.T) {
	got, ok := parsePkgUpgrade(fixture(t, "pkg/upgrade-opnsense.txt"))
	if !ok || len(got.kept) != 1 {
		t.Fatalf("ok %v, kept %+v", ok, got.kept)
	}
	want := keptPackage{name: "nginx", installed: "1.26.2_5,3", candidate: "1.26.3,3", why: keptHeld}
	if got.kept[0] != want {
		t.Errorf("got %+v, want %+v", got.kept[0], want)
	}
	for _, line := range []string{
		"\tPackage nginx-1.26.2 is locked and may not be reinstalled to version 1.26.2",
		"\tPackage nginx-1.26.2 is locked and may not be deinstalled",
		"\tnot a locked line",
	} {
		if k, ok := parsePkgLocked(line); ok {
			t.Errorf("%q gave %+v", line, k)
		}
	}
}

// The catalogue had another name before pkg 2.
func TestPkgOldCatalogueName(t *testing.T) {
	f := newFake(t, "freebsd", answers{
		"pkg upgrade -n -U":   {stdout: fixture(t, "pkg/upgrade-none.txt")},
		"freebsd-version -kr": {stdout: fixture(t, "pkg/freebsd-version-kr-same.txt")},
	})
	f.file("/var/db/pkg/repo-OPNsense.sqlite", "", day(9, 4))
	r, err := f.collect(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Packages.ListsUpdated.Equal(day(9, 4)) {
		t.Errorf("lists updated %s", r.Packages.ListsUpdated)
	}
}
