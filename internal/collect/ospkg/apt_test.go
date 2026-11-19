package ospkg

import (
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

const aptShowHold = "apt-mark showhold"

func TestAptPending(t *testing.T) {
	tests := []struct {
		name     string
		sim      string // fixture with the simulation's output
		showhold string // fixture with "apt-mark showhold", when the collector should ask
		pending  int
		security int
		kept     map[string]string // name: why
		has      []report.PackageUpdate
		hasNot   []string
	}{
		{
			// apt 3.0 on Debian 13, without -V and with the note a simulation prints for a
			// normal user: the format before the collector added its options.
			name: "trixie", sim: "apt/trixie-plain.txt", pending: 33, security: 16,
			has: []report.PackageUpdate{
				{Name: "libc6", Installed: "2.41-12", Candidate: "2.41-12+deb13u4"},
				{Name: "zlib1g", Installed: "1:1.3.dfsg+really1.3.1-1+b1", Candidate: "1:1.3.dfsg+really1.3.1-1+deb13u1", Security: true},
				// In the main archive and in security: a security update a point release took over.
				{Name: "util-linux", Installed: "2.41-5", Candidate: "2.41.5-0+deb13u1", Security: true},
				// stable-updates is not security.
				{Name: "tzdata", Installed: "2025b-4", Candidate: "2026f-0+deb13u1"},
			},
		},
		{
			name: "trixie with two packages on hold", sim: "apt/trixie-held.txt", showhold: "apt/trixie-held-showhold.txt",
			pending: 31, security: 15,
			kept:   map[string]string{"libssl3t64": keptHeld, "tzdata": keptHeld},
			hasNot: []string{"libssl3t64", "tzdata"},
			// Its sibling from the same source is not held and still comes.
			has: []report.PackageUpdate{{Name: "openssl-provider-legacy", Installed: "3.5.1-1", Candidate: "3.5.7-1~deb13u3", Security: true}},
		},
		{
			// A new kernel: the meta-package is upgraded and pulls in a new package. The new
			// package and apparmor are installs, not newer versions, and are not counted.
			name: "trixie with a kernel update", sim: "apt/trixie-kernel.txt", pending: 50, security: 19,
			has:    []report.PackageUpdate{{Name: "linux-image-cloud-amd64", Installed: "6.12.38-1", Candidate: "6.12.117-1", Security: true}},
			hasNot: []string{"linux-image-6.12.117+deb13-cloud-amd64", "apparmor"},
		},
		{
			name: "trixie with the kernel on hold", sim: "apt/trixie-kernel-held.txt", showhold: "apt/trixie-kernel-held-showhold.txt",
			pending: 48, security: 17,
			kept:   map[string]string{"libssl3t64": keptHeld, "linux-image-cloud-amd64": keptHeld},
			hasNot: []string{"linux-image-cloud-amd64", "linux-image-6.12.117+deb13-cloud-amd64"},
		},
		{name: "trixie, nothing to do", sim: "apt/trixie-clean.txt"},
		{
			// apt 2.6 on Debian 12, which is "oldstable" by now.
			name: "bookworm", sim: "apt/bookworm.txt", pending: 30, security: 8,
			has: []report.PackageUpdate{
				{Name: "apt", Installed: "2.6.1", Candidate: "2.6.2", Security: true},
				{Name: "libc6", Installed: "2.36-9+deb12u10", Candidate: "2.36-9+deb12u14"},
			},
		},
		{
			// Ubuntu holds some updates back for part of its machines. They are not pending
			// here, and nobody has to be asked whether they are on hold.
			name: "ubuntu with phased updates", sim: "apt/noble-phased.txt", pending: 66, security: 42,
			kept:   map[string]string{"alsa-ucm-conf": keptPhased, "distro-info": keptPhased, "libdistro-info-perl": keptPhased},
			hasNot: []string{"alsa-ucm-conf", "distro-info"},
			has:    []report.PackageUpdate{{Name: "libssl3t64", Installed: "3.0.13-0ubuntu3", Candidate: "3.0.13-0ubuntu3.16", Security: true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := answers{aptSimulate.String(): {stdout: fixture(t, tt.sim)}}
			if tt.showhold != "" {
				a[aptShowHold] = output{stdout: fixture(t, tt.showhold)}
			}
			f := newFake(t, "linux", a)
			f.file("/etc/os-release", debianOSRelease, time.Time{})
			f.file("/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease", "", day(12, 8))

			got, err := apt{f.machine()}.pending(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if len(got.doubts) != 0 {
				t.Errorf("doubts: %q", got.doubts)
			}
			security := 0
			for _, it := range got.items {
				if it.Security {
					security++
				}
			}
			if len(got.items) != tt.pending || security != tt.security {
				t.Errorf("pending %d, security %d; want %d and %d", len(got.items), security, tt.pending, tt.security)
			}
			for _, want := range tt.has {
				if it, ok := find(got.items, want.Name); !ok || it != want {
					t.Errorf("got %+v (found %v), want %+v", it, ok, want)
				}
			}
			for _, name := range tt.hasNot {
				if it, ok := find(got.items, name); ok {
					t.Errorf("%+v must not be pending", it)
				}
			}
			kept := map[string]string{}
			for _, k := range got.kept {
				kept[k.name] = k.why
				if k.installed == "" || k.candidate == "" {
					t.Errorf("kept package without versions: %+v", k)
				}
			}
			if len(kept) != len(tt.kept) {
				t.Errorf("kept %v, want %v", kept, tt.kept)
			}
			for name, why := range tt.kept {
				if kept[name] != why {
					t.Errorf("%s is %q, want %q", name, kept[name], why)
				}
			}
			// "apt-mark showhold" is only worth a process when something was kept back.
			if asked := len(f.ran) == 2; asked != (tt.showhold != "") {
				t.Errorf("commands run: %q", f.ran)
			}
		})
	}
}

// The evidence behind the choice of "apt-get -s dist-upgrade", as tests: the same machines,
// asked the other ways.
func TestAptWhyTheSimulation(t *testing.T) {
	t.Run("apt list --upgradable cannot tell a held package", func(t *testing.T) {
		list := fixture(t, "apt/trixie-held-apt-list.txt") // same machine, same moment as trixie-held.txt
		listed := strings.Count(list, "[upgradable from: ")
		sim, err := parseAptSimulation(fixture(t, "apt/trixie-held.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if listed != 33 || len(sim.upgrades) != 31 || len(sim.kept) != 2 {
			t.Fatalf("list %d, simulation %d upgrades and %d kept", listed, len(sim.upgrades), len(sim.kept))
		}
		for _, k := range sim.kept {
			line := ""
			for _, l := range strings.Split(list, "\n") {
				if strings.HasPrefix(l, k.name+"/") {
					line = l
				}
			}
			if line == "" || strings.Contains(line, "hold") || strings.Contains(line, "kept") {
				t.Errorf("%s in the list: %q", k.name, line)
			}
		}
	})
	t.Run("a plain upgrade keeps the new kernel back", func(t *testing.T) {
		// "apt-get -s upgrade" on the machine of trixie-kernel.txt.
		sim, err := parseAptSimulation(fixture(t, "apt/trixie-kernel-upgrade-only.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := find(sim.upgrades, "linux-image-cloud-amd64"); ok || len(sim.upgrades) != 49 {
			t.Errorf("%d upgrades", len(sim.upgrades))
		}
		if len(sim.kept) != 1 || sim.kept[0].name != "linux-image-cloud-amd64" || sim.kept[0].why != keptBack {
			t.Errorf("kept: %+v", sim.kept)
		}
	})
}

func TestAptErrors(t *testing.T) {
	tests := []struct {
		name   string
		stdout string // fixture
		stderr string // fixture
		keep   int    // only this much of stdout arrived, when not zero
		code   int
		want   string
	}{
		{
			// A package whose dependency cannot be met, on Debian 12: apt refuses to plan.
			name: "unmet dependencies", stdout: "apt/broken-stdout.txt", stderr: "apt/broken-stderr.txt", code: 100,
			want: "exit status 100: Unmet dependencies. Try 'apt --fix-broken install' with no packages (or specify a solution).",
		},
		{name: "output ends before the summary", stdout: "apt/trixie-held.txt", keep: 300, want: "no summary line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := output{code: tt.code, stdout: fixture(t, tt.stdout)}
			if tt.stderr != "" {
				out.stderr = fixture(t, tt.stderr)
			}
			if tt.keep > 0 {
				out.stdout = out.stdout[:tt.keep]
			}
			f := newFake(t, "linux", answers{aptSimulate.String(): out})
			f.file("/etc/os-release", debianOSRelease, time.Time{})
			r, err := f.collect(Config{})
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.HasPrefix(err.Error(), "apt: ") {
				t.Errorf("error %v, want one with %q", err, tt.want)
			}
			if r.Packages != nil {
				t.Errorf("a failed look must leave no packages: %+v", r.Packages)
			}
		})
	}
}

// Output that ends in the middle of the actions still has apt's own count, which gives it away.
func TestAptOutputCutShort(t *testing.T) {
	text := fixture(t, "apt/trixie-plain.txt")
	f := newFake(t, "linux", answers{aptSimulate.String(): {stdout: text[:len(text)/2]}})
	f.file("/etc/os-release", debianOSRelease, time.Time{})
	f.file("/var/lib/apt/lists/x_InRelease", "", day(18, 8))
	r, err := f.collect(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0].Message, "apt-get counts 33 upgrades but") {
		t.Errorf("errors %+v", r.Errors)
	}
}

func TestAptCountMismatchIsReported(t *testing.T) {
	// Three actions on installed packages, but apt's summary says four: something was not read.
	text := "Inst a [1] (2 Debian:13.7/stable [amd64])\nInst b [1] (2 Debian:13.7/stable [amd64])\nInst c [1] (2 Debian:13.7/stable [amd64])\n" +
		"4 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
	f := newFake(t, "linux", answers{aptSimulate.String(): {stdout: text}})
	f.file("/etc/os-release", debianOSRelease, time.Time{})
	f.file("/var/lib/apt/lists/x_InRelease", "", day(18, 8))
	r, err := f.collect(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Packages.Pending != 3 || len(r.Errors) != 1 || r.Errors[0].Collector != "ospkg" ||
		!strings.Contains(r.Errors[0].Message, "apt-get counts 4 upgrades but 3 were read") {
		t.Errorf("pending %d, errors %+v", r.Packages.Pending, r.Errors)
	}
}

func TestAptDowngradeIsNotAnUpgrade(t *testing.T) {
	// Format of the section from apt-private/private-output.cc; the Inst lines as apt prints them.
	text := "The following packages will be DOWNGRADED:\n   curl (8.14.1-2+deb13u2 => 8.14.1-2)\n" +
		"The following packages will be upgraded:\n   sed (4.9-2 => 4.9-2+deb13u1)\n" +
		"1 upgraded, 0 newly installed, 1 downgraded, 0 to remove and 0 not upgraded.\n" +
		"Inst curl [8.14.1-2+deb13u2] (8.14.1-2 Debian:13.7/stable [amd64])\n" +
		"Inst sed [4.9-2] (4.9-2+deb13u1 Debian:13.7/stable [amd64])\n"
	sim, err := parseAptSimulation(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(sim.upgrades) != 1 || sim.upgrades[0].Name != "sed" || sim.upgraded != 1 {
		t.Errorf("%+v", sim)
	}
}

func TestParseAptInst(t *testing.T) {
	tests := []struct {
		line string
		want report.PackageUpdate
		ok   bool
	}{
		{
			"Inst libc6 [2.41-12] (2.41-12+deb13u4 Debian:13.7/stable [amd64])",
			report.PackageUpdate{Name: "libc6", Installed: "2.41-12", Candidate: "2.41-12+deb13u4"}, true,
		},
		{
			// Notes about other packages follow in more brackets.
			"Inst liblastlog2-2 [2.41-5] (2.41.5-0+deb13u1 Debian:13.7/stable, Debian-Security:13/stable-security [amd64]) [util-linux:amd64 on liblastlog2-2:amd64] [util-linux:amd64 ]",
			report.PackageUpdate{Name: "liblastlog2-2", Installed: "2.41-5", Candidate: "2.41.5-0+deb13u1", Security: true}, true,
		},
		{
			// A new package has no installed version.
			"Inst linux-image-6.12.117+deb13-cloud-amd64 (6.12.117-1 Debian-Security:13/stable-security [amd64])",
			report.PackageUpdate{Name: "linux-image-6.12.117+deb13-cloud-amd64", Candidate: "6.12.117-1", Security: true}, true,
		},
		{
			"Inst libc6 (2.36-9+deb12u14 Debian:12.15/oldstable [amd64]) []",
			report.PackageUpdate{Name: "libc6", Candidate: "2.36-9+deb12u14"}, true,
		},
		{
			"Inst libssl3t64 [3.0.13-0ubuntu3] (3.0.13-0ubuntu3.16 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])",
			report.PackageUpdate{Name: "libssl3t64", Installed: "3.0.13-0ubuntu3", Candidate: "3.0.13-0ubuntu3.16", Security: true}, true,
		},
		{
			// A package of another architecture carries it in its name; a label may have spaces.
			"Inst libc6:i386 [2.41-12] (2.41-12+deb13u4 Raspberry Pi Foundation:stable [i386])",
			report.PackageUpdate{Name: "libc6:i386", Installed: "2.41-12", Candidate: "2.41-12+deb13u4"}, true,
		},
		{
			// A version that is in no repository, only the architecture is printed.
			"Inst local-thing [1.0] (1.1  [all])",
			report.PackageUpdate{Name: "local-thing", Installed: "1.0", Candidate: "1.1"}, true,
		},
		{"Conf libc6 (2.41-12+deb13u4 Debian:13.7/stable [amd64])", report.PackageUpdate{}, false},
		{"Inst broken", report.PackageUpdate{}, false},
		{"Inst broken [1.0", report.PackageUpdate{}, false},
		{"Inst broken [1.0] no parentheses", report.PackageUpdate{}, false},
		{"Inst broken [1.0] (1.1 never closed", report.PackageUpdate{}, false},
	}
	for _, tt := range tests {
		got, ok := parseAptInst(tt.line)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("%s\n got  %+v, %v\n want %+v, %v", tt.line, got, ok, tt.want, tt.ok)
		}
	}
}

func TestAptSecurityOrigin(t *testing.T) {
	tests := []struct {
		origins string
		want    bool
	}{
		{"Debian:13.7/stable", false},
		{"Debian-Security:13/stable-security", true},
		{"Debian:13.7/stable, Debian-Security:13/stable-security", true},
		{"Debian-Security:12/oldstable-security", true},
		{"Debian:13-updates/stable-updates", false},
		{"Ubuntu:24.04/noble-updates", false},
		{"Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security", true},
		{"UbuntuESMApps:22.04/jammy-apps-security", true},
		{"Docker CE:trixie", false},
		{"security-tools.example.org", false}, // a host name, for a repository without a Release file
		{"", false},
	}
	for _, tt := range tests {
		if got := aptSecurityOrigin(tt.origins); got != tt.want {
			t.Errorf("%q: got %v, want %v", tt.origins, got, tt.want)
		}
	}
}

func TestAptListsUpdated(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]time.Time
		want  time.Time
		doubt bool
	}{
		{
			// As on the captured machines: every file carries the time its repository
			// published it. The newest is the security archive's.
			name: "newest Release file",
			files: map[string]time.Time{
				"/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease":                                        day(2, 7),
				"/var/lib/apt/lists/deb.debian.org_debian_dists_trixie-updates_InRelease":                                day(18, 20),
				"/var/lib/apt/lists/deb.debian.org_debian-security_dists_trixie-security_InRelease":                      day(18, 22),
				"/var/lib/apt/lists/deb.debian.org_debian-security_dists_trixie-security_main_binary-amd64_Packages.lz4": day(18, 23), // not a Release file
				"/var/lib/apt/lists/partial/placeholder":                                                                 day(19, 6),  // moves on a failed refresh too
				"/var/lib/apt/periodic/update-stamp":                                                                     day(19, 6),  // and so does this
			},
			want: day(18, 22),
		},
		{
			name: "a repository without InRelease has Release",
			files: map[string]time.Time{
				"/var/lib/apt/lists/repo.example.org_dists_stable_Release":     day(10, 9),
				"/var/lib/apt/lists/repo.example.org_dists_stable_Release.gpg": day(11, 9),
			},
			want: day(10, 9),
		},
		{
			name: "the success stamp of update-notifier-common is exact",
			files: map[string]time.Time{
				"/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble_InRelease": day(3, 9),
				"/var/lib/apt/periodic/update-success-stamp":                         day(18, 6),
			},
			want: day(18, 6),
		},
		{
			name:  "a repository that is only a directory of packages",
			files: map[string]time.Time{"/var/lib/apt/lists/_srv_repo_._Packages.lz4": day(7, 9)},
			want:  day(7, 9),
		},
		{name: "no lists at all", files: map[string]time.Time{"/var/lib/apt/lists/lock": day(18, 6)}, doubt: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t, "linux", answers{aptSimulate.String(): {stdout: fixture(t, "apt/trixie-clean.txt")}})
			f.file("/etc/os-release", debianOSRelease, time.Time{})
			for path, mtime := range tt.files {
				f.file(path, "", mtime)
			}
			r, err := f.collect(Config{})
			if err != nil {
				t.Fatal(err)
			}
			if !r.Packages.ListsUpdated.Equal(tt.want) {
				t.Errorf("lists updated %s, want %s", r.Packages.ListsUpdated, tt.want)
			}
			if doubt := len(r.Errors) == 1 && strings.Contains(r.Errors[0].Message, "no package lists"); doubt != tt.doubt {
				t.Errorf("errors: %+v", r.Errors)
			}
		})
	}
}

func TestAptReboot(t *testing.T) {
	const (
		old = "6.12.38+deb13-cloud-amd64"
		new = "6.12.117+deb13-cloud-amd64"
	)
	tests := []struct {
		name    string
		files   map[string]string
		running string
		need    bool
		why     string
	}{
		{
			// The files as Debian 13 left them after the kernel update of trixie-kernel.txt:
			// the flag is empty, the list has the package that asked.
			name: "flag and its package list",
			files: map[string]string{
				"/var/run/reboot-required":      "",
				"/var/run/reboot-required.pkgs": "linux-image-6.12.117+deb13-cloud-amd64\n",
				"/boot/vmlinuz-" + old:          "", "/boot/vmlinuz-" + new: "",
			},
			running: old, need: true, why: "linux-image-6.12.117+deb13-cloud-amd64",
		},
		{
			// Ubuntu writes a text into the flag and lists a package once per trigger.
			name: "several packages, some twice",
			files: map[string]string{
				"/run/reboot-required":      "*** System restart required ***\n",
				"/run/reboot-required.pkgs": "linux-image-6.8.0-48-generic\nlinux-base\nlibc6\nlinux-base\n",
			},
			running: "6.8.0-45-generic", need: true, why: "linux-image-6.8.0-48-generic, linux-base, libc6",
		},
		{
			name:    "flag without a list: the kernels tell why",
			files:   map[string]string{"/var/run/reboot-required": "", "/boot/vmlinuz-" + old: "", "/boot/vmlinuz-" + new: ""},
			running: old, need: true, why: "kernel " + old + " running, " + new + " installed",
		},
		{
			name:    "flag without a list and nothing else to go by",
			files:   map[string]string{"/var/run/reboot-required": ""},
			running: new, need: true, why: "asked for by an installed package",
		},
		{
			// A machine without unattended-upgrades has no flag at all.
			name:    "no flag, newer kernel installed",
			files:   map[string]string{"/boot/vmlinuz-" + old: "", "/boot/vmlinuz-" + new: ""},
			running: old, need: true, why: "kernel " + old + " running, " + new + " installed",
		},
		{
			name:    "no flag, running the newest kernel",
			files:   map[string]string{"/boot/vmlinuz-" + old: "", "/boot/vmlinuz-" + new: ""},
			running: new,
		},
		{
			// What the capture containers really looked like: Debian's kernels in /boot, the
			// Fedora host's kernel running.
			name:    "a container runs its host's kernel",
			files:   map[string]string{"/boot/vmlinuz-" + old: "", "/boot/vmlinuz-" + new: ""},
			running: "7.2.15-100.fc43.x86_64",
		},
		{name: "nothing installed, nothing flagged", running: old},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t, "linux", answers{aptSimulate.String(): {stdout: fixture(t, "apt/trixie-clean.txt")}})
			f.file("/etc/os-release", debianOSRelease, time.Time{})
			f.file("/var/lib/apt/lists/x_InRelease", "", day(18, 8))
			f.file("/proc/sys/kernel/osrelease", tt.running+"\n", time.Time{})
			for path, content := range tt.files {
				f.file(path, content, time.Time{})
			}
			r, err := f.collect(Config{})
			if err != nil {
				t.Fatal(err)
			}
			if r.Packages.RebootRequired != tt.need || r.Packages.RebootReason != tt.why {
				t.Errorf("got %v %q, want %v %q", r.Packages.RebootRequired, r.Packages.RebootReason, tt.need, tt.why)
			}
		})
	}
}

func TestJoinNames(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b", "a"}, "a, b"},
		{[]string{"a", "b", "c", "d", "e", "f", "g"}, "a, b, c, d, e and 2 more"},
	}
	for _, tt := range tests {
		if got := joinNames(tt.in); got != tt.want {
			t.Errorf("%v: got %q, want %q", tt.in, got, tt.want)
		}
	}
}

// What an upgrade would leave alone is in the report, apart from what is pending: a package on
// hold gets no security update either, and the dashboard has to be able to say so.
func TestKeptBackIsReported(t *testing.T) {
	f := newFake(t, "linux", answers{
		aptSimulate.String(): {stdout: fixture(t, "apt/trixie-held.txt")},
		aptShowHold:          {stdout: fixture(t, "apt/trixie-held-showhold.txt")},
	})
	f.file("/etc/os-release", debianOSRelease, time.Time{})
	f.file("/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease", "", day(12, 8))

	r, err := f.collect(Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := r.Packages
	if p == nil || p.Pending != 31 {
		t.Fatalf("packages: %+v", p)
	}
	want := []report.PackageUpdate{
		{Name: "libssl3t64", Installed: "3.5.1-1", Candidate: "3.5.7-1~deb13u3", Reason: keptHeld},
		{Name: "tzdata", Installed: "2025b-4", Candidate: "2026f-0+deb13u1", Reason: keptHeld},
	}
	if len(p.KeptBack) != len(want) {
		t.Fatalf("kept back: %+v, want %+v", p.KeptBack, want)
	}
	for i, w := range want {
		if p.KeptBack[i] != w {
			t.Errorf("kept back %d: %+v, want %+v", i, p.KeptBack[i], w)
		}
	}
	for _, k := range p.KeptBack {
		if _, pending := find(p.Items, k.Name); pending {
			t.Errorf("%s is kept back and must not be pending too", k.Name)
		}
	}
}
