package ospkg

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// dnf is the package manager of Fedora and the Red Hat family.
//
// It is only asked from the cache that root's dnf keeps and the host's dnf-makecache.timer
// refreshes, and it adds nothing to it. dnf 4 does that for a normal user with -C. dnf 5 has
// to be told more (testdata/README): left alone it copies root's cache into the user's home,
// 110 MB where it was tried, and with --cacheonly then answers from that copy for ever.
type dnf struct{ m *machine }

func (dnf) name() string { return "dnf" }

const (
	dnfTimeout = 2 * time.Minute
	rpmTimeout = time.Minute

	dnf5Cache = "/var/cache/libdnf5"
	dnf4Cache = "/var/cache/dnf"
)

// check builds "dnf check-upgrade". Its exit status is 100 when there are updates. logdir is
// only for dnf 5, which stops if it has no log it can write.
func (d dnf) check(logdir string, more ...string) command {
	if logdir == "" {
		return command{name: "dnf", args: append([]string{"-C", "-q", "check-update"}, more...), timeout: dnfTimeout}
	}
	args := []string{
		"--cacheonly",
		"--setopt=cachedir=" + dnf5Cache,
		"--setopt=build_cache=false", // write nothing into root's cache
		"--setopt=logdir=" + logdir,
		"check-upgrade",
	}
	return command{name: "dnf5", args: append(args, more...), timeout: dnfTimeout}
}

func (d dnf) pending(ctx context.Context) (pending, error) {
	logdir := ""
	if d.m.have("dnf5") {
		dir, err := os.MkdirTemp(d.m.tmp, "upkeep-dnf-")
		if err != nil {
			return pending{}, fmt.Errorf("make a directory for dnf's log: %w", err)
		}
		defer os.RemoveAll(dir)
		logdir = dir
	}

	all := d.check(logdir)
	out, err := d.m.run(ctx, all)
	if err != nil {
		return pending{}, err
	}
	if out.code != 0 && out.code != 100 {
		return pending{}, failure(all, out)
	}
	got := pending{items: parseDnfCheck(out.stdout)}
	got.listsUpdated = d.m.newestMtime(dnf5Cache+"/*/repodata/*", dnf4Cache+"/*/repodata/*")

	if len(got.items) > 0 {
		// Which of them fix a security problem: the same question with --security. If that
		// fails the updates are still reported, only without the mark.
		sec := d.check(logdir, "--security")
		if out, err := d.m.run(ctx, sec); err == nil && (out.code == 0 || out.code == 100) {
			security := map[string]bool{}
			for _, it := range parseDnfCheck(out.stdout) {
				security[it.Name+" "+it.Candidate] = true
			}
			markSecurity(got.items, func(it report.PackageUpdate) bool { return security[it.Name+" "+it.Candidate] })
		}
		d.installed(ctx, got.items)
	}
	for i := range got.items {
		got.items[i].Name = dnfShortName(got.items[i].Name, d.m.goarch)
	}
	return got, nil
}

// installed fills in the installed versions, which check-upgrade does not print. Several
// versions of a kernel are installed side by side; the one installed last is the one meant.
func (d dnf) installed(ctx context.Context, items []report.PackageUpdate) {
	out, err := d.m.run(ctx, command{
		name:    "rpm",
		args:    []string{"-qa", "--qf", `%{NAME}.%{ARCH}\t%{EVR}\t%{INSTALLTIME}\n`},
		timeout: rpmTimeout,
	})
	if err != nil || out.code != 0 {
		return
	}
	version, when := map[string]string{}, map[string]int64{}
	for _, line := range strings.Split(out.stdout, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		t, _ := strconv.ParseInt(f[2], 10, 64)
		if _, seen := version[f[0]]; !seen || t >= when[f[0]] {
			version[f[0]], when[f[0]] = f[1], t
		}
	}
	for i := range items {
		items[i].Installed = version[items[i].Name]
	}
}

// reboot: dnf keeps no flag. The collector's comparison of kernels does the work.
func (dnf) reboot(context.Context) (bool, string) { return false, "" }

// parseDnfCheck reads "dnf check-upgrade", the same in dnf 4 and 5: one package a line as
// "name.arch  version  repository". After an empty line comes a section on packages that
// replace others, which repeats some of them; it is not read.
func parseDnfCheck(text string) []report.PackageUpdate {
	var out []report.PackageUpdate
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Obsoleting ") {
			break
		}
		f := strings.Fields(line)
		if len(f) != 3 || line[0] == ' ' || !strings.Contains(f[0], ".") {
			continue
		}
		out = append(out, report.PackageUpdate{Name: f[0], Candidate: f[1]})
	}
	return out
}

// rpmArch is what rpm calls the architectures Go knows by another name.
var rpmArch = map[string]string{"amd64": "x86_64", "arm64": "aarch64", "arm": "armv7hl", "386": "i686"}

// dnfShortName drops the architecture from "name.arch" where it says nothing: packages of the
// machine's own architecture and those without one. "SDL3.i686" on a 64-bit machine keeps it,
// as it is a second package next to "SDL3".
func dnfShortName(name, goarch string) string {
	native := rpmArch[goarch]
	if native == "" {
		native = goarch
	}
	for _, arch := range []string{native, "noarch"} {
		if short, ok := strings.CutSuffix(name, "."+arch); ok {
			return short
		}
	}
	return name
}
