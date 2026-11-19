package ospkg

import (
	"context"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// apk is Alpine's package manager. It says nothing about security, so no update is marked.
type apk struct{ m *machine }

func (apk) name() string { return "apk" }

const apkTimeout = time.Minute

// apkVersion lists the installed packages that are older than the index says is available.
// "apk upgrade --simulate" is not used: run by a normal user on Alpine 3.20 it answered
// "OK" although ten packages were waiting (testdata/README).
var apkVersion = command{name: "apk", args: []string{"--no-network", "version", "-l", "<"}, timeout: apkTimeout}

func (a apk) pending(ctx context.Context) (pending, error) {
	out, err := a.m.run(ctx, apkVersion)
	if err != nil {
		return pending{}, err
	}
	if out.code != 0 {
		return pending{}, failure(apkVersion, out)
	}
	got := pending{items: parseApkVersion(out.stdout)}
	// "apk update" gives the index files the time it ran.
	got.listsUpdated = a.m.newestMtime("/var/cache/apk/APKINDEX.*.tar.gz")
	if got.listsUpdated.IsZero() {
		// Without an index apk prints a warning and no package, which reads as "all up to
		// date". A container image is in that state until somebody runs "apk update".
		got.doubts = append(got.doubts,
			"there is no package index in /var/cache/apk, so no update can be seen: \"apk update\" has to run on this machine")
	}
	return got, nil
}

// reboot: Alpine keeps no flag. The collector's comparison of kernels does the work.
func (apk) reboot(context.Context) (bool, string) { return false, "" }

// parseApkVersion reads lines like "busybox-1.36.1-r28    < 1.36.1-r31". A name can hold
// dashes itself; the version is always the last two parts, "1.36.1" and "r28".
func parseApkVersion(text string) []report.PackageUpdate {
	var out []report.PackageUpdate
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[1] != "<" {
			continue
		}
		rel := strings.LastIndex(f[0], "-")
		if rel <= 0 {
			continue
		}
		ver := strings.LastIndex(f[0][:rel], "-")
		if ver <= 0 {
			continue
		}
		out = append(out, report.PackageUpdate{Name: f[0][:ver], Installed: f[0][ver+1:], Candidate: f[2]})
	}
	return out
}
