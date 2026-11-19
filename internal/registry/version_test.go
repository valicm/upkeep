package registry

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// loadTags reads a fixture of testdata/tags: every tag of one repository, as the registry
// listed them on the day named in the file's first lines.
func loadTags(t testing.TB, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "tags", name+".txt"))
	if err != nil {
		t.Fatalf("reading the tag list fixture: %v", err)
	}
	var tags []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			tags = append(tags, line)
		}
	}
	if len(tags) == 0 {
		t.Fatalf("fixture %s has no tags", name)
	}
	return tags
}

// The tag lists are the real ones of 2026-11-18 (see testdata/tags). The first block is every
// image of the homelab this was written for; the rest are other tags of the same repositories
// that show one rule each.
func TestNewerTagsRealLists(t *testing.T) {
	tests := []struct {
		fixture, current    string
		patch, minor, major string
	}{
		// The images in use.
		{"docker.io_gitea_gitea", "1.23.6", "1.23.8", "1.27.3", "28.4.0"},
		{"docker.io_library_mariadb", "11.4.13", "", "11.8.9", "13.0.2"},
		{"docker.io_library_mariadb", "11.8.9", "", "", "13.0.2"},
		{"docker.io_photoprism_photoprism", "251130", "", "", "261029"},
		{"lscr.io_linuxserver_unifi-network-application", "10.0.162-ls114", "", "10.6.109-ls155", ""},
		{"docker.io_library_mongo", "7.0.48", "", "", "9.0.8"},
		{"docker.io_adguard_adguardhome", "latest", "", "", ""},
		{"docker.io_louislam_uptime-kuma", "2", "", "", ""},
		{"docker.io_henrygd_beszel", "0.21.2", "", "", ""},
		{"docker.io_ollama_ollama", "latest", "", "", ""},
		{"docker.io_axllent_mailpit", "latest", "", "", ""},

		// A variant is part of the scheme: "-rootless" only sees "-rootless".
		{"docker.io_gitea_gitea", "1.23.6-rootless", "1.23.8-rootless", "1.27.3-rootless", "28.4.0-rootless"},
		// gitea stopped pushing a tag per architecture after 1.20.5.
		{"docker.io_gitea_gitea", "1.19.2-linux-arm64", "1.19.4-linux-arm64", "1.20.5-linux-arm64", ""},
		// mariadb 13 is built on "resolute", so the "noble" line ends with 12.
		{"docker.io_library_mariadb", "11.4.13-noble", "", "11.8.9-noble", "12.3.3-noble"},
		{"docker.io_library_mariadb", "11.4.13-ubi", "", "11.8.9-ubi", "13.0.2-ubi"},
		// mongo 8 and 9 have no "jammy" build at all.
		{"docker.io_library_mongo", "7.0.48-jammy", "", "", ""},
		{"docker.io_library_mongo", "6.0.5", "6.0.28", "", "9.0.8"},
		{"docker.io_library_mongo", "7.0.5-windowsservercore-ltsc2022", "7.0.48-windowsservercore-ltsc2022", "", "9.0.8-windowsservercore-ltsc2022"},
		{"docker.io_photoprism_photoprism", "251130-ce", "", "", "261029-ce"},
		{"docker.io_photoprism_photoprism", "250821-postgres", "", "", "260913-postgres"},
		{"docker.io_louislam_uptime-kuma", "2-slim", "", "", ""},
		// uptime-kuma 2 has no "alpine" build.
		{"docker.io_louislam_uptime-kuma", "1.23.9-alpine", "1.23.17-alpine", "", ""},
		{"docker.io_ollama_ollama", "0.40.10-rocm", "0.40.16-rocm", "", ""},

		// Rolling tags with fewer numbers compare among themselves.
		{"docker.io_gitea_gitea", "1.23", "", "1.27", "28.4"},
		{"docker.io_gitea_gitea", "1", "", "", "28"},
		{"docker.io_library_mariadb", "11.4", "", "11.8", "13.0"},
		{"docker.io_library_mariadb", "11", "", "", "13"},
		{"docker.io_library_mongo", "7.0", "", "", "9.0"},
		{"docker.io_louislam_uptime-kuma", "1", "", "", "2"},
		{"docker.io_henrygd_beszel", "0.19", "", "0.21", ""},
		{"docker.io_axllent_mailpit", "v1", "", "", ""},

		// Pre-releases are left out: mariadb has 13.1.1-rc, uptime-kuma 3.0.0-beta.1, AdGuard
		// Home v0.108.0-b.91 and v1.0.0-b.2, materia had v0.8.0-rc1.
		{"docker.io_louislam_uptime-kuma", "1.23.9", "1.23.17", "", "2.5.12"},
		{"docker.io_louislam_uptime-kuma", "2.4.0", "", "2.5.12", ""},
		{"docker.io_adguard_adguardhome", "v0.107.50", "v0.107.80", "", ""},
		{"docker.io_henrygd_beszel", "0.11.1", "", "0.21.2", ""},
		{"docker.io_ollama_ollama", "0.40.10", "0.40.16", "", ""},
		{"ghcr.io_stryan_materia", "v0.7.2", "", "v0.8.1", ""},
		{"ghcr.io_stryan_materia", "v0.8.1", "", "", ""},
		{"quay.io_prometheus_node-exporter", "v1.8.2", "", "v1.12.1", ""},
		{"quay.io_prometheus_node-exporter", "v0.18.1", "", "", "v1.12.1"},

		// Unless the tag in use is a pre-release: then its release, later pre-releases of the
		// same kind and releases above it all count.
		{"docker.io_gitea_gitea", "1.23.0-rc0", "1.23.8", "1.27.3", "28.4.0"},
		{"docker.io_gitea_gitea", "1.19-nightly", "1.19", "1.27", "28.4"},
		{"docker.io_library_mariadb", "13.0.1-rc", "13.0.2", "13.1.1-rc", ""},
		{"docker.io_library_mariadb", "13.1.1-rc", "", "", ""},
		{"docker.io_library_mongo", "8.0.0-rc20", "8.0.38", "8.3.17", "9.0.8"},
		{"docker.io_louislam_uptime-kuma", "2.1.0-beta.1", "2.1.3", "2.5.12", "3.0.0-beta.1"},
		{"docker.io_louislam_uptime-kuma", "3.0.0-beta.1", "", "", ""},
		{"docker.io_henrygd_beszel", "0.12.0-beta1", "0.12.12", "0.21.2", ""},
		{"docker.io_adguard_adguardhome", "v0.108.0-b.50", "v0.108.0-b.91", "", "v1.0.0-b.2"},
		{"ghcr.io_stryan_materia", "v0.8.0-rc1", "v0.8.1", "", ""},

		// linuxserver.io: the ls number counts builds, also of the same version; some tags of
		// one version were pushed with a "v" and some without.
		{"lscr.io_linuxserver_unifi-network-application", "10.6.109-ls152", "10.6.109-ls155", "", ""},
		{"lscr.io_linuxserver_unifi-network-application", "10.6.109-ls155", "", "", ""},
		{"lscr.io_linuxserver_unifi-network-application", "9.4.19-ls104", "", "9.5.21-ls109", "10.6.109-ls155"},
		{"lscr.io_linuxserver_unifi-network-application", "v9.5.21-ls106", "9.5.21-ls109", "", "10.6.109-ls155"},
		{"lscr.io_linuxserver_unifi-network-application", "8.0.7-ls16", "8.0.28-ls33", "8.6.9-ls73", "10.6.109-ls155"},
		// Its other spellings of the same versions stay apart.
		{"lscr.io_linuxserver_unifi-network-application", "10.0.162", "", "10.6.109", ""},
		{"lscr.io_linuxserver_unifi-network-application", "version-10.0.162", "", "version-10.6.109", ""},
		{"lscr.io_linuxserver_unifi-network-application", "arm64v8-10.0.162-ls114", "", "arm64v8-10.6.109-ls155", ""},
		{"lscr.io_linuxserver_unifi-network-application", "amd64-version-10.0.162", "", "amd64-version-10.6.109", ""},

		// mailpit dropped and added the "v" over the years: 1.2.5 was followed by v1.2.6.
		{"docker.io_axllent_mailpit", "1.2.5", "v1.2.9", "v1.34.0", ""},
		{"docker.io_axllent_mailpit", "v1.20.3", "v1.20.7", "v1.34.0", ""},
		{"docker.io_axllent_mailpit", "0.1.5", "", "", "v1.34.0"},

		// photoprism went from 20220121 to 220302: both are dates, and they are in that order.
		{"docker.io_photoprism_photoprism", "20220121", "", "", "261029"},
		{"docker.io_photoprism_photoprism", "261029", "", "", ""},

		// Tags that are not versions say nothing.
		{"docker.io_gitea_gitea", "latest-rootless", "", "", ""},
		{"docker.io_gitea_gitea", "main-nightly", "", "", ""},
		{"docker.io_photoprism_photoprism", "preview", "", "", ""},
		{"docker.io_library_mongo", "noble", "", "", ""},
		{"lscr.io_linuxserver_unifi-network-application", "amd64-latest", "", "", ""},
		{"ghcr.io_stryan_materia", "stable", "", "", ""},
		{"ghcr.io_stryan_materia", "sha256-109d608005bc404dbaeb481e3b2674eca2c0f489796ac5c8991532220d45420c", "", "", ""},
		// A suffix nobody can order is its own variant: nothing else has it.
		{"docker.io_adguard_adguardhome", "v0.100.3-dirty", "v0.100.5-dirty", "", ""},
		{"docker.io_adguard_adguardhome", "v0.105.0-SNAPSHOT-e829e7a0", "", "", ""},
		{"docker.io_ollama_ollama", "0.5.8-rc1rocm", "", "", ""}, // there is a 0.5.8-rc2rocm
	}
	lists := map[string][]string{}
	for _, tc := range tests {
		t.Run(tc.fixture+":"+tc.current, func(t *testing.T) {
			tags, ok := lists[tc.fixture]
			if !ok {
				tags = loadTags(t, tc.fixture)
				lists[tc.fixture] = tags
			}
			patch, minor, major := newerTags(tc.current, tags)
			if patch != tc.patch || minor != tc.minor || major != tc.major {
				t.Errorf("newerTags(%q) = patch %q, minor %q, major %q; want %q, %q, %q",
					tc.current, patch, minor, major, tc.patch, tc.minor, tc.major)
			}
		})
	}
}

// Whatever tag of a real repository is in use, a tag reported as newer must be one of the
// same shape with a higher version. This runs every tag of every fixture against its list.
func TestNewerTagsNeverLower(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "tags", "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no tag list fixtures: %v", err)
	}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".txt")
		tags := loadTags(t, name)
		var versions []tagVersion
		for _, tag := range tags {
			if v, ok := parseTag(tag); ok {
				versions = append(versions, v)
			}
		}
		if len(versions) == 0 {
			t.Errorf("%s: no tag was read as a version", name)
		}
		for _, cur := range versions {
			for _, got := range pickNewer(cur, versions) {
				if got == "" {
					continue
				}
				v, _ := parseTag(got)
				if v.lead != cur.lead || v.variant != cur.variant || v.kinds != cur.kinds || v.class != cur.class || len(v.nums) != len(cur.nums) {
					t.Errorf("%s: %q is called newer than %q, which is another kind of tag", name, got, cur.tag)
				}
				if c := compareNums(v.nums, cur.nums); c < 0 || (c == 0 && cur.pre == nil && compareNums(v.builds, cur.builds) <= 0) {
					t.Errorf("%s: %q is called newer than %q", name, got, cur.tag)
				}
				if cur.pre == nil && v.pre != nil {
					t.Errorf("%s: pre-release %q is offered to the release %q", name, got, cur.tag)
				}
			}
		}
	}
}

// Rules that the captured lists do not show, on small lists made for the purpose.
func TestNewerTagsRules(t *testing.T) {
	tests := []struct {
		name                string
		current             string
		tags                []string
		patch, minor, major string
	}{
		{"calendar versions, as Home Assistant's", "2026.11.1",
			[]string{"2026.10.4", "2026.11.0", "2026.11.1", "2026.11.3", "2026.12.0b2", "2026.12.0.dev20261115", "2026.12.0", "2027.1.0", "latest", "stable", "beta", "dev"},
			"2026.11.3", "2026.12.0", "2027.1.0"},
		{"a year does not follow a small major", "0.118.5",
			[]string{"0.118.5", "0.119.0", "2020.12.0", "2026.11.1"},
			"", "0.119.0", ""},
		{"nor a small major a year", "2021.3.4",
			[]string{"2021.3.4", "1.0.0", "2.5.1"},
			"", "", ""},
		{"a build ID is not a major", "2",
			[]string{"1", "2", "3", "20200120", "9799770991", "1234567", "2024"},
			"", "", "3"},
		{"a long number is no version", "9799770991",
			[]string{"9799770991", "9799770992", "10000000000"},
			"", "", ""},
		{"a six-digit number that is no date is no version", "251340",
			[]string{"251340", "251341", "261029"},
			"", "", ""},
		{"more or fewer numbers is another scheme", "1.2.3",
			[]string{"1.2", "1.3", "2", "1.2.3.1", "1.2.4.0", "14.3.9.99202110311443"},
			"", "", ""},
		{"four numbers", "4.0.14.2939",
			[]string{"4.0.14.2939", "4.0.14.2945", "4.0.15.2941", "4.1.0.1", "5.0.0.1", "4.0.9.9999"},
			"4.0.15.2941", "4.1.0.1", "5.0.0.1"},
		{"v and no v are the same release, the tag in use decides the spelling", "v1.2.0",
			[]string{"1.3.0", "v1.3.0", "v1.2.1", "1.2.1", "2.0.0"},
			"v1.2.1", "v1.3.0", "2.0.0"},
		{"and the other way round", "1.2.0",
			[]string{"v1.3.0", "1.3.0", "v1.2.1", "1.2.1", "v2.0.0"},
			"1.2.1", "1.3.0", "v2.0.0"},
		{"two build counters: Alpine's revision and linuxserver's build", "4.0.5-r0-ls226",
			[]string{"4.0.5-r0-ls226", "4.0.5-r0-ls230", "4.0.5-r1-ls231", "4.0.6-r0-ls240", "4.1.0-r0-ls250", "4.0.5-ls999", "version-4.0.6-r0", "2.94-r3-ls53"},
			"4.0.6-r0-ls240", "4.1.0-r0-ls250", ""},
		{"a later build of the version in use is a patch-level step", "4.0.5-r0-ls226",
			[]string{"4.0.5-r0-ls226", "4.0.5-r0-ls230", "4.0.5-r1-ls231", "4.0.5-r0-ls100"},
			"4.0.5-r1-ls231", "", ""},
		{"a commit hash in the tag makes every tag its own variant", "1.40.0.7998-c29d4c0c8-ls200",
			[]string{"1.40.0.7998-c29d4c0c8-ls200", "1.40.1.8227-c0dd5a73e-ls205", "1.41.0.8992-8463ad060-ls230"},
			"", "", ""},
		{"a variant with a number in it must be the very same", "3.12.1-alpine3.19",
			[]string{"3.12.1-alpine3.19", "3.12.4-alpine3.19", "3.12.7-alpine3.20", "3.13.0-alpine3.20", "3.12.7-alpine", "3.12.7"},
			"3.12.4-alpine3.19", "", ""},
		{"beta, then rc, then the release", "2.0.0-beta.3",
			[]string{"2.0.0-alpha.9", "2.0.0-beta.2", "2.0.0-beta.3", "2.0.0-beta.4", "2.0.0-rc.1", "1.9.9"},
			"2.0.0-rc.1", "", ""},
		{"an rc with a number and one without do not compare", "8.0-rc",
			[]string{"8.0-rc", "8.0-rc1", "8.0-preview", "8.0-nightly"},
			"", "", ""},
		{"from a nightly only nightlies and releases", "1.19-nightly",
			[]string{"1.19-nightly", "1.20-nightly", "1.20-rc1", "1.20-dev", "1.21-beta"},
			"", "1.20-nightly", ""},
		{"pre-release words without a dash, as Python packages write them", "1.0b1",
			[]string{"1.0a5", "1.0b1", "1.0b2", "1.0rc1", "1.0", "1.1b1", "1.1"},
			"1.0", "1.1", ""},
		{"the release wins over a pre-release of the same version", "1.0.0-rc1",
			[]string{"1.1.0-rc2", "1.1.0", "1.1.0-rc3"},
			"", "1.1.0", ""},
		{"architecture and other words in front keep tags apart", "1.2.3",
			[]string{"amd64-1.2.4", "arm64v8-1.3.0", "version-1.2.9", "release-2.0.0", "sha-1234567", "pr-124", "build-99", "nightly-1.2.9"},
			"", "", ""},
		{"a word in front that is not known is no version", "pr-123",
			[]string{"pr-123", "pr-124", "pr-200"},
			"", "", ""},
		{"a date written with dashes is no version", "2024-05-01",
			[]string{"2024-05-01", "2024-06-01", "2025-05-01", "2024-05-02", "2025"},
			"", "", ""},
		{"eight-digit dates", "20240311",
			[]string{"20240101", "20240311", "20240401", "20241301", "240501", "20240401-arm64"},
			"", "", "240501"},
		{"numbers too long to hold", "1.2.3",
			[]string{"99999999999999999999.0.0", "1.99999999999999999999.0", "1.2.4"},
			"1.2.4", "", ""},
		{"an empty or broken tail", "1.2.3",
			[]string{"1.2.4-", "1.2.5--x", "1.2.6.", "1.2.7_", "1.2.8"},
			"1.2.8", "", ""},
		{"nothing in the list", "1.2.3", nil, "", "", ""},
		{"only itself in the list", "1.2.3", []string{"1.2.3", "1.2.3", "v1.2.3"}, "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			patch, minor, major := newerTags(tc.current, tc.tags)
			if patch != tc.patch || minor != tc.minor || major != tc.major {
				t.Errorf("newerTags(%q, %q) = patch %q, minor %q, major %q; want %q, %q, %q",
					tc.current, tc.tags, patch, minor, major, tc.patch, tc.minor, tc.major)
			}
		})
	}
}

func TestParseTag(t *testing.T) {
	rc := func(word string, num uint64, hasNum bool) *preRelease { return &preRelease{word, num, hasNum} }
	tests := []struct {
		tag  string
		want tagVersion // tag is filled in by the test
		ok   bool
	}{
		{"1.23.6", tagVersion{nums: []uint64{1, 23, 6}, class: classSmall}, true},
		{"v0.107.80", tagVersion{v: true, nums: []uint64{0, 107, 80}, class: classSmall}, true},
		{"2", tagVersion{nums: []uint64{2}, class: classSmall}, true},
		{"11.4", tagVersion{nums: []uint64{11, 4}, class: classSmall}, true},
		{"251130", tagVersion{nums: []uint64{20251130}, class: classDate}, true},
		{"20200120", tagVersion{nums: []uint64{20200120}, class: classDate}, true},
		{"2026.11.1", tagVersion{nums: []uint64{2026, 11, 1}, class: classYear}, true},
		{"10.0.162-ls114", tagVersion{nums: []uint64{10, 0, 162}, class: classSmall, kinds: "ls,", builds: []uint64{114}}, true},
		{"arm64v8-10.0.162-ls114", tagVersion{lead: "arm64v8-", nums: []uint64{10, 0, 162}, class: classSmall, kinds: "ls,", builds: []uint64{114}}, true},
		{"amd64-version-v9.5.21", tagVersion{lead: "amd64-version-", v: true, nums: []uint64{9, 5, 21}, class: classSmall}, true},
		{"4.0.5-r0-ls226", tagVersion{nums: []uint64{4, 0, 5}, class: classSmall, kinds: "r,ls,", builds: []uint64{0, 226}}, true},
		{"1.23.6-rootless", tagVersion{nums: []uint64{1, 23, 6}, class: classSmall, variant: "rootless"}, true},
		{"1.14.0-rc1-rootless", tagVersion{nums: []uint64{1, 14, 0}, class: classSmall, variant: "rootless", pre: rc("rc", 1, true)}, true},
		{"11.5.1-noble-rc", tagVersion{nums: []uint64{11, 5, 1}, class: classSmall, variant: "noble", pre: rc("rc", 0, false)}, true},
		{"2.0.0-beta-slim-rootless.0", tagVersion{nums: []uint64{2, 0, 0}, class: classSmall, variant: "slim-rootless.0", pre: rc("beta", 0, false)}, true},
		{"v0.108.0-b.91", tagVersion{v: true, nums: []uint64{0, 108, 0}, class: classSmall, pre: rc("b", 91, true)}, true},
		{"v0.105.0-SNAPSHOT-e829e7a0", tagVersion{v: true, nums: []uint64{0, 105, 0}, class: classSmall, variant: "e829e7a0", pre: rc("snapshot", 0, false)}, true},
		{"2026.12.0.dev20261115", tagVersion{nums: []uint64{2026, 12, 0}, class: classYear, pre: rc("dev", 20261115, true)}, true},
		{"2026.12.0b2", tagVersion{nums: []uint64{2026, 12, 0}, class: classYear, pre: rc("b", 2, true)}, true},
		{"7.0.48-windowsservercore-ltsc2022", tagVersion{nums: []uint64{7, 0, 48}, class: classSmall, variant: "windowsservercore-ltsc2022"}, true},
		{"1.2.3-b", tagVersion{nums: []uint64{1, 2, 3}, class: classSmall, variant: "b"}, true},
		{"1.2.3-rc1-rc2", tagVersion{nums: []uint64{1, 2, 3}, class: classSmall, variant: "rc2", pre: rc("rc", 1, true)}, true},

		{"latest", tagVersion{}, false},
		{"stable", tagVersion{}, false},
		{"v", tagVersion{}, false},
		{"vnext", tagVersion{}, false},
		{"sha-1a2b3c4", tagVersion{}, false},
		{"sha256-109d608005bc404dbaeb481e3b2674eca2c0f489796ac5c8991532220d45420c", tagVersion{}, false},
		{"amd64-latest", tagVersion{lead: "amd64-"}, false},
		{"1234567", tagVersion{}, false},  // seven digits: a short commit hash made of digits
		{"1809", tagVersion{}, false},     // four digits that are no year: a Windows build
		{"251340", tagVersion{}, false},   // six digits that are no date
		{"20241301", tagVersion{}, false}, // eight digits that are no date
		{"9799770991", tagVersion{}, false},
		{"1.2.3-", tagVersion{nums: []uint64{1, 2, 3}, class: classSmall}, false},
		{"1.2.3--x", tagVersion{nums: []uint64{1, 2, 3}, class: classSmall}, false},
	}
	for _, tc := range tests {
		t.Run(tc.tag, func(t *testing.T) {
			got, ok := parseTag(tc.tag)
			if ok != tc.ok {
				t.Fatalf("parseTag(%q) ok = %v, want %v (parsed as %+v)", tc.tag, ok, tc.ok, got)
			}
			if !ok {
				return // what was read before giving up does not matter
			}
			tc.want.tag = tc.tag
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseTag(%q)\n got %+v pre %+v\nwant %+v pre %+v", tc.tag, got, got.pre, tc.want, tc.want.pre)
			}
		})
	}
}

func TestComparePre(t *testing.T) {
	pre := func(word string, num int) preRelease {
		if num < 0 {
			return preRelease{word: word}
		}
		return preRelease{word: word, num: uint64(num), hasNum: true}
	}
	tests := []struct {
		a, b  preRelease
		order int // -1, 0, 1 as a is before, the same as, after b
		known bool
	}{
		{pre("rc", 1), pre("rc", 2), -1, true},
		{pre("rc", 10), pre("rc", 9), 1, true},
		{pre("rc", 1), pre("rc", 1), 0, true},
		{pre("rc", -1), pre("rc", -1), 0, true},
		{pre("rc", -1), pre("rc", 1), 0, false},
		{pre("alpha", 9), pre("beta", 1), -1, true},
		{pre("rc", 1), pre("beta", 9), 1, true},
		{pre("rc", -1), pre("alpha", -1), 1, true},
		{pre("b", 2), pre("beta", 3), -1, true}, // "b" is how some write beta
		{pre("nightly", 20261101), pre("nightly", 20261102), -1, true},
		{pre("nightly", 1), pre("dev", 2), 0, false},
		{pre("preview", 1), pre("rc", 1), 0, false},
		{pre("rc", 1), pre("preview", 1), 0, false},
	}
	for _, tc := range tests {
		order, known := comparePre(tc.a, tc.b)
		sign := 0
		switch {
		case order < 0:
			sign = -1
		case order > 0:
			sign = 1
		}
		if sign != tc.order || known != tc.known {
			t.Errorf("comparePre(%+v, %+v) = %d, %v; want %d, %v", tc.a, tc.b, order, known, tc.order, tc.known)
		}
	}
}
