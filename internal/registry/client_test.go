package registry

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
)

// homelabImage is one image of the homelab this was written for, with what its registry said
// on 2026-11-18: the tag list in testdata/tags and the Docker-Content-Digest of a HEAD on the
// tag in use (for the image pinned by digest: of "latest", which the tests use elsewhere).
type homelabImage struct {
	image   string
	apiHost string
	repo    string
	fixture string
	tag     string
	digest  string
	want    model.ImageCheck // Image, Tag and CheckedAt are filled in by the test
}

var homelab = []homelabImage{
	{"docker.io/gitea/gitea:1.23.6", "registry-1.docker.io", "gitea/gitea", "docker.io_gitea_gitea", "1.23.6",
		"sha256:01bb6f98fb9e256554d59c85b9f1cb39f3da68202910ea0909d61c6b449c207d",
		model.ImageCheck{NewerPatch: "1.23.8", NewerMinor: "1.27.3", NewerMajor: "28.4.0"}},
	{"docker.io/library/mariadb:11.4.13", "registry-1.docker.io", "library/mariadb", "docker.io_library_mariadb", "11.4.13",
		"sha256:5e73baf8179b29f115101bb102763a47a017361f3e9792daccba6646c3ab1532",
		model.ImageCheck{NewerMinor: "11.8.9", NewerMajor: "13.0.2"}},
	{"docker.io/library/mariadb:11.8.9", "registry-1.docker.io", "library/mariadb", "docker.io_library_mariadb", "11.8.9",
		"sha256:d36f18d65a0459510b8b0f643b226a6d299e3206486e2b64ff20754a6d291707",
		model.ImageCheck{NewerMajor: "13.0.2"}},
	{"docker.io/photoprism/photoprism:251130", "registry-1.docker.io", "photoprism/photoprism", "docker.io_photoprism_photoprism", "251130",
		"sha256:db16ee6b1ba3e5bc5ad787a3141a082532d1b30932c8b1396fa609394374b83f",
		model.ImageCheck{NewerMajor: "261029"}},
	{"lscr.io/linuxserver/unifi-network-application:10.0.162-ls114", "lscr.io", "linuxserver/unifi-network-application", "lscr.io_linuxserver_unifi-network-application", "10.0.162-ls114",
		"sha256:1c3667f6f145b49dcbd105b090a3740a6403f2ae02a164ae9231649e073e2f84",
		model.ImageCheck{NewerMinor: "10.6.109-ls155"}},
	{"docker.io/library/mongo:7.0.48", "registry-1.docker.io", "library/mongo", "docker.io_library_mongo", "7.0.48",
		"sha256:884c055bff8b7144ca44830d01826facd3083b33c4dea44b94a1476c62de3c32",
		model.ImageCheck{NewerMajor: "9.0.8"}},
	{"docker.io/adguard/adguardhome:latest", "registry-1.docker.io", "adguard/adguardhome", "docker.io_adguard_adguardhome", "latest",
		"sha256:e2e1b48c832f7705be915873f95de0d5114de573736441d7f2923a8a6293027c",
		model.ImageCheck{}},
	{"docker.io/louislam/uptime-kuma:2", "registry-1.docker.io", "louislam/uptime-kuma", "docker.io_louislam_uptime-kuma", "2",
		"sha256:8e4b6bef96417ec98a35dc103c99cc64fc229a01e584e56d95d9004d2003c02a",
		model.ImageCheck{}},
	{"docker.io/henrygd/beszel:0.21.2", "registry-1.docker.io", "henrygd/beszel", "docker.io_henrygd_beszel", "0.21.2",
		"sha256:b0be90bd4aee2993fde763032a5098ce4386fba43cfe5031ec017b8d9e8c97a2",
		model.ImageCheck{}},
	{"docker.io/ollama/ollama:latest", "registry-1.docker.io", "ollama/ollama", "docker.io_ollama_ollama", "latest",
		"sha256:910d0d8107b538fb0894e63163eb195de0cc7aefcbc666dc62d3b18f71124592",
		model.ImageCheck{}},
	{"docker.io/axllent/mailpit:latest", "registry-1.docker.io", "axllent/mailpit", "docker.io_axllent_mailpit", "latest",
		"sha256:23a2ef85bc50853ab3093645d1d64679afd8887e89da5e48a88940c172591a4e",
		model.ImageCheck{}},
	// Pinned by digest, no tag: nothing is asked and nothing is known.
	{"ghcr.io/stryan/materia@sha256:c32ebfeefe9c65a225f9c034a7049a940e3556a49aed38588cabf8cfd25baace", "ghcr.io", "stryan/materia", "ghcr.io_stryan_materia", "latest",
		"sha256:c32ebfeefe9c65a225f9c034a7049a940e3556a49aed38588cabf8cfd25baace",
		model.ImageCheck{}},
	// Built on the machine: no registry has it.
	{"localhost/medimorec-server:current", "", "", "", "current", "", model.ImageCheck{}},
}

// quayImage is not in the homelab; quay.io is here because it behaves unlike the others.
var quayImage = homelabImage{"quay.io/prometheus/node-exporter:v1.8.2", "quay.io", "prometheus/node-exporter", "quay.io_prometheus_node-exporter", "v1.8.2",
	"sha256:4032c6d5bfd752342c3e631c2f1de93ba6b86c41db6b167b9a35372c139e7706",
	model.ImageCheck{NewerMinor: "v1.12.1"}}

// newHomelabRegistry returns a fake with every repository of the homelab and quay.io's.
func newHomelabRegistry(t *testing.T) *fakeRegistry {
	f := newFakeRegistry(t)
	digests := map[string]map[string]string{}
	for _, img := range append(homelab[:len(homelab):len(homelab)], quayImage) {
		if img.fixture == "" {
			continue
		}
		key := img.apiHost + "/" + img.repo
		if digests[key] == nil {
			digests[key] = map[string]string{}
			f.add(img.apiHost, img.repo, img.fixture, digests[key])
		}
		digests[key][img.tag] = img.digest
	}
	return f
}

func TestCheckHomelabImages(t *testing.T) {
	f := newHomelabRegistry(t)
	for _, img := range append(homelab[:len(homelab):len(homelab)], quayImage) {
		t.Run(img.image, func(t *testing.T) {
			before := len(f.requests())
			got := f.client(Options{}).Check(context.Background(), img.image)

			want := img.want
			want.Image, want.CheckedAt = img.image, f.clock.Now()
			remote := img.fixture != "" && !strings.Contains(img.image, "@")
			if remote {
				want.Tag, want.TagDigest = img.tag, img.digest
			} else if img.fixture == "" {
				want.Tag = img.tag
			}
			if got != want {
				t.Errorf("Check(%q)\n got %+v\nwant %+v", img.image, got, want)
			}
			asked := f.requests()[before:]
			if !remote && len(asked) != 0 {
				t.Errorf("Check(%q) asked a registry: %q", img.image, asked)
			}
			for _, line := range asked {
				if strings.HasPrefix(line, "GET ") && strings.Contains(line, "/manifests/") {
					t.Errorf("Check(%q) made %q: a GET of a manifest counts as a pull", img.image, line)
				}
			}
		})
	}
}

// The exact conversation with each kind of registry, for a client that has not talked to it
// before.
func TestCheckRequests(t *testing.T) {
	tests := []struct {
		image string
		want  []string
	}{
		{"docker.io/gitea/gitea:1.23.6", []string{
			"HEAD registry-1.docker.io/v2/gitea/gitea/manifests/1.23.6 401",
			"GET auth.docker.io/token?scope=repository%3Agitea%2Fgitea%3Apull&service=registry.docker.io 200",
			"HEAD registry-1.docker.io/v2/gitea/gitea/manifests/1.23.6 200",
			"GET registry-1.docker.io/v2/gitea/gitea/tags/list?n=1000 200",
		}},
		// One-word names are under library/ on Docker Hub; 3729 tags come in four pages.
		{"mongo:7.0.48", []string{
			"HEAD registry-1.docker.io/v2/library/mongo/manifests/7.0.48 401",
			"GET auth.docker.io/token?scope=repository%3Alibrary%2Fmongo%3Apull&service=registry.docker.io 200",
			"HEAD registry-1.docker.io/v2/library/mongo/manifests/7.0.48 200",
			"GET registry-1.docker.io/v2/library/mongo/tags/list?n=1000 200",
			"GET registry-1.docker.io/v2/library/mongo/tags/list?last=4.2.24-rc1-windowsservercore-ltsc2022&n=1000 200",
			"GET registry-1.docker.io/v2/library/mongo/tags/list?last=6.0.1-nanoserver&n=1000 200",
			"GET registry-1.docker.io/v2/library/mongo/tags/list?last=8.0-windowsservercore-1809&n=1000 200",
		}},
		// A tag that is no version: its digest is all there is to know, the tags are not listed.
		{"docker.io/adguard/adguardhome:latest", []string{
			"HEAD registry-1.docker.io/v2/adguard/adguardhome/manifests/latest 401",
			"GET auth.docker.io/token?scope=repository%3Aadguard%2Fadguardhome%3Apull&service=registry.docker.io 200",
			"HEAD registry-1.docker.io/v2/adguard/adguardhome/manifests/latest 200",
		}},
		// lscr.io answers itself and takes ghcr.io's tokens.
		{"lscr.io/linuxserver/unifi-network-application:10.0.162-ls114", []string{
			"HEAD lscr.io/v2/linuxserver/unifi-network-application/manifests/10.0.162-ls114 401",
			"GET ghcr.io/token?scope=repository%3Alinuxserver%2Funifi-network-application%3Apull&service=ghcr.io 200",
			"HEAD lscr.io/v2/linuxserver/unifi-network-application/manifests/10.0.162-ls114 200",
			"GET lscr.io/v2/linuxserver/unifi-network-application/tags/list?n=1000 200",
		}},
		// quay.io wants no token for a public repository.
		{"quay.io/prometheus/node-exporter:v1.8.2", []string{
			"HEAD quay.io/v2/prometheus/node-exporter/manifests/v1.8.2 200",
			"GET quay.io/v2/prometheus/node-exporter/tags/list?n=1000 200",
		}},
		// A tag next to a digest is still a tag to compare.
		{"docker.io/henrygd/beszel:0.21.2@sha256:b0be90bd4aee2993fde763032a5098ce4386fba43cfe5031ec017b8d9e8c97a2", []string{
			"HEAD registry-1.docker.io/v2/henrygd/beszel/manifests/0.21.2 401",
			"GET auth.docker.io/token?scope=repository%3Ahenrygd%2Fbeszel%3Apull&service=registry.docker.io 200",
			"HEAD registry-1.docker.io/v2/henrygd/beszel/manifests/0.21.2 200",
			"GET registry-1.docker.io/v2/henrygd/beszel/tags/list?n=1000 200",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.image, func(t *testing.T) {
			f := newHomelabRegistry(t)
			got := f.client(Options{}).Check(context.Background(), tc.image)
			if got.Error != "" || got.TagDigest == "" {
				t.Errorf("Check(%q) = %+v", tc.image, got)
			}
			if asked := f.requests(); !reflect.DeepEqual(asked, tc.want) {
				t.Errorf("Check(%q) asked\n%s\nwant\n%s", tc.image, strings.Join(asked, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

func TestPagination(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		pageSize int
		maxTags  int
		pages    int    // requests for the tag list
		lastPage string // how the registry writes the link, seen in the last request
		want     model.ImageCheck
		note     string // what Note has to say when the list was cut; it is no error
	}{
		{name: "Docker Hub, 3729 tags in pages of 50", image: "docker.io/library/mongo:7.0.48", pageSize: 50, pages: 75,
			lastPage: "/tags/list?last=latest&n=50 200",
			want:     model.ImageCheck{NewerMajor: "9.0.8"}},
		{name: "quay.io gives 100 a page whatever is asked: 65 tags fit", image: "quay.io/prometheus/node-exporter:v1.8.2", pageSize: 1000, pages: 1,
			lastPage: "/tags/list?n=1000 200",
			want:     model.ImageCheck{NewerMinor: "v1.12.1"}},
		{name: "quay.io in pages of 20, n before last", image: "quay.io/prometheus/node-exporter:v1.8.2", pageSize: 20, pages: 4,
			lastPage: "/tags/list?n=20&last=v1.8.1 200",
			want:     model.ImageCheck{NewerMinor: "v1.12.1"}},
		{name: "ghcr.io lists by age, so a cut list loses the newest", image: "lscr.io/linuxserver/unifi-network-application:10.0.162-ls114", pageSize: 100, maxTags: 600, pages: 6,
			lastPage: "/tags/list?last=arm64v8-10.0.162-ls112&n=100 200",
			want:     model.ImageCheck{NewerMinor: "10.4.57-ls133"}, // the whole list has 10.6.109-ls155
			note:     "only the first 600 tags of lscr.io/linuxserver/unifi-network-application were read, newer ones may be missing"},
		{name: "a limit inside a page", image: "docker.io/gitea/gitea:1.0.0", pageSize: 1000, maxTags: 100, pages: 1,
			lastPage: "/tags/list?n=100 200",
			want:     model.ImageCheck{NewerPatch: "1.0.2", NewerMinor: "1.12.2"}, // the whole list has 1.27.3 and 28.4.0
			note:     "only the first 100 tags of docker.io/gitea/gitea were read, newer ones may be missing"},
		{name: "a limit that is exactly the list is no cut", image: "docker.io/henrygd/beszel:0.20.0", pageSize: 51, maxTags: 102, pages: 2,
			lastPage: "/tags/list?last=0.16.1&n=51 200",
			want:     model.ImageCheck{NewerMinor: "0.21.2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newHomelabRegistry(t)
			// The digests of these tags were not captured; any will do here.
			for key, repo := range f.repos {
				if strings.HasSuffix(key, "/gitea/gitea") || strings.HasSuffix(key, "/henrygd/beszel") {
					repo.digests["1.0.0"], repo.digests["0.20.0"] = someDigest, someDigest
				}
			}
			c := f.client(Options{MaxTags: tc.maxTags})
			c.pageSize = tc.pageSize
			got := c.Check(context.Background(), tc.image)
			if got.NewerPatch != tc.want.NewerPatch || got.NewerMinor != tc.want.NewerMinor || got.NewerMajor != tc.want.NewerMajor {
				t.Errorf("Check(%q) = patch %q, minor %q, major %q; want %q, %q, %q", tc.image,
					got.NewerPatch, got.NewerMinor, got.NewerMajor, tc.want.NewerPatch, tc.want.NewerMinor, tc.want.NewerMajor)
			}
			if got.Note != tc.note || got.Error != "" {
				t.Errorf("Check(%q) Note = %q and Error = %q, want the note %q and no error", tc.image, got.Note, got.Error, tc.note)
			}
			var lists []string
			for _, line := range f.requests() {
				if strings.Contains(line, "/tags/list") && strings.HasSuffix(line, " 200") {
					lists = append(lists, line)
				}
			}
			if len(lists) != tc.pages {
				t.Fatalf("Check(%q) read %d pages, want %d:\n%s", tc.image, len(lists), tc.pages, strings.Join(lists, "\n"))
			}
			if last := lists[len(lists)-1]; !strings.HasSuffix(last, tc.lastPage) {
				t.Errorf("the last page was asked for as %q, want it to end in %q", last, tc.lastPage)
			}
		})
	}
}

// Tokens are kept per repository until they expire, and a registry that asked for a token
// once is not asked without one again.
func TestTokenCache(t *testing.T) {
	f := newHomelabRegistry(t)
	c := f.client(Options{})
	ctx := context.Background()
	check := func(image string) {
		t.Helper()
		if got := c.Check(ctx, image); got.Error != "" || got.TagDigest == "" {
			t.Fatalf("Check(%q) = %+v", image, got)
		}
	}
	expect := func(step string, hubTokens, ghcrTokens, refusals int) {
		t.Helper()
		got := [3]int{f.count("GET auth.docker.io/token"), f.count("GET ghcr.io/token"), 0}
		for _, line := range f.requests() {
			if strings.HasSuffix(line, " 401") {
				got[2]++
			}
		}
		if want := [3]int{hubTokens, ghcrTokens, refusals}; got != want {
			t.Fatalf("%s: tokens from Docker Hub, tokens from ghcr.io, answers 401 = %v, want %v\n%s", step, got, want, strings.Join(f.requests(), "\n"))
		}
	}

	check("docker.io/gitea/gitea:1.23.6")
	expect("first check", 1, 0, 1)
	check("docker.io/gitea/gitea:1.23.6")
	expect("the same image again", 1, 0, 1)
	check("docker.io/library/mariadb:11.4.13")
	expect("another repository: a token of its own, and no 401 to learn where from", 2, 0, 1)
	check("docker.io/library/mariadb:11.8.9")
	expect("another tag of that repository", 2, 0, 1)

	// Docker Hub's tokens live 300 seconds.
	f.clock.Advance(280 * time.Second)
	check("docker.io/gitea/gitea:1.23.6")
	expect("after 280 s the token is still good", 2, 0, 1)
	f.clock.Advance(15 * time.Second)
	check("docker.io/gitea/gitea:1.23.6")
	expect("after 295 s it is too close to its end to be used", 3, 0, 1)

	// ghcr.io does not say how long its tokens live: 60 seconds then.
	check("lscr.io/linuxserver/unifi-network-application:10.0.162-ls114")
	expect("first check on lscr.io", 3, 1, 2)
	f.clock.Advance(45 * time.Second)
	check("lscr.io/linuxserver/unifi-network-application:10.0.162-ls114")
	expect("after 45 s", 3, 1, 2)
	f.clock.Advance(10 * time.Second)
	check("lscr.io/linuxserver/unifi-network-application:10.0.162-ls114")
	expect("after 55 s", 3, 2, 2)

	// A registry may drop a token early. The 401 then leads to a new one.
	f.mu.Lock()
	clear(f.tokens)
	f.mu.Unlock()
	check("docker.io/gitea/gitea:1.23.6")
	expect("after the registry forgot its tokens", 4, 2, 3)
}

// A registry may move its token service. What the client remembers is then wrong, and the
// 401 that follows has to be read again, not taken for "not public".
func TestTokenServiceMoves(t *testing.T) {
	f := newHomelabRegistry(t)
	c := f.client(Options{})
	const image = "docker.io/gitea/gitea:1.23.6"
	// At first the registry names a service that issues tokens the registry does not take.
	firstHead := true
	f.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Host == "old.example":
			fmt.Fprintf(w, `{"token":"%s-from-the-old-service"}`, secretMark)
			return true
		case r.Method == http.MethodHead && firstHead:
			firstHead = false
			w.Header().Set("Www-Authenticate", `Bearer realm="https://old.example/token",service="registry.docker.io"`)
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		return false
	})
	if got := c.Check(context.Background(), image); !strings.Contains(got.Error, "not found, or not public (HTTP 401)") {
		t.Fatalf("with a token service whose tokens are refused: %+v", got)
	}
	// Once that token has expired the client goes to the old service again, is refused, and
	// must now follow the registry to the service it names.
	f.clock.Advance(2 * time.Minute)
	got := c.Check(context.Background(), image)
	if got.Error != "" || got.TagDigest != homelab[0].digest || got.NewerPatch != "1.23.8" {
		t.Errorf("after the registry named another token service: %+v\n%s", got, strings.Join(f.requests(), "\n"))
	}
	if n := f.count("GET old.example/token"); n != 2 {
		t.Errorf("the old token service was asked %d times, want 2", n)
	}
}

func TestCheckFailures(t *testing.T) {
	const tagsOfGitea = "GET registry-1.docker.io/v2/gitea/gitea/tags/list"
	answer := func(status int, header, body string) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if name, value, ok := strings.Cut(header, ": "); ok {
				w.Header().Set(name, value)
			}
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		}
	}
	tests := []struct {
		name  string
		image string
		// when a request line ("GET host/path?query") starts with on, the fake answers with do.
		on   string
		do   func(http.ResponseWriter, *http.Request)
		opts Options
		want model.ImageCheck // Error is compared as a whole; Image and CheckedAt are filled in
	}{
		{name: "not a reference", image: "docker.io/Gitea/gitea:1",
			want: model.ImageCheck{Error: `image reference "docker.io/Gitea/gitea:1": "Gitea/gitea" is not a repository name`}},
		{name: "empty", image: "",
			want: model.ImageCheck{Error: "empty image reference"}},
		// Docker Hub gives a token for any name, and then 401 with error="insufficient_scope".
		{name: "Docker Hub: a repository that does not exist", image: "docker.io/library/no-such-image:1.2.3",
			want: model.ImageCheck{Tag: "1.2.3", Error: "asking what docker.io/library/no-such-image:1.2.3 points at: not found, or not public (HTTP 401)"}},
		// ghcr.io refuses the token itself.
		{name: "ghcr.io: a repository that does not exist", image: "ghcr.io/stryan/no-such-image:v1",
			want: model.ImageCheck{Tag: "v1", Error: "asking what ghcr.io/stryan/no-such-image:v1 points at: getting a token from ghcr.io: not found, or not public (HTTP 403 DENIED)"}},
		// quay.io asks for a token only now, gives one, and refuses it.
		{name: "quay.io: a repository that does not exist", image: "quay.io/prometheus/no-such-image:v1",
			want: model.ImageCheck{Tag: "v1", Error: "asking what quay.io/prometheus/no-such-image:v1 points at: not found, or not public (HTTP 401)"}},
		{name: "a tag that is gone: the newer ones are still found", image: "docker.io/gitea/gitea:1.23.99",
			want: model.ImageCheck{Tag: "1.23.99", NewerMinor: "1.27.3", NewerMajor: "28.4.0", Error: "docker.io/gitea/gitea has no tag 1.23.99 (any more)"}},
		{name: "a tag that is gone and no version", image: "docker.io/gitea/gitea:gone",
			want: model.ImageCheck{Tag: "gone", Error: "docker.io/gitea/gitea has no tag gone (any more)"}},
		{name: "the tag list fails: the digest is still reported", image: "docker.io/gitea/gitea:1.23.6",
			on: tagsOfGitea, do: answer(http.StatusInternalServerError, "", "<html>oops</html>"),
			want: model.ImageCheck{Tag: "1.23.6", TagDigest: homelab[0].digest, Error: "listing the tags of docker.io/gitea/gitea: unexpected answer (HTTP 500)"}},
		{name: "over the pull limit", image: "docker.io/gitea/gitea:1.23.6",
			on: tagsOfGitea, do: answer(http.StatusTooManyRequests, "Content-Type: application/json", hubTooManyRequests),
			want: model.ImageCheck{Tag: "1.23.6", TagDigest: homelab[0].digest, Error: "listing the tags of docker.io/gitea/gitea: too many requests, the registry asks to slow down (HTTP 429 TOOMANYREQUESTS)"}},
		{name: "over the pull limit on the HEAD: nothing more is asked", image: "docker.io/gitea/gitea:1.23.6",
			on: "HEAD registry-1.docker.io/v2/gitea/gitea/manifests/", do: answer(http.StatusTooManyRequests, "", ""),
			want: model.ImageCheck{Tag: "1.23.6", Error: "asking what docker.io/gitea/gitea:1.23.6 points at: too many requests, the registry asks to slow down (HTTP 429)"}},
		{name: "a tag list that is not JSON", image: "docker.io/gitea/gitea:1.23.6",
			on: tagsOfGitea, do: answer(http.StatusOK, "Content-Type: text/html", "<html>a captive portal</html>"),
			want: model.ImageCheck{Tag: "1.23.6", TagDigest: homelab[0].digest, Error: "listing the tags of docker.io/gitea/gitea: the answer is not a list of tags"}},
		{name: "a tag list without end", image: "docker.io/gitea/gitea:1.23.6",
			on: tagsOfGitea, do: answer(http.StatusOK, "", `{"tags":["`+strings.Repeat("x", maxTagsBody)+`"]}`),
			want: model.ImageCheck{Tag: "1.23.6", TagDigest: homelab[0].digest, Error: "listing the tags of docker.io/gitea/gitea: the answer is larger than 4194304 bytes"}},
		{name: "a registry that does not answer in time", image: "docker.io/gitea/gitea:1.23.6",
			on: tagsOfGitea, do: func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
			},
			opts: Options{Timeout: 300 * time.Millisecond},
			want: model.ImageCheck{Tag: "1.23.6", TagDigest: homelab[0].digest, Error: "listing the tags of docker.io/gitea/gitea: no answer within 300ms"}},
		{name: "no digest in the answer", image: "docker.io/gitea/gitea:1.23.6",
			on: "HEAD registry-1.docker.io/v2/gitea/gitea/manifests/", do: answer(http.StatusOK, "Docker-Content-Digest: latest", ""),
			want: model.ImageCheck{Tag: "1.23.6", Error: "asking what docker.io/gitea/gitea:1.23.6 points at: the registry did not name a digest"}},
		{name: "a 401 that names no token service", image: "docker.io/gitea/gitea:1.23.6",
			on: "HEAD registry-1.docker.io/", do: answer(http.StatusUnauthorized, `Www-Authenticate: Basic realm="Registry"`, ""),
			want: model.ImageCheck{Tag: "1.23.6", Error: "asking what docker.io/gitea/gitea:1.23.6 points at: not found, or not public (HTTP 401)"}},
		{name: "a token service that is not https", image: "docker.io/gitea/gitea:1.23.6",
			on: "HEAD registry-1.docker.io/", do: answer(http.StatusUnauthorized, `Www-Authenticate: Bearer realm="http://auth.docker.io/token",service="registry.docker.io"`, ""),
			want: model.ImageCheck{Tag: "1.23.6", Error: "asking what docker.io/gitea/gitea:1.23.6 points at: registry-1.docker.io names a token service that is not an https address"}},
		{name: "a token service that is down", image: "docker.io/gitea/gitea:1.23.6",
			on: "GET auth.docker.io/token", do: answer(http.StatusServiceUnavailable, "", "try later"),
			want: model.ImageCheck{Tag: "1.23.6", Error: "asking what docker.io/gitea/gitea:1.23.6 points at: getting a token from auth.docker.io: unexpected answer (HTTP 503)"}},
		{name: "a token answer that is cut off", image: "docker.io/gitea/gitea:1.23.6",
			on: "GET auth.docker.io/token", do: answer(http.StatusOK, "", `{"token":"`+secretMark+`-half`),
			want: model.ImageCheck{Tag: "1.23.6", Error: "asking what docker.io/gitea/gitea:1.23.6 points at: getting a token from auth.docker.io: the answer is not JSON"}},
		{name: "a token answer without a token", image: "docker.io/gitea/gitea:1.23.6",
			on: "GET auth.docker.io/token", do: answer(http.StatusOK, "", `{"expires_in":300}`),
			want: model.ImageCheck{Tag: "1.23.6", Error: "asking what docker.io/gitea/gitea:1.23.6 points at: getting a token from auth.docker.io: the answer has no usable token"}},
		{name: "a token that could not go into a header", image: "docker.io/gitea/gitea:1.23.6",
			on: "GET auth.docker.io/token", do: answer(http.StatusOK, "", `{"token":"`+secretMark+`\r\nX-Injected: 1"}`),
			want: model.ImageCheck{Tag: "1.23.6", Error: "asking what docker.io/gitea/gitea:1.23.6 points at: getting a token from auth.docker.io: the answer has no usable token"}},
		// The error code a registry gives for a repository it does not have, as the OCI
		// distribution specification lists it (spec.md, error codes); not captured: the four
		// registries here hide such a repository behind 401.
		{name: "a registry that says the repository is unknown", image: "docker.io/gitea/gitea:1.23.6",
			on: tagsOfGitea, do: answer(http.StatusNotFound, "Content-Type: application/json", `{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}`),
			want: model.ImageCheck{Tag: "1.23.6", TagDigest: homelab[0].digest, Error: "listing the tags of docker.io/gitea/gitea: not found (HTTP 404 NAME_UNKNOWN)"}},
		// The next page somewhere else: the token must not follow it there.
		{name: "a next page on another host", image: "docker.io/henrygd/beszel:0.20.0",
			on: "GET registry-1.docker.io/v2/henrygd/beszel/tags/list", do: answer(http.StatusOK, `Link: <https://elsewhere.example/v2/henrygd/beszel/tags/list?n=2&last=0.21.0>; rel="next"`, `{"name":"henrygd/beszel","tags":["0.20.0","0.21.0"]}`),
			want: model.ImageCheck{Tag: "0.20.0", NewerMinor: "0.21.0", Note: "registry-1.docker.io did not say properly where its tag list goes on, newer tags may be missing"}},
		{name: "a next page that is the same page", image: "docker.io/henrygd/beszel:0.20.0",
			on: "GET registry-1.docker.io/v2/henrygd/beszel/tags/list", do: answer(http.StatusOK, `Link: </v2/henrygd/beszel/tags/list?n=1000>; rel="next"`, `{"name":"henrygd/beszel","tags":["0.20.0","0.21.0"]}`),
			want: model.ImageCheck{Tag: "0.20.0", NewerMinor: "0.21.0", Note: "registry-1.docker.io did not say properly where its tag list goes on, newer tags may be missing"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newHomelabRegistry(t)
			if tc.on != "" {
				f.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
					if !strings.HasPrefix(r.Method+" "+r.Host+r.URL.RequestURI(), tc.on) {
						return false
					}
					tc.do(w, r)
					return true
				})
			}
			f.mu.Lock()
			f.repos["registry-1.docker.io/henrygd/beszel"].digests["0.20.0"] = someDigest
			f.mu.Unlock()

			got := f.client(tc.opts).Check(context.Background(), tc.image)
			want := tc.want
			want.Image, want.CheckedAt = tc.image, f.clock.Now()
			if tc.name == "a next page on another host" || tc.name == "a next page that is the same page" {
				want.TagDigest = someDigest
			}
			if got != want {
				t.Errorf("Check(%q)\n got %+v\nwant %+v", tc.image, got, want)
			}
			if strings.Contains(got.Error, secretMark) {
				t.Errorf("Check(%q): a token is in the error: %q", tc.image, got.Error)
			}
			for _, line := range f.requests() {
				if strings.Contains(line, "elsewhere.example") {
					t.Errorf("Check(%q) followed the registry to another host: %q", tc.image, line)
				}
			}
		})
	}
}

// A registry that is not there at all: the error names what was asked and holds no secret.
func TestCheckRegistryDown(t *testing.T) {
	f := newHomelabRegistry(t)
	c := f.client(Options{Timeout: 2 * time.Second})
	f.server.Close()
	got := c.Check(context.Background(), "docker.io/gitea/gitea:1.23.6")
	if !strings.HasPrefix(got.Error, "asking what docker.io/gitea/gitea:1.23.6 points at: ") || got.TagDigest != "" || got.NewerPatch != "" {
		t.Errorf("Check with the registry down = %+v", got)
	}
	if strings.Contains(got.Error, "https://") || strings.Contains(got.Error, "/v2/") {
		t.Errorf("the error repeats the URL: %q", got.Error)
	}
}

// The caller's context ends the check.
func TestCheckCancelled(t *testing.T) {
	f := newHomelabRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := f.client(Options{}).Check(ctx, "docker.io/gitea/gitea:1.23.6")
	if want := "asking what docker.io/gitea/gitea:1.23.6 points at: cancelled"; got.Error != want {
		t.Errorf("Check with a cancelled context: Error = %q, want %q", got.Error, want)
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("Check with a cancelled context made %d requests", n)
	}
}

// A registry that hands out its tags one by one is not followed for ever.
func TestPageLimit(t *testing.T) {
	f := newHomelabRegistry(t)
	c := f.client(Options{})
	c.pageSize = 1
	got := c.Check(context.Background(), "docker.io/gitea/gitea:1.23.6")
	want := "only the first 100 pages of the tags of docker.io/gitea/gitea were read, newer ones may be missing"
	if got.Note != want || got.Error != "" || got.TagDigest == "" {
		t.Errorf("Check = %+v, want the note %q and no error", got, want)
	}
	if n := f.count("GET registry-1.docker.io/v2/gitea/gitea/tags/list"); n != maxPages {
		t.Errorf("%d pages were asked for, want %d", n, maxPages)
	}
}

// The token cache does not grow with every repository ever checked.
func TestTokenCacheIsBounded(t *testing.T) {
	f := newHomelabRegistry(t)
	c := f.client(Options{})
	now := f.clock.Now()
	fill := func(expires time.Time) {
		c.mu.Lock()
		defer c.mu.Unlock()
		clear(c.tokens)
		for i := 0; i < maxTokens; i++ {
			c.tokens[fmt.Sprintf("registry.example/repo%d", i)] = token{value: "x", expires: expires}
		}
	}
	size := func() int {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.tokens)
	}
	const image = "docker.io/gitea/gitea:1.23.6"

	fill(now.Add(-time.Second))
	if got := c.Check(context.Background(), image); got.Error != "" {
		t.Fatalf("Check = %+v", got)
	}
	if n := size(); n != 1 {
		t.Errorf("with %d expired tokens cached, %d are left after a check, want 1", maxTokens, n)
	}
	fill(now.Add(time.Hour))
	f.clock.Advance(10 * time.Minute) // gitea's own token is gone by now
	if got := c.Check(context.Background(), image); got.Error != "" {
		t.Fatalf("Check = %+v", got)
	}
	if n := size(); n != 1 {
		t.Errorf("with %d live tokens cached, %d are left after a check, want 1", maxTokens, n)
	}
}

// Without an HTTP client of the caller's, redirects only go to https.
func TestHTTPSOnly(t *testing.T) {
	c := New(Options{})
	if c.http.CheckRedirect == nil || c.now == nil || c.timeout != defaultTimeout || c.maxTags != defaultMaxTags {
		t.Fatalf("New(Options{}) left a default unset: %+v", c)
	}
	request := func(rawurl string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, rawurl, nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	tests := []struct {
		name   string
		target string
		hops   int
		ok     bool
	}{
		{"https, as Docker Hub redirects blobs to its storage", "https://production.cloudflare.docker.com/x", 1, true},
		{"plain http", "http://registry-1.docker.io/v2/", 1, false},
		{"something else", "ftp://registry-1.docker.io/v2/", 1, false},
		{"the fifth redirect", "https://registry-1.docker.io/v2/", 5, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := c.http.CheckRedirect(request(tc.target), make([]*http.Request, tc.hops))
			if (err == nil) != tc.ok {
				t.Errorf("redirect to %s after %d requests: error %v, want ok %v", tc.target, tc.hops, err, tc.ok)
			}
		})
	}
}

// Some registries refuse a page size above their own limit instead of lowering it. None of
// the four named in this package does, so the refusal here is Docker Hub's real answer to a
// page size it cannot read (n=abc), given for n=1000.
func TestPageSizeRefused(t *testing.T) {
	f := newHomelabRegistry(t)
	f.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/tags/list") || r.URL.Query().Get("n") != "1000" {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, hubBadPageSize)
		return true
	})
	got := f.client(Options{}).Check(context.Background(), "docker.io/gitea/gitea:1.23.6")
	if got.Error != "" || got.NewerPatch != "1.23.8" || got.NewerMinor != "1.27.3" || got.NewerMajor != "28.4.0" {
		t.Errorf("Check = %+v", got)
	}
	if n := f.count("GET registry-1.docker.io/v2/gitea/gitea/tags/list?n=100 200"); n != 1 {
		t.Errorf("want one first page of 100 after the refusal, got %d:\n%s", n, strings.Join(f.requests(), "\n"))
	}
}

// Many checks at once on one Client; "go test -race" watches the caches.
func TestCheckConcurrently(t *testing.T) {
	f := newHomelabRegistry(t)
	c := f.client(Options{})
	var wg sync.WaitGroup
	for round := 0; round < 4; round++ {
		for _, img := range homelab {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got := c.Check(context.Background(), img.image)
				if got.Error != "" || got.NewerPatch != img.want.NewerPatch || got.NewerMinor != img.want.NewerMinor || got.NewerMajor != img.want.NewerMajor {
					t.Errorf("Check(%q) = %+v", img.image, got)
				}
			}()
		}
	}
	wg.Wait()
	// Ten repositories behind a token, eleven images in them: however the checks interleave,
	// no check fetches more than one token.
	if tokens := f.count("GET auth.docker.io/token") + f.count("GET ghcr.io/token"); tokens < 10 || tokens > 4*11 {
		t.Errorf("%d tokens were fetched by %d checks of 10 repositories", tokens, 4*11)
	}
}

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    challenge
		ok      bool
	}{
		// The first four are what the registries sent on 2026-11-18.
		{"Docker Hub", []string{`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:gitea/gitea:pull"`},
			challenge{"https://auth.docker.io/token", "registry.docker.io"}, true},
		{"Docker Hub, a token for a repository that is not there", []string{`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/this-does-not-exist-xyz123:pull",error="insufficient_scope"`},
			challenge{"https://auth.docker.io/token", "registry.docker.io"}, true},
		{"ghcr.io and lscr.io", []string{`Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:linuxserver/unifi-network-application:pull"`},
			challenge{"https://ghcr.io/token", "ghcr.io"}, true},
		{"quay.io", []string{`Bearer realm="https://quay.io/v2/auth",service="quay.io",scope="repository:prometheus/no-such-repo-xyz123:pull"`},
			challenge{"https://quay.io/v2/auth", "quay.io"}, true},
		{"spaces after the commas, lowercase scheme", []string{`bearer realm="https://r.example/token", service="r.example"`},
			challenge{"https://r.example/token", "r.example"}, true},
		{"no service", []string{`Bearer realm="https://r.example/token"`}, challenge{"https://r.example/token", ""}, true},
		{"Basic first, Bearer second", []string{`Basic realm="Registry"`, `Bearer realm="https://r.example/token",service="s"`},
			challenge{"https://r.example/token", "s"}, true},
		{"only Basic", []string{`Basic realm="Registry"`}, challenge{}, false},
		{"Bearer without a realm", []string{`Bearer service="s"`}, challenge{}, false},
		{"nothing", nil, challenge{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseChallenge(tc.headers)
			if got != tc.want || ok != tc.ok {
				t.Errorf("parseChallenge(%q) = %+v, %v; want %+v, %v", tc.headers, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNextLink(t *testing.T) {
	page := "https://registry-1.docker.io/v2/gitea/gitea/tags/list?n=5"
	tests := []struct {
		name    string
		headers []string
		want    string // empty: no next page
	}{
		// The first three are what the registries sent on 2026-11-18.
		{"Docker Hub", []string{`</v2/gitea/gitea/tags/list?last=1-linux-arm64-rootless&n=5>; rel="next"`},
			"https://registry-1.docker.io/v2/gitea/gitea/tags/list?last=1-linux-arm64-rootless&n=5"},
		{"ghcr.io", []string{`</v2/stryan/materia/tags/list?last=v0.2.1&n=5>; rel="next"`},
			"https://registry-1.docker.io/v2/stryan/materia/tags/list?last=v0.2.1&n=5"},
		{"quay.io", []string{`</v2/prometheus/node-exporter/tags/list?n=5&last=master>; rel="next"`},
			"https://registry-1.docker.io/v2/prometheus/node-exporter/tags/list?n=5&last=master"},
		{"no header: the last page", nil, ""},
		{"rel without quotes", []string{`</v2/a/tags/list?last=x>; rel=next`}, "https://registry-1.docker.io/v2/a/tags/list?last=x"},
		{"other links first", []string{`</v2/a/tags/list>; rel="first", </v2/a/tags/list?last=x>; rel="next"`}, "https://registry-1.docker.io/v2/a/tags/list?last=x"},
		{"two headers", []string{`</first>; rel="first"`, `</next>; rel="next"`}, "https://registry-1.docker.io/next"},
		{"several relations in one", []string{`</next>; rel="last next"; title="more"`}, "https://registry-1.docker.io/next"},
		{"an absolute address is taken as it is, the caller checks the host", []string{`<https://elsewhere.example/x>; rel="next"`}, "https://elsewhere.example/x"},
		{"only a previous page", []string{`</prev>; rel="prev"`}, ""},
		{"broken", []string{`</v2/a/tags/list?last=x; rel="next"`}, ""},
		{"empty", []string{``}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, page, nil)
			if err != nil {
				t.Fatal(err)
			}
			h := http.Header{}
			for _, v := range tc.headers {
				h.Add("Link", v)
			}
			got := ""
			if u := nextLink(h, req.URL); u != nil {
				got = u.String()
			}
			if got != tc.want {
				t.Errorf("nextLink(%q) = %q, want %q", tc.headers, got, tc.want)
			}
		})
	}
}
