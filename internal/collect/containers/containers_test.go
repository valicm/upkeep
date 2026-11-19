package containers

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/valicm/upkeep/internal/report"
)

// The answers under testdata were captured from running software; testdata/SOURCES.txt says
// from what and how. fakeRuntime serves them over a unix socket the way the runtime did.
type fakeRuntime struct {
	dir     string
	replace map[string]reply // request path (with query) to a canned answer instead of the capture

	mu       sync.Mutex
	requests []string
}

type reply struct {
	status int
	body   string
}

var (
	containerPath   = regexp.MustCompile(`^/containers/([0-9a-f]+)/json$`)
	imagePath       = regexp.MustCompile(`^/images/(?:sha256:)?([0-9a-f]+)/json$`)
	libpodImagePath = regexp.MustCompile(`^/v[0-9.]+/libpod/images/(?:sha256:)?([0-9a-f]+)/json$`)
)

func (f *fakeRuntime) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.URL.RequestURI())
	f.mu.Unlock()

	if canned, ok := f.replace[r.URL.RequestURI()]; ok {
		w.WriteHeader(canned.status)
		_, _ = w.Write([]byte(canned.body))
		return
	}
	file, missing := "", ""
	switch path := r.URL.Path; {
	case path == "/_ping":
		f.ping(w)
		return
	case path == "/containers/json":
		file = "containers.json"
	case containerPath.MatchString(path):
		file, missing = "container-"+id12(containerPath, path)+".json", "missing-container.json"
	case imagePath.MatchString(path):
		file, missing = "image-"+id12(imagePath, path)+".json", "missing-image.json"
	case libpodImagePath.MatchString(path):
		file, missing = "libpod-image-"+id12(libpodImagePath, path)+".json", "missing-image.json"
	default:
		http.NotFound(w, r)
		return
	}
	body, err := os.ReadFile(filepath.Join(f.dir, file))
	if err != nil {
		body, _ = os.ReadFile(filepath.Join(f.dir, missing))
		w.WriteHeader(http.StatusNotFound)
	}
	_, _ = w.Write(body)
}

func id12(re *regexp.Regexp, path string) string {
	id := re.FindStringSubmatch(path)[1]
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}

// ping replays the captured headers of GET /_ping: they are how the runtimes differ.
func (f *fakeRuntime) ping(w http.ResponseWriter) {
	file, err := os.Open(filepath.Join(f.dir, "ping.txt"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer file.Close()
	lines := bufio.NewScanner(file)
	lines.Scan() // the status line
	for lines.Scan() && lines.Text() != "" {
		key, value, _ := strings.Cut(lines.Text(), ": ")
		if key != "Content-Length" && key != "Date" {
			w.Header().Set(key, value)
		}
	}
	_, _ = w.Write([]byte("OK"))
}

func (f *fakeRuntime) asked(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r == path {
			n++
		}
	}
	return n
}

// socketDir is a directory for unix sockets. Not t.TempDir(): with the test's name in it the
// path can pass the 108 bytes a socket's address may have.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "upkeep")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// listen serves h on a unix socket and returns the socket's path.
func listen(t *testing.T, h http.Handler) string {
	t.Helper()
	socket := filepath.Join(socketDir(t), "api.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return socket
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

// check compares what a run said went wrong with what a case expects: an error returned, which
// is for a run that found nothing, or a problem left in the report beside what was found.
func check(t *testing.T, r *report.Report, err error, wantErr, wantProblem string) {
	t.Helper()
	switch {
	case wantErr == "" && err != nil:
		t.Fatalf("Collect: %v", err)
	case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
		t.Fatalf("Collect: error %v\nwant one containing %q", err, wantErr)
	}
	var problems []string
	for _, p := range r.Errors {
		if p.Collector != "containers" {
			t.Errorf("a problem under the name %q: %s", p.Collector, p.Message)
		}
		problems = append(problems, p.Message)
	}
	switch all := strings.Join(problems, "\n"); {
	case wantProblem == "" && all != "":
		t.Errorf("problems in the report: %s", all)
	case wantProblem != "" && !strings.Contains(all, wantProblem):
		t.Errorf("problems in the report: %q\nwant one containing %q", all, wantProblem)
	}
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// edit rewrites one captured JSON file for a case the capture does not have, and returns the
// result as the answer to serve instead.
func edit[T any](t *testing.T, file string, change func(*T)) reply {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	change(&v)
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return reply{status: http.StatusOK, body: string(out)}
}

const (
	alpineID    = "sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731"
	alpineIndex = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc" // what docker.io had for alpine:3.20; the amd64 variant inside it is sha256:c64c...
	alpineAMD64 = "sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e" // the amd64 variant
	localID     = "sha256:d6d0644ff02b3ba3354bc34c03ebbd10700f65225c55516b234da429dcf51908"
	localDigest = "sha256:9b98a2631cb61ec41bca6d77dfddfe061152fe02111ac43b12414fe5bfc63ccc"

	redisID  = "sha256:c35b83ce044bb6d148c484d36e059ad28e02d5714ba6731fb55b6421e2ed0ccf"
	logsID   = "sha256:47b820890d64c4575a2a0a46415dcd8a4fd59a0f1fcd6a377693d7aea639442e"
	dynamoID = "sha256:f57a1e8cff92471f76fe826045418e28769ab486cefcbecdbc0cae7bbe8e0a02"
	engineID = "sha256:f340aee1ab70b508ce94b9672ea7c25f4db1ff31334d6080f0efefae8d5aae63"
	shopDBID = "sha256:284e08721b32840fd0d20cbd6e4339ac323ab8fb84739269eb5cd86eedf2ca85"

	// Containers of the captures that the cases below change.
	autoupdate = "5bcf4354fc97be6625e52f52d79c5f415a21dd995f890d0c39b3f5d11eee23ce"
	inpod      = "0312cf1f511a47769e97ef8e8c1ab5359fa99f104a1490279bd1708aec22f434"
	redis      = "d1b9724378f9a070b9c4044a51b82b94ca63cfd6a6e082c3c904bfcecdea18be"
)

// alpineBoth is how Podman lists the two digests of the alpine image: in the order of their text.
var alpineBoth = []string{alpineAMD64, alpineIndex}

// podmanWant is what the Podman capture holds: seven containers, of which one is a pod's
// infra container, one has exited and one was never started.
func podmanWant() []report.Container {
	return []report.Container{
		{Name: "upkeep-fx-autoupdate", Image: "docker.io/library/alpine:3.20", ImageID: alpineID, Digest: alpineIndex, Digests: alpineBoth,
			State: "running", StartedAt: at("2026-11-18T23:42:10.181522305Z"), AutoUpdate: "registry", Runtime: "podman"},
		{Name: "upkeep-fx-digest", Image: "docker.io/library/alpine@" + alpineIndex, ImageID: alpineID, Digest: alpineIndex, Digests: alpineBoth,
			State: "running", StartedAt: at("2026-11-18T23:42:10.294613304Z"), Runtime: "podman"},
		{Name: "upkeep-fx-inpod", Image: "docker.io/library/alpine:3.20", ImageID: alpineID, Digest: alpineIndex, Digests: alpineBoth,
			State: "running", StartedAt: at("2026-11-18T23:42:10.616732799Z"), Runtime: "podman"},
		{Name: "upkeep-fx-local", Image: "localhost/upkeep-fixture:current", ImageID: localID, Digest: localDigest,
			State: "running", StartedAt: at("2026-11-18T23:42:10.406046946Z"), Runtime: "podman"},
	}
}

// dockerWant is what the Docker capture holds: seven containers, one exited, one never started.
// shop-db runs an image whose tag has since moved to a rebuilt image: Docker lists the old
// image's ID in place of the name and no longer has the image itself.
func dockerWant() []report.Container {
	return []report.Container{
		{Name: "app-engine", Image: "docker.io/library/app-engine-cpu:local", ImageID: engineID, Digest: engineID,
			State: "running", StartedAt: at("2026-11-12T23:25:39.9420458Z"), Runtime: "docker"},
		{Name: "logs-victorialogs", Image: "docker.io/victoriametrics/victoria-logs:v1.52.0", ImageID: logsID, Digest: logsID,
			State: "running", StartedAt: at("2026-11-15T09:41:56.337857796Z"), Runtime: "docker"},
		{Name: "shop-db", Image: "docker.io/ddev/ddev-dbserver-mariadb-11.4:v1.25.5-shop-built", ImageID: shopDBID,
			State: "running", StartedAt: at("2026-11-12T23:23:05.768374196Z"), Runtime: "docker"},
		{Name: "shop-dynamodb", Image: "docker.io/amazon/dynamodb-local:latest", ImageID: dynamoID, Digest: dynamoID,
			State: "running", StartedAt: at("2026-11-13T09:05:38.630576364Z"), Runtime: "docker"},
		{Name: "shop-redis", Image: "docker.io/library/redis:6", ImageID: redisID, Digest: redisID,
			State: "running", StartedAt: at("2026-11-13T09:05:38.898162746Z"), Runtime: "docker"},
	}
}

func TestCollect(t *testing.T) {
	type entry = map[string]any
	// change returns want with one container altered, or left out when alter says so.
	change := func(want []report.Container, name string, alter func(*report.Container) bool) []report.Container {
		var out []report.Container
		for _, c := range want {
			if c.Name != name || alter(&c) {
				out = append(out, c)
			}
		}
		return out
	}

	cases := []struct {
		name        string
		dir         string
		replace     func(t *testing.T) map[string]reply
		want        []report.Container
		wantErr     string // part of the error returned; empty means none
		wantProblem string // part of a problem left in the report
	}{
		{name: "podman as captured", dir: "testdata/podman", want: podmanWant()},
		{name: "docker as captured", dir: "testdata/docker", want: dockerWant()},
		{
			// Podman 5.4.2: its pods' infra containers have an image, localhost/podman-pause.
			name: "debian 13's podman as captured", dir: "testdata/podman-debian13",
			want: []report.Container{
				{Name: "fx-autoupdate", Image: "docker.io/library/alpine:3.20", ImageID: alpineID, Digest: alpineIndex, Digests: alpineBoth,
					State: "running", StartedAt: at("2026-11-19T00:17:46.130451398Z"), AutoUpdate: "registry", Runtime: "podman"},
				{Name: "fx-inpod", Image: "docker.io/library/alpine:3.20", ImageID: alpineID, Digest: alpineIndex, Digests: alpineBoth,
					State: "running", StartedAt: at("2026-11-19T00:17:46.386693154Z"), Runtime: "podman"},
			},
		},
		{
			// Without Podman's own record of the image, its two digests cannot be told apart,
			// and no digest is better than a coin toss.
			name: "podman whose own image API fails",
			dir:  "testdata/podman",
			replace: func(*testing.T) map[string]reply {
				return map[string]reply{
					"/v5.8.9/libpod/images/" + alpineID + "/json": {status: http.StatusInternalServerError, body: `{"message":"boom"}`},
				}
			},
			want: func() []report.Container {
				w := change(podmanWant(), "upkeep-fx-autoupdate", func(c *report.Container) bool { c.Digest = ""; return true })
				return change(w, "upkeep-fx-inpod", func(c *report.Container) bool { c.Digest = ""; return true })
			}(),
		},
		{
			// Docker's state between two attempts of a restart policy.
			name: "docker container that is restarting",
			dir:  "testdata/docker",
			replace: func(t *testing.T) map[string]reply {
				return map[string]reply{
					"/containers/json?all=true": edit(t, "testdata/docker/containers.json", func(l *[]entry) {
						for _, e := range *l {
							if e["Id"] == redis {
								e["State"] = "restarting"
							}
						}
					}),
					"/containers/" + redis + "/json": edit(t, "testdata/docker/container-d1b9724378f9.json", func(c *entry) {
						(*c)["State"].(entry)["Status"] = "restarting"
					}),
				}
			},
			want: change(dockerWant(), "shop-redis", func(c *report.Container) bool { c.State = "restarting"; return true }),
		},
		{
			name: "container removed between the list and the look at it",
			dir:  "testdata/podman",
			replace: func(t *testing.T) map[string]reply {
				gone, err := os.ReadFile("testdata/podman/missing-container.json")
				if err != nil {
					t.Fatal(err)
				}
				return map[string]reply{"/containers/" + autoupdate + "/json": {status: http.StatusNotFound, body: string(gone)}}
			},
			want: change(podmanWant(), "upkeep-fx-autoupdate", func(*report.Container) bool { return false }),
		},
		{
			name: "container stopped between the list and the look at it",
			dir:  "testdata/podman",
			replace: func(t *testing.T) map[string]reply {
				return map[string]reply{
					"/containers/" + autoupdate + "/json": edit(t, "testdata/podman/container-5bcf4354fc97.json", func(c *entry) {
						(*c)["State"].(entry)["Status"] = "exited"
					}),
				}
			},
			want: change(podmanWant(), "upkeep-fx-autoupdate", func(*report.Container) bool { return false }),
		},
		{
			// The list alone still names the container and its image; only the start time is lost.
			name: "container that cannot be inspected",
			dir:  "testdata/podman",
			replace: func(*testing.T) map[string]reply {
				return map[string]reply{"/containers/" + autoupdate + "/json": {status: http.StatusInternalServerError, body: `{"message":"container state improper"}`}}
			},
			want:        change(podmanWant(), "upkeep-fx-autoupdate", func(c *report.Container) bool { c.StartedAt = time.Time{}; return true }),
			wantProblem: "inspecting container 5bcf4354fc97 on ",
		},
		{
			name: "list refused",
			dir:  "testdata/podman",
			replace: func(t *testing.T) map[string]reply {
				refused, err := os.ReadFile("testdata/podman/status-filter-refused.json")
				if err != nil {
					t.Fatal(err)
				}
				return map[string]reply{"/containers/json?all=true": {status: http.StatusInternalServerError, body: string(refused)}}
			},
			wantErr: "the runtime answered 500: unknown container state: restarting: invalid argument",
		},
		{
			// Docker lists an ID, not the name, for a container whose image lost its tag. Only
			// the container's own record then tells that it runs a pause image.
			name: "pause containers known by their own record only",
			dir:  "testdata/podman",
			replace: func(t *testing.T) map[string]reply {
				infra := func(file, image string) reply {
					return edit(t, file, func(c *entry) { (*c)["Config"].(entry)["Image"] = image })
				}
				return map[string]reply{
					"/containers/" + autoupdate + "/json": infra("testdata/podman/container-5bcf4354fc97.json", "localhost/podman-pause:5.4.2-1747958400"),
					"/containers/" + inpod + "/json":      infra("testdata/podman/container-0312cf1f511a.json", "registry.k8s.io/pause:3.9"),
				}
			},
			want: func() []report.Container {
				w := change(podmanWant(), "upkeep-fx-autoupdate", func(*report.Container) bool { return false })
				return change(w, "upkeep-fx-inpod", func(*report.Container) bool { return false })
			}(),
		},
		{
			// "docker run c35b83ce044b": the container names no image, so the image's tag does.
			name: "container started from an image ID",
			dir:  "testdata/docker",
			replace: func(t *testing.T) map[string]reply {
				return map[string]reply{
					"/containers/" + redis + "/json": edit(t, "testdata/docker/container-d1b9724378f9.json", func(c *entry) {
						(*c)["Config"].(entry)["Image"] = "c35b83ce044b"
					}),
				}
			},
			want: dockerWant(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRuntime{dir: tc.dir}
			if tc.replace != nil {
				fake.replace = tc.replace(t)
			}
			socket := listen(t, fake)

			var r report.Report
			err := New(Config{Sockets: []string{socket}}).Collect(context.Background(), &r)
			check(t, &r, err, tc.wantErr, tc.wantProblem)
			if got, want := asJSON(t, r.Containers), asJSON(t, tc.want); got != want {
				t.Errorf("containers:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

// No more is asked than needed: an image is looked up once however many containers run it,
// Podman is asked through its own API, which knows the digest the image was pulled as, and
// containers that do not run, or only hold a pod together, are not looked at.
func TestCollectAsksNoMoreThanNeeded(t *testing.T) {
	cases := []struct {
		dir   string
		calls int      // ping, list, one per container reported, one per image they run
		never []string // IDs that must not appear in any call
	}{
		{"testdata/podman", 1 + 1 + 4 + 2, []string{
			"f7d17416db6d", // exited
			"69c4ccbd7799", // created, never started
			"af0cf99a10ce", // the pod's infra container, which has no image
		}},
		{"testdata/podman-debian13", 1 + 1 + 2 + 1, []string{
			"123bfbaf2b82", // the pod's infra container
			"5b6aa39c3b21", // and its image, localhost/podman-pause
		}},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			fake := &fakeRuntime{dir: tc.dir}
			socket := listen(t, fake)
			var r report.Report
			if err := New(Config{Sockets: []string{socket}}).Collect(context.Background(), &r); err != nil {
				t.Fatal(err)
			}
			if n := fake.asked("/images/" + alpineID + "/json"); n != 0 {
				t.Errorf("Docker's image call was made %d times on Podman, want 0", n)
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			images := 0
			for _, req := range fake.requests {
				if strings.Contains(req, "/libpod/images/"+alpineID+"/json") {
					images++
				}
				for _, id := range tc.never {
					if strings.Contains(req, id) {
						t.Errorf("asked %s, which nothing depends on", req)
					}
				}
			}
			if images != 1 {
				t.Errorf("alpine's image was asked for %d times, want 1 (several containers run it)", images)
			}
			if len(fake.requests) != tc.calls {
				t.Errorf("%d calls, want %d: %v", len(fake.requests), tc.calls, fake.requests)
			}
		})
	}
}

func TestCollectSockets(t *testing.T) {
	podman := listen(t, &fakeRuntime{dir: "testdata/podman"})
	docker := listen(t, &fakeRuntime{dir: "testdata/docker"})
	dir := socketDir(t)
	missing := filepath.Join(dir, "missing.sock")

	link := filepath.Join(dir, "docker.sock") // what the podman-docker package does
	if err := os.Symlink(podman, link); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain-file")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A socket nobody listens on any more: the file stays when a socket unit is stopped.
	stale := filepath.Join(dir, "stale.sock")
	l, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()

	off := false
	cases := []struct {
		name        string
		cfg         Config
		candidates  []string // what auto-detection would try
		installed   string   // the runtime whose command is on the machine
		want        int      // containers reported
		wantErr     string
		wantProblem string
	}{
		{name: "nothing configured, no runtime", candidates: []string{missing, plain}},
		// Podman's socket is off until podman.socket is enabled: its containers would go unseen.
		{name: "nothing configured, a runtime without its socket", candidates: []string{missing, plain}, installed: "podman",
			wantErr: "podman is installed but its API socket was not found (looked at " + missing + ", " + plain + ")"},
		{name: "a runtime that is installed and found is no problem", candidates: []string{missing, podman}, installed: "podman", want: 4},
		{name: "configured sockets say what is wrong themselves", cfg: Config{Sockets: []string{missing}}, installed: "podman",
			wantErr: "looking for the container runtime's socket: stat " + missing},
		{name: "switched off although a runtime is installed", cfg: Config{Enabled: &off}, candidates: []string{missing}, installed: "podman"},
		{name: "nothing configured, podman found", candidates: []string{missing, podman}, want: 4},
		{name: "podman and docker side by side", candidates: []string{podman, docker}, want: 9},
		{name: "one runtime behind two paths", candidates: []string{podman, link}, want: 4},
		{name: "found but nobody listens", candidates: []string{stale}, wantErr: "asking which container runtime listens on " + stale},
		{name: "one fails, the other is still reported", candidates: []string{stale, docker}, want: 5, wantProblem: "asking which container runtime listens on " + stale},
		{name: "two fail", cfg: Config{Sockets: []string{missing, stale}}, wantErr: "missing.sock: no such file or directory; asking which container runtime listens on " + stale},
		{name: "configured", cfg: Config{Sockets: []string{docker}}, candidates: []string{podman}, want: 5},
		{name: "configured but missing", cfg: Config{Sockets: []string{missing}}, wantErr: "looking for the container runtime's socket: stat " + missing},
		{name: "configured but not a socket", cfg: Config{Sockets: []string{plain}}, wantErr: plain + " is not a socket"},
		{name: "switched off", cfg: Config{Enabled: &off, Sockets: []string{podman}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.cfg).(*collector)
			c.candidates = func() []string { return tc.candidates }
			c.installed = func() string { return tc.installed }
			var r report.Report
			err := c.Collect(context.Background(), &r)
			check(t, &r, err, tc.wantErr, tc.wantProblem)
			if len(r.Containers) != tc.want {
				t.Errorf("%d containers, want %d: %s", len(r.Containers), tc.want, asJSON(t, r.Containers))
			}
			if tc.want == 0 && r.Containers != nil {
				t.Errorf("Containers is %v, want nil: an empty part means this source does not look", r.Containers)
			}
		})
	}
}

// A runtime that accepts the connection and then says nothing must not hold the agent up.
func TestCollectGivesUpOnASilentRuntime(t *testing.T) {
	release := make(chan struct{})
	socket := listen(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	var r report.Report
	err := New(Config{Sockets: []string{socket}}).Collect(ctx, &r)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("Collect: error %v, want a deadline", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("gave up after %s", took)
	}
}

// The configuration file as its owner writes it, read with the library the agent uses.
func TestConfigFromTOML(t *testing.T) {
	cases := []struct {
		name        string
		file        string
		wantEnabled bool
		wantSockets []string
	}{
		{"nothing said", "", true, nil},
		{"an empty table", "[containers]\n", true, nil},
		{"switched off", "[containers]\nenabled = false\n", false, nil},
		{"sockets named", "[containers]\nsockets = [\"/run/podman/podman.sock\", \"/srv/docker/docker.sock\"]\n", true,
			[]string{"/run/podman/podman.sock", "/srv/docker/docker.sock"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got struct {
				Containers Config `toml:"containers"`
			}
			if err := toml.Unmarshal([]byte(tc.file), &got); err != nil {
				t.Fatal(err)
			}
			c := New(got.Containers).(*collector)
			if c.enabled != tc.wantEnabled || strings.Join(c.sockets, " ") != strings.Join(tc.wantSockets, " ") {
				t.Errorf("enabled %v, sockets %v; want %v, %v", c.enabled, c.sockets, tc.wantEnabled, tc.wantSockets)
			}
		})
	}
}

func TestUsualSockets(t *testing.T) {
	cases := []struct {
		name       string
		runtimeDir string
		uid        int
		want       []string
	}{
		{
			name: "root in a system service", uid: 0,
			want: []string{"/run/podman/podman.sock", "/var/run/podman/podman.sock", "/run/user/0/podman/podman.sock", "/var/run/docker.sock", "/run/user/0/docker.sock"},
		},
		{
			name: "a user's session", runtimeDir: "/run/user/1000", uid: 1000,
			want: []string{"/run/podman/podman.sock", "/var/run/podman/podman.sock", "/run/user/1000/podman/podman.sock", "/var/run/docker.sock", "/run/user/1000/docker.sock"},
		},
		{
			name: "a user without a session", uid: 1001,
			want: []string{"/run/podman/podman.sock", "/var/run/podman/podman.sock", "/run/user/1001/podman/podman.sock", "/var/run/docker.sock", "/run/user/1001/docker.sock"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := usualSockets(tc.runtimeDir, tc.uid); strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("got  %v\nwant %v", got, tc.want)
			}
		})
	}
}

func TestPulledAs(t *testing.T) {
	const a, b, c = "sha256:aaaa", "sha256:bbbb", "sha256:cccc"
	cases := []struct {
		name    string
		image   string
		info    imageInfo
		want    string
		wantAll []string // every digest of the image in the container's repository, when that says more than want
	}{
		{name: "docker: one digest", image: "redis:6", info: imageInfo{RepoDigests: []string{"redis@" + a}}, want: a},
		{name: "podman: its record picks among two", image: "docker.io/library/alpine:3.20",
			info: imageInfo{RepoDigests: []string{"docker.io/library/alpine@" + a, "docker.io/library/alpine@" + b}, Digest: b},
			want: b, wantAll: []string{a, b}},
		{name: "two digests and nothing to pick with", image: "redis:6",
			info: imageInfo{RepoDigests: []string{"redis@" + a, "redis@" + b}}, wantAll: []string{a, b}},
		{name: "the record names a digest the repository does not list", image: "docker.io/library/alpine:3.20",
			info:    imageInfo{RepoDigests: []string{"docker.io/library/alpine@" + a, "docker.io/library/alpine@" + b}, Digest: c},
			wantAll: []string{a, b}},
		{name: "pulled again as part of a newer set: three digests, and no telling which set is current", image: "docker.io/library/alpine:3.20",
			info:    imageInfo{RepoDigests: []string{"docker.io/library/alpine@" + a, "docker.io/library/alpine@" + b, "docker.io/library/alpine@" + c}, Digest: b},
			wantAll: []string{a, b, c}},
		{name: "the same digest listed twice counts once", image: "redis:6",
			info: imageInfo{RepoDigests: []string{"redis@" + a, "docker.io/library/redis@" + a}}, want: a},
		{name: "image under two names", image: "ghcr.io/example/app:1",
			info: imageInfo{RepoDigests: []string{"docker.io/example/app@" + a, "ghcr.io/example/app@" + b}}, want: b},
		{name: "no digest for this repository", image: "ghcr.io/example/app:1", info: imageInfo{RepoDigests: []string{"docker.io/example/app@" + a}}},
		{name: "never pulled", image: "localhost/app:current"},
		{name: "the container names the digest", image: "ghcr.io/stryan/materia@" + c,
			info: imageInfo{RepoDigests: []string{"ghcr.io/stryan/materia@" + a}}, want: c, wantAll: []string{a}},
		{name: "the container names the digest and the image is gone", image: "ghcr.io/stryan/materia@" + c, want: c},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, all := pulledAs(parseReference(tc.image), tc.info)
			if got != tc.want || strings.Join(all, " ") != strings.Join(tc.wantAll, " ") {
				t.Errorf("got %q and %q, want %q and %q", got, all, tc.want, tc.wantAll)
			}
		})
	}
}

// With UPKEEP_TEST_SOCKET set this asks a real runtime and prints what it would report. It is
// how the collector was checked against Podman and Docker themselves.
func TestLiveSocket(t *testing.T) {
	socket := os.Getenv("UPKEEP_TEST_SOCKET")
	if socket == "" {
		t.Skip("UPKEEP_TEST_SOCKET is not set")
	}
	var r report.Report
	err := New(Config{Sockets: []string{socket}}).Collect(context.Background(), &r)
	t.Logf("%d containers, error: %v", len(r.Containers), err)
	if os.Getenv("UPKEEP_TEST_VERBOSE") != "" {
		t.Log(asJSON(t, r.Containers))
	}
	if err != nil {
		t.Fail()
	}
}
