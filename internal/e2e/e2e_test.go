//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	sharedToken = "e2e-shared-token-0123456789abcdef"
	debianToken = "e2e-debian-token-0123456789abcdef"
	opnKey      = "e2e/key+with/slashes"
	opnSecret   = "e2e-secret-that-must-not-leak"
	haToken     = "e2e-homeassistant-long-lived-token"
)

// secrets must not show up in any page, any answer of the API or any log line.
var secrets = []string{sharedToken, debianToken, opnKey, opnSecret, haToken}

// ---- the binary and processes ----

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// binary is the upkeep under test: UPKEEP_BIN, or a static build of this tree.
func binary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("UPKEEP_BIN"); bin != "" {
		return bin
	}
	out := filepath.Join(t.TempDir(), "upkeep")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-X github.com/valicm/upkeep/internal/version.Version=e2e", "-o", out, "./cmd/upkeep")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building upkeep: %v\n%s", err, b)
	}
	return out
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// syncBuffer is a log that a process writes and the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// server is one running "upkeep server".
type server struct {
	t    *testing.T
	cmd  *exec.Cmd
	addr string
	log  *syncBuffer
	done chan error
}

// startServer runs the binary and waits until it answers /healthz. env is added to a small
// environment of its own, so that nothing of the developer's shell (a proxy, say) decides
// where the server's requests go.
func startServer(t *testing.T, bin string, env []string, args ...string) *server {
	t.Helper()
	s := &server{t: t, log: &syncBuffer{}, done: make(chan error, 1)}
	for i, a := range args {
		if a == "-listen" {
			s.addr = args[i+1]
		}
	}
	s.cmd = exec.Command(bin, append([]string{"server"}, args...)...)
	s.cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir(), "TZ=UTC"}, env...)
	s.cmd.Stdout, s.cmd.Stderr = s.log, s.log
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { s.done <- s.cmd.Wait() }()
	t.Cleanup(func() {
		if s.cmd.ProcessState == nil {
			s.cmd.Process.Kill()
			<-s.done
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get("http://" + s.addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s
			}
		}
		select {
		case err := <-s.done:
			t.Fatalf("the server ended at once: %v\n%s", err, s.log)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server did not answer /healthz within 20 s\n%s", s.log)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// stop sends SIGTERM and wants a clean end.
func (s *server) stop() {
	s.t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		s.t.Fatal(err)
	}
	select {
	case err := <-s.done:
		if err != nil {
			s.t.Errorf("the server ended with %v after SIGTERM, want exit status 0\n%s", err, s.log)
		}
	case <-time.After(30 * time.Second):
		s.t.Errorf("the server did not stop within 30 s of SIGTERM\n%s", s.log)
	}
}

// answer is one fetched page.
type answer struct {
	status int
	header http.Header
	body   string
	took   time.Duration
}

func (s *server) do(method, path, token, body string) answer {
	s.t.Helper()
	req, err := http.NewRequest(method, "http://"+s.addr+path, strings.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	start := time.Now()
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v\n%s", method, path, err, s.log)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return answer{status: resp.StatusCode, header: resp.Header, body: string(b), took: time.Since(start)}
}

func (s *server) get(path string) answer { return s.do(http.MethodGet, path, "", "") }

// ---- pages ----

var (
	tagRE   = regexp.MustCompile(`(?s)<(script|style)[^>]*>.*?</(script|style)>|<[^>]*>`)
	spaceRE = regexp.MustCompile(`\s+`)
	entity  = strings.NewReplacer("&#34;", `"`, "&#39;", "'", "&amp;", "&", "&lt;", "<", "&gt;", ">", "&#43;", "+")
)

// text is what a page says, without its markup, on one line.
func text(html string) string {
	return strings.TrimSpace(spaceRE.ReplaceAllString(entity.Replace(tagRE.ReplaceAllString(html, " ")), " "))
}

// save keeps a fetched page for whoever wants to read it after the run.
func save(t *testing.T, name, body string) {
	dir := os.Getenv("UPKEEP_E2E_OUT")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fileName(path string) string {
	n := strings.Trim(strings.NewReplacer("/", "_", "?", "_").Replace(path), "_")
	if n == "" {
		n = "overview"
	}
	if !strings.Contains(n, ".") {
		n += ".html"
	}
	return n
}

// page fetches one dashboard page, wants 200 and every one of the texts in it, and returns
// what it says.
func (s *server) page(path string, wants ...string) string {
	s.t.Helper()
	a := s.get(path)
	save(s.t, fileName(path), a.body)
	if a.status != http.StatusOK {
		s.t.Errorf("GET %s = %d, want 200", path, a.status)
		return ""
	}
	said := text(a.body)
	for _, want := range wants {
		if !strings.Contains(said, want) {
			s.t.Errorf("GET %s does not say %q", path, want)
		}
	}
	for _, secret := range secrets {
		if strings.Contains(a.body, secret) {
			s.t.Errorf("GET %s shows a secret (%s...)", path, secret[:8])
		}
	}
	return said
}

// around is the part of a page after a word, for an error message.
func around(said, word string, n int) string {
	i := strings.Index(said, word)
	if i < 0 {
		return "(" + word + " is not on the page)"
	}
	return said[i:min(len(said), i+n)]
}

// ---- the state as the API gives it ----

type state struct {
	Version string `json:"version"`
	Systems []struct {
		Name       string    `json:"name"`
		ReceivedAt time.Time `json:"received_at"`
		Report     struct {
			System struct {
				Name, Kind, OS, Kernel, Arch, Source string
				OSVersion                            string `json:"os_version"`
				AgentVersion                         string `json:"agent_version"`
			} `json:"system"`
			Packages *struct {
				Manager      string    `json:"manager"`
				Pending      int       `json:"pending"`
				Security     int       `json:"security"`
				ListsUpdated time.Time `json:"lists_updated"`
				Items        []struct {
					Name, Installed, Candidate string
					Security                   bool
				} `json:"items"`
				RebootRequired bool `json:"reboot_required"`
			} `json:"packages"`
			Software []struct {
				Name, Kind, Installed, Latest string
				UpdateAvailable               bool `json:"update_available"`
			} `json:"software"`
			Containers []struct {
				Name, Image, Digest, State, Runtime string
				Digests                             []string
				AutoUpdate                          string `json:"auto_update"`
			} `json:"containers"`
			Backups []struct {
				Name, Kind  string
				LastSuccess time.Time `json:"last_success"`
				LastResult  string    `json:"last_result"`
				Detail      string
			} `json:"backups"`
			Errors []struct{ Collector, Message string } `json:"errors"`
		} `json:"report"`
	} `json:"systems"`
	ImageChecks []struct {
		Image      string `json:"image"`
		Tag        string `json:"tag"`
		TagDigest  string `json:"tag_digest"`
		NewerPatch string `json:"newer_patch"`
		NewerMinor string `json:"newer_minor"`
		NewerMajor string `json:"newer_major"`
		Error      string `json:"error"`
		Note       string `json:"note"`
	} `json:"image_checks"`
	Findings []struct{ System, Category, Severity, Title, Detail string } `json:"findings"`
}

func (s *server) state() state {
	s.t.Helper()
	a := s.do(http.MethodGet, "/api/v1/state", sharedToken, "")
	if a.status != http.StatusOK {
		s.t.Fatalf("GET /api/v1/state = %d: %s", a.status, a.body)
	}
	save(s.t, "state.json", a.body)
	var st state
	if err := json.Unmarshal([]byte(a.body), &st); err != nil {
		s.t.Fatalf("the state is not JSON: %v", err)
	}
	return st
}

func (st state) titles(system string) []string {
	var out []string
	for _, f := range st.Findings {
		if f.System == system {
			out = append(out, f.Severity+" "+f.Category+": "+f.Title)
		}
	}
	return out
}

func (st state) has(system, title string) bool {
	for _, f := range st.Findings {
		if f.System == system && strings.Contains(f.Title, title) {
			return true
		}
	}
	return false
}

// ---- the stand-ins ----

func fixture(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeOPNsense answers the firmware status with the connector's own test data, as if the
// firewall had checked two hours ago, and only to the right API key.
func fakeOPNsense(t *testing.T) (srv *httptest.Server, asked func() []string) {
	var mu sync.Mutex
	var paths []string
	var status map[string]any
	if err := json.Unmarshal(fixture(t, "internal/connect/opnsense/testdata/status-update.json"), &status); err != nil {
		t.Fatal(err)
	}
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if key, secret, ok := r.BasicAuth(); !ok || key != opnKey || secret != opnSecret {
			http.Error(w, `{"status":401,"message":"Authentication Failed"}`, http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/core/firmware/status" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		// date(1) in the firewall's zone, which here is UTC.
		status["last_check"] = time.Now().UTC().Add(-2 * time.Hour).Format("Mon Jan _2 15:04:05 UTC 2006")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

// fakeHomeAssistant answers the two calls with the connector's test data of a Home Assistant
// OS installation; the times of its backup are moved to this morning.
func fakeHomeAssistant(t *testing.T) *httptest.Server {
	var states []map[string]any
	if err := json.Unmarshal(fixture(t, "internal/connect/homeassistant/testdata/states-haos.json"), &states); err != nil {
		t.Fatal(err)
	}
	config := fixture(t, "internal/connect/homeassistant/testdata/config-haos.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+haToken {
			http.Error(w, "401: Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/config":
			w.Write(config)
		case "/api/states":
			now := time.Now().UTC()
			at := func(d time.Duration) string { return now.Add(d).Format("2006-01-02T15:04:05+00:00") }
			for _, e := range states {
				switch e["entity_id"] {
				case "sensor.backup_last_attempted_automatic_backup":
					e["state"] = at(-5*time.Hour - 7*time.Minute)
				case "sensor.backup_last_successful_automatic_backup", "event.backup_automatic_backup":
					e["state"] = at(-5 * time.Hour)
				case "sensor.backup_next_scheduled_automatic_backup":
					e["state"] = at(19 * time.Hour)
				}
			}
			json.NewEncoder(w).Encode(states)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// silentAppliance accepts connections and never answers: a firewall that hangs.
func silentAppliance(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return ln.Addr().String()
}

// repository is what the stand-in registry has for one repository.
type repository struct {
	tags    []string
	digests map[string]string // by tag; a tag without one is not there
}

// fakeRegistry is every registry at once, behind a proxy. It speaks the part of the protocol
// the server uses: a 401 that names a token service, the token, HEAD of a manifest, and the
// tag list.
type fakeRegistry struct {
	mu       sync.Mutex
	repos    map[string]*repository // "registry-1.docker.io/library/alpine"
	requests []string               // "HEAD registry-1.docker.io/v2/library/alpine/manifests/3.20 200"
	tunnels  []string               // hosts the proxy was asked to connect to

	caFile   string
	proxyURL string
}

func (f *fakeRegistry) log(r *http.Request, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, fmt.Sprintf("%s %s%s %d", r.Method, r.Host, r.URL.Path, status))
}

func (f *fakeRegistry) asked() (requests, tunnels []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...), append([]string(nil), f.tunnels...)
}

var registryPath = regexp.MustCompile(`^/v2/(.+)/(manifests|tags)/([^/]+)$`)

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	status := http.StatusOK
	defer func() { f.log(r, status) }()
	fail := func(code int, registryCode string) {
		status = code
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"errors":[{"code":%q,"message":"e2e"}]}`, registryCode)
	}
	if r.Host == "auth.e2e.example" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":"e2e-registry-token","expires_in":300}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer e2e-registry-token" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.e2e.example/token",service="e2e"`)
		fail(http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}
	m := registryPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		fail(http.StatusNotFound, "NOT_FOUND")
		return
	}
	f.mu.Lock()
	repo := f.repos[r.Host+"/"+m[1]]
	f.mu.Unlock()
	switch {
	case repo == nil:
		// As the real ones do for a repository that is not public, or not there.
		fail(http.StatusUnauthorized, "UNAUTHORIZED")
	case m[2] == "manifests":
		digest, ok := repo.digests[m[3]]
		if !ok {
			fail(http.StatusNotFound, "MANIFEST_UNKNOWN")
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
	case m[2] == "tags" && m[3] == "list":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"name": m[1], "tags": repo.tags})
	default:
		fail(http.StatusNotFound, "NOT_FOUND")
	}
}

// newFakeRegistry starts the stand-in with a certificate authority of its own, and the proxy
// in front of it that sends every https request there, whatever host it was meant for.
func newFakeRegistry(t *testing.T, repos map[string]*repository) *fakeRegistry {
	f := &fakeRegistry{repos: repos}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upkeep e2e CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	f.caFile = filepath.Join(t.TempDir(), "registry-ca.pem")
	if err := os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	// One certificate per host, made when the host is first asked for.
	var certMu sync.Mutex
	certs := map[string]*tls.Certificate{}
	certFor := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		certMu.Lock()
		defer certMu.Unlock()
		if c, ok := certs[hello.ServerName]; ok {
			return c, nil
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(len(certs) + 2)), Subject: pkix.Name{CommonName: hello.ServerName},
			DNSNames: []string{hello.ServerName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
		certs[hello.ServerName] = c
		return c, nil
	}
	registry := httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	registry.TLS = &tls.Config{GetCertificate: certFor}
	registry.StartTLS()
	t.Cleanup(registry.Close)
	target := registry.Listener.Addr().String()

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "only https goes through here", http.StatusBadGateway)
			return
		}
		f.mu.Lock()
		f.tunnels = append(f.tunnels, r.Host)
		f.mu.Unlock()
		up, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		down, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		io.WriteString(down, "HTTP/1.1 200 Connection established\r\n\r\n")
		go func() { io.Copy(up, down); up.Close() }()
		go func() { io.Copy(down, up); down.Close() }()
	}))
	t.Cleanup(proxy.Close)
	f.proxyURL = proxy.URL
	return f
}

// ---- Podman ----

func podman(args ...string) (string, error) {
	out, err := exec.Command("podman", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func havePodmanImage(image string) bool {
	if _, err := exec.LookPath("podman"); err != nil {
		return false
	}
	_, err := podman("image", "exists", image)
	return err == nil
}

// tagDigestFor picks, among the digests Podman knows a local image by, the one a registry
// would name for its tag: for an image that exists for several architectures that is the
// digest of the whole set, not the one "podman image inspect" calls the image's own.
func tagDigestFor(t *testing.T, image string) string {
	t.Helper()
	out, err := podman("image", "inspect", "--format", "{{.Digest}} {{range .RepoDigests}}{{.}} {{end}}", image)
	if err != nil {
		t.Fatalf("podman image inspect %s: %v: %s", image, err, out)
	}
	fields := strings.Fields(out)
	own, pick := fields[0], ""
	for _, rd := range fields[1:] {
		_, digest, _ := strings.Cut(rd, "@")
		if pick == "" || digest != own {
			pick = digest
		}
	}
	return pick
}

const (
	alpineRolling = "docker.io/library/alpine:3.20"
	alpineExact   = "docker.io/library/alpine:3.20.0"
	rebuiltDigest = "sha256:e2e0000000000000000000000000000000000000000000000000000000000e2e"
)

// startPodman runs two small containers and a Podman API service on a socket of the test's
// own, and returns the socket. The machine's own containers are not touched and not reported.
func startPodman(t *testing.T) (socket string) {
	t.Helper()
	for _, image := range []string{alpineRolling, alpineExact} {
		if !havePodmanImage(image) {
			t.Logf("no Podman, or no local image %s: the agent on this machine reports no containers", image)
			return ""
		}
	}
	names := []string{"upkeep-e2e-rolling", "upkeep-e2e-exact"}
	podman(append([]string{"rm", "-f"}, names...)...) // left behind by a run that was killed
	t.Cleanup(func() { podman(append([]string{"rm", "-f", "-t", "0"}, names...)...) })
	for i, image := range []string{alpineRolling, alpineExact} {
		args := []string{"run", "-d", "--pull=never", "--name", names[i]}
		if i == 0 {
			args = append(args, "--label", "io.containers.autoupdate=registry")
		}
		if out, err := podman(append(args, image, "sleep", "1800")...); err != nil {
			t.Fatalf("podman run %s: %v: %s", image, err, out)
		}
	}
	// A unix socket's path is short by law (108 bytes); t.TempDir's is too deep for it.
	dir, err := os.MkdirTemp("", "upkeep-e2e-")
	if err == nil && len(dir) > 80 {
		os.Remove(dir)
		dir, err = os.MkdirTemp("/tmp", "upkeep-e2e-")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket = filepath.Join(dir, "podman.sock")
	service := exec.Command("podman", "system", "service", "--time=0", "unix://"+socket)
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		service.Process.Signal(syscall.SIGTERM)
		service.Wait()
	})
	for deadline := time.Now().Add(15 * time.Second); ; {
		if c, err := net.Dial("unix", socket); err == nil {
			c.Close()
			return socket
		}
		if time.Now().After(deadline) {
			t.Fatal("podman system service did not open its socket within 15 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func write(t *testing.T, path, content string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// runAgent runs "upkeep agent" to its end and returns what it wrote and how it ended.
func runAgent(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append([]string{"agent"}, args...)...)
	// A small environment: nothing set for the developer's shell is to decide what is reported.
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + os.Getenv("HOME"), "XDG_RUNTIME_DIR=" + os.Getenv("XDG_RUNTIME_DIR")}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ---- the test ----

func TestEndToEnd(t *testing.T) {
	bin := binary(t)
	dir := t.TempDir()
	host, _ := os.Hostname()
	workstation := "workstation-e2e"

	// The appliances and the registries.
	opn, opnAsked := fakeOPNsense(t)
	ha := fakeHomeAssistant(t)
	dead := silentAppliance(t)
	socket := startPodman(t)
	repos := map[string]*repository{}
	if socket != "" {
		repos["registry-1.docker.io/library/alpine"] = &repository{
			tags: []string{"2.7", "3.19", "3.19.4", "3.20", "3.20.0", "3.20.1", "3.20.3", "3.21", "3.21.0", "3.22", "3.22.2", "3.23.0_rc1", "edge", "latest"},
			digests: map[string]string{
				alpineRollingTag: rebuiltDigest,                // the tag moved since the image was pulled
				alpineExactTag:   tagDigestFor(t, alpineExact), // still what was pulled
			},
		}
	}
	registry := newFakeRegistry(t, repos)

	// The server's configuration: every secret in a file of its own.
	opnCert := write(t, filepath.Join(dir, "opnsense-ca.pem"),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: opn.Certificate().Raw})), 0o644)
	listen := freePort(t)
	config := write(t, filepath.Join(dir, "server.toml"), fmt.Sprintf(`
listen = %q
data_dir = %q
token_file = %q
connector_interval = "1m"
registry_interval = "10m"

[tokens]
debian-e2e = %q

[[opnsense]]
name = "opnsense-e2e"
url = %q
key_file = %q
ca_file = %q
timezone = "UTC"

[[opnsense]]
name = "opnsense-silent"
url = %q
key_file = %q
tls_skip_verify = true
timeout = "3s"

[[homeassistant]]
name = "homeassistant-e2e"
url = %q
token_file = %q
`,
		listen, filepath.Join(dir, "data"),
		write(t, filepath.Join(dir, "token"), sharedToken+"\n", 0o600),
		write(t, filepath.Join(dir, "debian.token"), debianToken+"\n", 0o600),
		opn.URL, write(t, filepath.Join(dir, "apikey.txt"), "key="+opnKey+"\nsecret="+opnSecret+"\n", 0o600), opnCert,
		"https://"+dead, filepath.Join(dir, "apikey.txt"),
		ha.URL, write(t, filepath.Join(dir, "ha.token"), haToken+"\n", 0o600),
	), 0o644)

	started := time.Now()
	srv := startServer(t, bin, []string{"HTTPS_PROXY=" + registry.proxyURL, "SSL_CERT_FILE=" + registry.caFile},
		"-config", config, "-listen", listen)
	t.Logf("server on http://%s, version %q", listen, srv.state().Version)

	// While one appliance says nothing, the dashboard answers at once.
	if a := srv.get("/"); a.status != 200 || a.took > 2*time.Second {
		t.Errorf("the overview took %s (status %d) while an appliance hangs", a.took, a.status)
	}

	// 1. The agent on this machine: its real package manager, the test's two containers, a
	// backup that shows as a file.
	backups := filepath.Join(dir, "backups")
	write(t, filepath.Join(backups, "home-2026-11-18.tar"), strings.Repeat("x", 4096), 0o644)
	containers := "enabled = false"
	if socket != "" {
		containers = fmt.Sprintf("sockets = [%q]", socket)
	}
	agentConfig := write(t, filepath.Join(dir, "agent.toml"), fmt.Sprintf(`
server = "http://%s"
token_file = %q
name = %q

[containers]
%s

[backups]
state_dir = %q

[[backups.file]]
name = "home archive"
path = %q
`, listen, filepath.Join(dir, "token"), workstation, containers, filepath.Join(dir, "agent-state"), filepath.Join(backups, "*.tar")), 0o644)
	out, err := runAgent(t, bin, "-config", agentConfig, "-once")
	t.Logf("agent on %s:\n%s", host, out)
	if err != nil {
		t.Fatalf("upkeep agent -once: %v", err)
	}
	if !strings.Contains(out, "report sent:") {
		t.Errorf("the agent did not say that its report was sent")
	}

	// What the server refuses.
	small := func(name string) string {
		return fmt.Sprintf(`{"schema":1,"system":{"name":%q,"kind":"linux","source":"agent"},"sent":%q}`, name, time.Now().UTC().Format(time.RFC3339))
	}
	for _, tc := range []struct {
		what, token, body string
		want              int
	}{
		{"a report without a token", "", small("intruder"), 401},
		{"a report with a wrong token", "not-the-token-not-the-token", small("intruder"), 401},
		{"a system's own token for another name", debianToken, small(workstation), 403},
		{"the shared token for a system with a token of its own", sharedToken, small("debian-e2e"), 403},
		{"the name of a polled system", sharedToken, small("opnsense-e2e"), 409},
		{"a name that is a path", sharedToken, small(".."), 400},
		{"something that is no report", sharedToken, `{"schema":`, 400},
	} {
		if a := srv.do(http.MethodPost, "/api/v1/report", tc.token, tc.body); a.status != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", tc.what, a.status, tc.want, strings.TrimSpace(a.body))
		}
	}
	if a := srv.get("/api/v1/state"); a.status != 401 {
		t.Errorf("the state without a token: status %d, want 401", a.status)
	}
	if a := srv.do(http.MethodGet, "/api/v1/state", debianToken, ""); a.status != 401 {
		t.Errorf("the state with one system's token: status %d, want 401", a.status)
	}

	// A machine that is taken out of service again.
	if a := srv.do(http.MethodPost, "/api/v1/report", sharedToken, small("old-pi")); a.status != 200 {
		t.Fatalf("a small report: status %d: %s", a.status, a.body)
	}
	srv.page("/systems/old-pi", "old-pi")
	if a := srv.do(http.MethodDelete, "/api/v1/systems/old-pi", sharedToken, ""); a.status != 200 {
		t.Errorf("forgetting old-pi: status %d: %s", a.status, a.body)
	}
	if a := srv.get("/systems/old-pi"); a.status != 404 {
		t.Errorf("old-pi after it was forgotten: status %d, want 404", a.status)
	}

	// 2. A real Debian: the same binary in a container, as an unprivileged user, with the
	// machine's network, reporting with a token of its own.
	debian := os.Getenv("UPKEEP_E2E_DEBIAN") != "0"
	image := os.Getenv("UPKEEP_E2E_DEBIAN_IMAGE")
	if image == "" {
		image = "docker.io/library/debian:trixie"
	}
	if debian && !havePodmanImage(image) {
		t.Logf("no Podman, or no local image %s: no Debian agent", image)
		debian = false
	}
	if debian {
		etc := filepath.Join(dir, "debian-etc")
		write(t, filepath.Join(etc, "token"), debianToken+"\n", 0o644) // read by "nobody" in the container
		write(t, filepath.Join(etc, "agent.toml"), fmt.Sprintf(`
server = "http://%s"
token_file = "/etc/upkeep/token"
name = "debian-e2e"

[[backups.file]]
name = "etc archive"
path = "/var/backups/e2e"
max_age_hours = 48
`, listen), 0o644)
		script := `set -e
apt-get update -q 2>&1 | tail -n 3
mkdir -p /var/backups/e2e && tar -cf /var/backups/e2e/etc.tar -C / etc/hostname etc/os-release 2>/dev/null
echo "--- as $(setpriv --reuid=65534 --regid=65534 --clear-groups id -un) ---"
exec setpriv --reuid=65534 --regid=65534 --clear-groups /usr/local/bin/upkeep agent -once`
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "--name", "upkeep-e2e-debian", "--pull=never",
			"--network", "host", "--security-opt", "label=disable",
			"-v", bin+":/usr/local/bin/upkeep:ro", "-v", etc+":/etc/upkeep:ro", image, "sh", "-c", script)
		t.Cleanup(func() { podman("rm", "-f", "-t", "0", "upkeep-e2e-debian") })
		out, err := cmd.CombinedOutput()
		cancel()
		t.Logf("agent in %s:\n%s", image, out)
		if err != nil {
			t.Fatalf("the agent in the Debian container: %v", err)
		}
	}

	// 3. The registry round starts a minute after the server; wait for its answers.
	wantChecks := 0
	if socket != "" {
		wantChecks = 2
	}
	var st state
	for deadline := started.Add(4 * time.Minute); ; {
		st = srv.state()
		if len(st.ImageChecks) >= wantChecks && time.Since(started) > 12*time.Second {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %s the server has %d image checks, want %d\n%s", time.Since(started).Round(time.Second), len(st.ImageChecks), wantChecks, srv.log)
		}
		time.Sleep(2 * time.Second)
	}

	// ---- what the API says ----
	systems := map[string]int{}
	for i, s := range st.Systems {
		systems[s.Name] = i
	}
	wantSystems := []string{workstation, "opnsense-e2e", "opnsense-silent", "homeassistant-e2e"}
	if debian {
		wantSystems = append(wantSystems, "debian-e2e")
	}
	for _, name := range wantSystems {
		if _, ok := systems[name]; !ok {
			t.Fatalf("the state has no system %q; it has %v", name, systems)
		}
	}
	if len(st.Systems) != len(wantSystems) {
		t.Errorf("the state has %d systems, want %d: %v", len(st.Systems), len(wantSystems), systems)
	}

	// This machine.
	ws := st.Systems[systems[workstation]].Report
	t.Logf("%s: %s %s, kernel %s, %s; agent %s", workstation, ws.System.OS, ws.System.OSVersion, ws.System.Kernel, ws.System.Arch, ws.System.AgentVersion)
	// "upkeep version" and the version in a report are the same words.
	said, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("upkeep version: %v", err)
	}
	if ws.System.Source != "agent" || ws.System.Kind != "linux" || ws.System.OS == "" || ws.System.Kernel == "" || ws.System.AgentVersion != strings.TrimSpace(string(said)) {
		t.Errorf("%s: system %+v", workstation, ws.System)
	}
	if ws.Packages == nil {
		t.Errorf("%s reports no packages; problems: %+v", workstation, ws.Errors)
	} else {
		t.Logf("%s: %s, %d pending, %d security, lists of %s", workstation, ws.Packages.Manager, ws.Packages.Pending, ws.Packages.Security, ws.Packages.ListsUpdated.Format(time.RFC3339))
		if ws.Packages.Pending > 0 != st.has(workstation, "package update") {
			t.Errorf("%s: %d pending, findings %v", workstation, ws.Packages.Pending, st.titles(workstation))
		}
		if n := min(ws.Packages.Pending, 300); len(ws.Packages.Items) != n {
			t.Errorf("%s: %d pending but %d listed", workstation, ws.Packages.Pending, len(ws.Packages.Items))
		}
	}
	if len(ws.Backups) != 1 || ws.Backups[0].Name != "home archive" || ws.Backups[0].LastResult != "ok" || ws.Backups[0].LastSuccess.IsZero() {
		t.Errorf("%s: backups %+v", workstation, ws.Backups)
	}
	if len(ws.Errors) != 0 {
		t.Errorf("%s: problems %+v", workstation, ws.Errors)
	}
	if socket != "" {
		if len(ws.Containers) != 2 {
			t.Fatalf("%s: containers %+v", workstation, ws.Containers)
		}
		exact, rolling := ws.Containers[0], ws.Containers[1] // sorted by name
		if exact.Name != "upkeep-e2e-exact" || exact.Image != alpineExact || exact.Runtime != "podman" || exact.State != "running" {
			t.Errorf("container: %+v", exact)
		}
		if rolling.Name != "upkeep-e2e-rolling" || rolling.Image != alpineRolling || rolling.AutoUpdate != "registry" {
			t.Errorf("container: %+v", rolling)
		}
		t.Logf("%s runs %s and is known by %v; the registry names %s", exact.Name, exact.Digest, exact.Digests, tagDigestFor(t, alpineExact))
		checks := map[string]int{}
		for i, c := range st.ImageChecks {
			checks[c.Image] = i
			if c.Error != "" || c.Note != "" {
				t.Errorf("check of %s: error %q, note %q", c.Image, c.Error, c.Note)
			}
		}
		if c := st.ImageChecks[checks[alpineExact]]; c.NewerPatch != "3.20.3" || c.NewerMinor != "3.22.2" || c.NewerMajor != "" || c.TagDigest != tagDigestFor(t, alpineExact) {
			t.Errorf("check of %s: %+v", alpineExact, c)
		}
		if c := st.ImageChecks[checks[alpineRolling]]; c.NewerPatch != "" || c.NewerMinor != "3.22" || c.NewerMajor != "" || c.TagDigest != rebuiltDigest {
			t.Errorf("check of %s: %+v", alpineRolling, c)
		}
		for title, want := range map[string]bool{
			"upkeep-e2e-exact: 3.20.3 available":       true,
			"upkeep-e2e-rolling: 3.22 available":       true,
			"upkeep-e2e-rolling: tag 3.20 was rebuilt": true,
			// The image is exactly what the tag points at, although Podman knows it by a
			// second digest too: this must not read as rebuilt.
			"upkeep-e2e-exact: tag 3.20.0 was rebuilt": false,
		} {
			if st.has(workstation, title) != want {
				t.Errorf("finding %q: there %v, want %v; findings: %v", title, !want, want, st.titles(workstation))
			}
		}
	}

	// The Debian container.
	if debian {
		deb := st.Systems[systems["debian-e2e"]].Report
		if deb.Packages == nil {
			t.Fatalf("debian-e2e reports no packages; problems: %+v", deb.Errors)
		}
		t.Logf("debian-e2e: %s %s, kernel %s; %s, %d pending, %d security, lists of %s", deb.System.OS, deb.System.OSVersion, deb.System.Kernel,
			deb.Packages.Manager, deb.Packages.Pending, deb.Packages.Security, deb.Packages.ListsUpdated.Format(time.RFC3339))
		if !strings.Contains(deb.System.OS, "Debian") || !strings.HasPrefix(deb.System.OSVersion, "13") || deb.Packages.Manager != "apt" {
			t.Errorf("debian-e2e: system %+v, manager %s", deb.System, deb.Packages.Manager)
		}
		if age := time.Since(deb.Packages.ListsUpdated); deb.Packages.ListsUpdated.IsZero() || age > 72*time.Hour || age < 0 {
			t.Errorf("debian-e2e: package lists of %s after an apt-get update just now", deb.Packages.ListsUpdated)
		}
		if deb.Packages.Pending > 0 != st.has("debian-e2e", "package update") {
			t.Errorf("debian-e2e: %d pending, findings %v", deb.Packages.Pending, st.titles("debian-e2e"))
		}
		for _, it := range deb.Packages.Items {
			if it.Name == "" || it.Installed == "" || it.Candidate == "" {
				t.Errorf("debian-e2e: a pending package without its versions: %+v", it)
			}
		}
		if len(deb.Backups) != 1 || deb.Backups[0].LastResult != "ok" || !strings.Contains(deb.Backups[0].Detail, "etc.tar") {
			t.Errorf("debian-e2e: backups %+v", deb.Backups)
		}
		if len(deb.Containers) != 0 || len(deb.Errors) != 0 {
			t.Errorf("debian-e2e: containers %+v, problems %+v (a machine without a runtime is no problem)", deb.Containers, deb.Errors)
		}
	}

	// The firewall that answers.
	fw := st.Systems[systems["opnsense-e2e"]].Report
	if fw.System.Kind != "opnsense" || fw.System.Source != "connector" || fw.System.OSVersion != "26.7.8" || fw.System.Kernel != "FreeBSD 15.1-RELEASE-p7" {
		t.Errorf("opnsense-e2e: system %+v", fw.System)
	}
	if fw.Packages == nil || fw.Packages.Manager != "pkg" || fw.Packages.Pending != 7 || time.Since(fw.Packages.ListsUpdated) > 3*time.Hour {
		t.Errorf("opnsense-e2e: packages %+v", fw.Packages)
	}
	if len(fw.Software) != 3 || fw.Software[0].Name != "OPNsense" || fw.Software[0].Latest != "26.7.9" || !fw.Software[0].UpdateAvailable {
		t.Errorf("opnsense-e2e: software %+v", fw.Software)
	}
	if len(fw.Errors) != 0 {
		t.Errorf("opnsense-e2e: problems %+v", fw.Errors)
	}
	for _, title := range []string{"OPNsense 26.7.9 available", "os-acme-client 4.13 available", "7 package updates"} {
		if !st.has("opnsense-e2e", title) {
			t.Errorf("opnsense-e2e: no finding %q in %v", title, st.titles("opnsense-e2e"))
		}
	}
	for _, p := range opnAsked() {
		if p != "GET /api/core/firmware/status" {
			t.Errorf("the firewall was asked %q; only the status may be read", p)
		}
	}

	// The firewall that hangs: on the dashboard as a failed connector, with nothing made up.
	silent := st.Systems[systems["opnsense-silent"]].Report
	if silent.Packages != nil || len(silent.Software) != 0 || len(silent.Errors) != 1 || silent.Errors[0].Collector != "connector" {
		t.Errorf("opnsense-silent: %+v", silent)
	}
	if !st.has("opnsense-silent", "connector failed") {
		t.Errorf("opnsense-silent: findings %v", st.titles("opnsense-silent"))
	}

	// Home Assistant.
	hass := st.Systems[systems["homeassistant-e2e"]].Report
	if hass.System.Kind != "homeassistant" || hass.System.OS != "Home Assistant OS" || hass.System.OSVersion != "18.4" {
		t.Errorf("homeassistant-e2e: system %+v", hass.System)
	}
	if len(hass.Software) != 11 || hass.Software[0].Name != "Home Assistant Core" || hass.Software[0].Latest != "2026.11.2" {
		t.Errorf("homeassistant-e2e: %d software entries, first %+v", len(hass.Software), hass.Software)
	}
	if len(hass.Backups) != 1 || hass.Backups[0].Kind != "homeassistant" || hass.Backups[0].LastResult != "ok" || time.Since(hass.Backups[0].LastSuccess) > 6*time.Hour {
		t.Errorf("homeassistant-e2e: backups %+v", hass.Backups)
	}
	for _, title := range []string{"Home Assistant Core 2026.11.2 available", "Home Assistant Operating System 18.5 available", "Zigbee2MQTT 2.7.0-1 available"} {
		if !st.has("homeassistant-e2e", title) {
			t.Errorf("homeassistant-e2e: no finding %q in %v", title, st.titles("homeassistant-e2e"))
		}
	}
	if st.has("homeassistant-e2e", "backup") {
		t.Errorf("homeassistant-e2e: a finding about a backup that ran five hours ago: %v", st.titles("homeassistant-e2e"))
	}

	// ---- what the dashboard says ----
	overview := srv.page("/",
		fmt.Sprintf("Systems %d 1 not answering", len(wantSystems)),
		"Needs attention", "connector failed",
		"opnsense-e2e", "opnsense-silent", "homeassistant-e2e", workstation,
		"OPNsense 26.7.9 available",
	)
	if strings.Contains(overview, "Nothing needs attention") {
		t.Error("the overview says that nothing needs attention")
	}
	// The row of the firewall that never answered: nothing known, and it says so.
	if !strings.Contains(overview, "opnsense-silent — — — — —") {
		at := strings.LastIndex(overview, "opnsense-silent")
		t.Errorf("the row of opnsense-silent claims something: %q", overview[at:min(len(overview), at+80)])
	}

	updates := srv.page("/updates", workstation, "opnsense-e2e", "OS packages", "OPNsense firmware 26.7.8 26.7.9 update", "Home Assistant Core core 2026.11.1 2026.11.2 update")
	if socket != "" {
		for _, want := range []string{
			"upkeep-e2e-rolling docker.io/library/alpine 3.20 minor 3.22 tag was rebuilt yes",
			"upkeep-e2e-exact docker.io/library/alpine 3.20.0 patch 3.20.3 minor 3.22.2 no",
		} {
			if !strings.Contains(updates, want) {
				t.Errorf("/updates does not say %q; it says %q", want, around(updates, "upkeep-e2e-", 300))
			}
		}
	}
	if debian {
		srv.page("/updates", "debian-e2e", "apt · lists refreshed")
		srv.page("/systems/debian-e2e", "Debian GNU/Linux 13 (trixie)", "an installed agent that pushes its report", "etc archive", "Every collector did its job.")
		srv.page("/backups", "debian-e2e etc archive ok")
	}
	srv.page("/backups", workstation+" home archive ok", "homeassistant-e2e homeassistant automatic backup ok", "Systems that report no backup: opnsense-e2e , opnsense-silent .")
	srv.page("/systems/"+workstation, "an installed agent that pushes its report", "home archive", "Raw report")
	srv.page("/systems/opnsense-e2e", "a connector: the server asks the system's API", "OPNsense 26.7.8", "FreeBSD 15.1-RELEASE-p7", "os-acme-client plugin 4.12 4.13 update", "7 pending")
	srv.page("/systems/opnsense-silent", "connector failed", "Collector problems 1")
	srv.page("/systems/homeassistant-e2e", "Home Assistant OS 18.4", "Zigbee2MQTT app 2.6.3-1 2.7.0-1 update", "homeassistant automatic backup")
	if a := srv.get("/systems/" + workstation + "/report.json"); a.status != 200 || !json.Valid([]byte(a.body)) || !strings.Contains(a.body, `"name": "`+workstation+`"`) {
		t.Errorf("the raw report: status %d, %d bytes", a.status, len(a.body))
	}
	if a := srv.get("/static/app.css"); a.status != 200 || !strings.HasPrefix(a.header.Get("Content-Type"), "text/css") {
		t.Errorf("the stylesheet: status %d, %s", a.status, a.header.Get("Content-Type"))
	}
	if a := srv.get("/systems/nobody"); a.status != 404 || !strings.Contains(text(a.body), "Unknown system") {
		t.Errorf("an unknown system: status %d", a.status)
	}
	if a := srv.get("/healthz"); a.status != 200 || a.body != "ok\n" {
		t.Errorf("/healthz: status %d, %q", a.status, a.body)
	}

	// ---- nothing went where it should not ----
	requests, tunnels := registry.asked()
	sort.Strings(requests)
	t.Logf("the stand-in registry was asked:\n  %s", strings.Join(requests, "\n  "))
	for _, host := range tunnels {
		if host != "registry-1.docker.io:443" && host != "auth.e2e.example:443" {
			t.Errorf("the server asked for a connection to %s", host)
		}
	}
	for _, line := range requests {
		if strings.HasPrefix(line, "GET ") && strings.Contains(line, "/manifests/") {
			t.Errorf("a manifest was fetched, which counts as a pull: %s", line)
		}
	}
	srv.stop()
	log := srv.log.String()
	save(t, "server.log", log)
	for _, secret := range secrets {
		if strings.Contains(log, secret) || strings.Contains(out, secret) {
			t.Errorf("a secret (%s...) is in a log", secret[:8])
		}
	}
	if !strings.Contains(log, "connector failed") || !strings.Contains(log, "opnsense-silent") {
		t.Errorf("the log does not name the connector that failed")
	}
	for _, leftover := range []string{"upkeep.db-wal", "upkeep.db-shm"} {
		if _, err := os.Stat(filepath.Join(dir, "data", leftover)); err == nil {
			t.Errorf("%s is left after a clean stop", leftover)
		}
	}
}

const (
	alpineRollingTag = "3.20"
	alpineExactTag   = "3.20.0"
)

// The demo needs nothing: no configuration, no agents, no network.
func TestDemo(t *testing.T) {
	bin := binary(t)
	listen := freePort(t)
	srv := startServer(t, bin, nil, "-demo", "-listen", listen)
	overview := srv.page("/", "Systems 7 1 silent", "Need attention", "OS updates 19 4 security, 1 reboot", "Container updates 9", "Backups late or failed 3")
	t.Logf("demo overview begins: %.300s", overview)
	save(t, "demo-overview.html", srv.get("/").body)
	srv.page("/updates", "gitea", "docker.io/gitea/gitea", "patch 1.23.8", "OPNsense")
	srv.page("/backups", "restic-backup", "failed")
	for _, name := range []string{"server", "ops01", "dns02", "storage", "opnsense", "opnsense02", "homeassistant"} {
		srv.page("/systems/"+name, name, "Raw report")
	}
	if a := srv.do(http.MethodPost, "/api/v1/report", sharedToken, `{"schema":1,"system":{"name":"x","source":"agent"}}`); a.status != 401 {
		t.Errorf("the demo took a report: status %d", a.status)
	}
	srv.stop()
}

// One look at the real registries, when asked for: four images that exist, reported by hand.
func TestLiveRegistries(t *testing.T) {
	if os.Getenv("UPKEEP_E2E_LIVE") != "1" {
		t.Skip("UPKEEP_E2E_LIVE is not 1")
	}
	images := []string{
		"docker.io/gitea/gitea:1.23.6",
		"lscr.io/linuxserver/unifi-network-application:10.0.162-ls114",
		"docker.io/library/mariadb:11.4.13",
		"docker.io/photoprism/photoprism:251130",
	}
	bin := binary(t)
	dir := t.TempDir()
	listen := freePort(t)
	config := write(t, filepath.Join(dir, "server.toml"), fmt.Sprintf("listen = %q\ndata_dir = %q\ntoken_file = %q\n",
		listen, filepath.Join(dir, "data"), write(t, filepath.Join(dir, "token"), sharedToken+"\n", 0o600)), 0o644)
	var env []string
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		if v := os.Getenv(name); v != "" {
			env = append(env, name+"="+v)
		}
	}
	srv := startServer(t, bin, env, "-config", config, "-listen", listen)
	var containers []string
	for i, image := range images {
		containers = append(containers, fmt.Sprintf(`{"name":"c%d","image":%q,"state":"running","runtime":"podman"}`, i, image))
	}
	body := fmt.Sprintf(`{"schema":1,"system":{"name":"live","kind":"linux","source":"agent"},"sent":%q,"containers":[%s]}`,
		time.Now().UTC().Format(time.RFC3339), strings.Join(containers, ","))
	if a := srv.do(http.MethodPost, "/api/v1/report", sharedToken, body); a.status != 200 {
		t.Fatalf("the report: status %d: %s", a.status, a.body)
	}
	var st state
	for deadline := time.Now().Add(4 * time.Minute); len(st.ImageChecks) < len(images); {
		if time.Now().After(deadline) {
			t.Fatalf("the server has %d image checks after 4 minutes\n%s", len(st.ImageChecks), srv.log)
		}
		time.Sleep(3 * time.Second)
		st = srv.state()
	}
	for _, c := range st.ImageChecks {
		t.Logf("%s\n    tag digest %s\n    newer: patch %q, minor %q, major %q; error %q; note %q",
			c.Image, c.TagDigest, c.NewerPatch, c.NewerMinor, c.NewerMajor, c.Error, c.Note)
		if c.Error != "" || c.TagDigest == "" {
			t.Errorf("%s: no good answer", c.Image)
		}
	}
	t.Logf("findings: %v", st.titles("live"))
	srv.page("/updates", "docker.io/gitea/gitea", "lscr.io/linuxserver/unifi-network-application")
	srv.stop()
}
