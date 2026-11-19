package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// flavour is how one registry behaves. Everything here was observed on 2026-11-18 with curl
// against the real registries, anonymously, unless a line says otherwise.
type flavour struct {
	realm, service string // token service named in the 401; none: public repositories need no token
	expiresIn      int    // "expires_in" of a token; 0: the answer has no such field
	bothTokens     bool   // the token answer has "token" and "access_token"
	maxPage        int    // the most tags in one page, whatever n says
	nBeforeLast    bool   // the order of n and last in the Link header
	needsOCIAccept bool   // HEAD of a manifest without the OCI index type in Accept: 404
	tokenDenied    bool   // the token service refuses a repository it does not know
}

var flavours = map[string]flavour{
	// Docker Hub: www-authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:gitea/gitea:pull"
	// Token answer: {"token": <2694 chars>, "access_token": <the same>, "expires_in": 300, "issued_at": "2026-11-18T23:36:33.993655326Z"}
	// link: </v2/gitea/gitea/tags/list?last=1-linux-arm64-rootless&n=5>; rel="next"; 1000 tags a page when asked for 1000.
	"registry-1.docker.io": {realm: "https://auth.docker.io/token", service: "registry.docker.io", expiresIn: 300, bothTokens: true, maxPage: 1000},
	// ghcr.io: www-authenticate: Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:stryan/materia:pull"
	// Token answer: {"token": <52 chars>} and nothing else. 1000 tags a page when asked for 1000.
	// link: </v2/stryan/materia/tags/list?last=v0.2.1&n=5>; rel="next"
	"ghcr.io": {realm: "https://ghcr.io/token", service: "ghcr.io", maxPage: 1000, needsOCIAccept: true, tokenDenied: true},
	// lscr.io is linuxserver.io's name for its images on ghcr.io: it answers itself, and sends
	// clients to ghcr.io for the token.
	"lscr.io": {realm: "https://ghcr.io/token", service: "ghcr.io", maxPage: 1000, needsOCIAccept: true, tokenDenied: true},
	// quay.io answers for public repositories without a token, gives 100 tags a page whatever
	// n says, and writes: link: </v2/prometheus/node-exporter/tags/list?n=5&last=master>; rel="next"
	// For a repository it does not show: www-authenticate: Bearer realm="https://quay.io/v2/auth",service="quay.io",scope="repository:prometheus/no-such-repo-xyz123:pull"
	"quay.io": {maxPage: 100, nBeforeLast: true},
}

// Bodies of real error answers.
const (
	// Docker Hub, any request without a token, and with one for a repository that does not exist.
	hubUnauthorized = `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"%s","Action":"pull"}]}]}`
	// ghcr.io and lscr.io, any request without a token.
	ghcrUnauthorized = `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`
	// ghcr.io/token for a repository that does not exist (HTTP 403).
	ghcrDenied = `{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}`
	// quay.io for a repository that does not exist or is private, with or without a token.
	quayUnauthorized = `{"errors":[{"code":"UNAUTHORIZED","detail":{},"message":"access to the requested resource is not authorized"}]}`
	// Docker Hub, GET /v2/gitea/gitea/tags/list?n=abc (HTTP 400).
	hubBadPageSize = `{"errors":[{"code":"PAGINATION_NUMBER_INVALID","message":"invalid number of results requested","detail":{"n":"abc"}}]}`
	// Docker Hub's answer over the pull limit (HTTP 429), as its documentation prints it
	// (docs.docker.com/docker-hub/usage/pulls); not captured, nobody here was over the limit.
	hubTooManyRequests = `{"errors":[{"code":"TOOMANYREQUESTS","message":"You have reached your unauthenticated pull rate limit. https://www.docker.com/increase-rate-limit"}]}`
)

// secretMark is in every token the fake issues, so that a test can look for a leak.
const secretMark = "sEcReT"

type fakeRepo struct {
	tags    []string
	digests map[string]string // tag -> what the registry said it points at
}

type fakeToken struct {
	scope   string
	service string
	expires time.Time
}

// fakeRegistry is all registries of the tests behind one httptest server. A transport sends
// every https request there and keeps the host it was meant for.
type fakeRegistry struct {
	t      *testing.T
	server *httptest.Server
	clock  *fakeClock

	mu        sync.Mutex
	repos     map[string]*fakeRepo // by "host/repository", the host being the API's
	tokens    map[string]fakeToken
	log       []string                                          // "HEAD registry-1.docker.io/v2/gitea/gitea/manifests/1.23.6 401"
	intercept func(w http.ResponseWriter, r *http.Request) bool // a test's own answer; true: done
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{
		t:      t,
		clock:  &fakeClock{t: time.Date(2026, 11, 18, 23, 40, 0, 0, time.UTC)},
		repos:  map[string]*fakeRepo{},
		tokens: map[string]fakeToken{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

// add puts a repository with the tags of a fixture into the fake.
func (f *fakeRegistry) add(apiHost, repo, fixture string, digests map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.repos[apiHost+"/"+repo] = &fakeRepo{tags: loadTags(f.t, fixture), digests: digests}
}

// client returns a Client whose requests all end at the fake.
func (f *fakeRegistry) client(opts Options) *Client {
	target, err := url.Parse(f.server.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	opts.HTTP = &http.Client{Transport: redirectAll{to: target.Host, base: f.server.Client().Transport}}
	opts.Now = f.clock.Now
	return New(opts)
}

// redirectAll sends every request to one address and refuses plain HTTP, which the client
// must never use.
type redirectAll struct {
	to   string
	base http.RoundTripper
}

func (rt redirectAll) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("the client asked for %s, which is not https", req.URL.Redacted())
	}
	out := req.Clone(req.Context())
	out.Host = req.URL.Host
	out.URL.Scheme, out.URL.Host = "http", rt.to
	return rt.base.RoundTrip(out)
}

// requests returns the log, and count how many entries start with prefix.
func (f *fakeRegistry) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeRegistry) count(prefix string) int {
	n := 0
	for _, line := range f.requests() {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeRegistry) setIntercept(fn func(w http.ResponseWriter, r *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.intercept = fn
}

// statusRecorder notes the status for the log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		f.mu.Lock()
		f.log = append(f.log, fmt.Sprintf("%s %s%s %d", r.Method, r.Host, r.URL.RequestURI(), rec.status))
		f.mu.Unlock()
	}()
	f.mu.Lock()
	intercept := f.intercept
	f.mu.Unlock()
	if intercept != nil && intercept(rec, r) {
		return
	}
	switch {
	case r.Host == "auth.docker.io" && r.URL.Path == "/token":
		f.serveToken(rec, r, flavours["registry-1.docker.io"])
	case r.Host == "ghcr.io" && r.URL.Path == "/token":
		f.serveToken(rec, r, flavours["ghcr.io"])
	case r.Host == "quay.io" && r.URL.Path == "/v2/auth":
		f.serveToken(rec, r, flavour{service: "quay.io"})
	default:
		fl, known := flavours[r.Host]
		if !known {
			f.t.Errorf("request to %s, which no test expects", r.Host)
			http.Error(rec, "no such registry in this test", http.StatusBadGateway)
			return
		}
		f.serveRegistry(rec, r, fl)
	}
}

func (f *fakeRegistry) serveToken(w http.ResponseWriter, r *http.Request, fl flavour) {
	q := r.URL.Query()
	scope, service := q.Get("scope"), q.Get("service")
	repo := strings.TrimSuffix(strings.TrimPrefix(scope, "repository:"), ":pull")
	if r.Method != http.MethodGet || service != fl.service || "repository:"+repo+":pull" != scope {
		f.t.Errorf("token request %s %s: want GET with service=%s and scope=repository:<name>:pull", r.Method, r.URL.RequestURI(), fl.service)
		http.Error(w, "bad token request", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Authorization") != "" {
		f.t.Errorf("token request carries an Authorization header")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if fl.tokenDenied {
		known := false
		for key := range f.repos {
			known = known || strings.HasSuffix(key, "/"+repo)
		}
		if !known {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, ghcrDenied)
			return
		}
	}
	value := fmt.Sprintf("%s-%d.for.%s", secretMark, len(f.tokens)+1, strings.ReplaceAll(repo, "/", "_"))
	life := time.Duration(fl.expiresIn) * time.Second
	if life == 0 {
		life = 60 * time.Second // what a token lives when the answer does not say
	}
	f.tokens[value] = fakeToken{scope: scope, service: service, expires: f.clock.Now().Add(life)}
	answer := map[string]any{"token": value}
	if fl.bothTokens {
		answer["access_token"] = value
		answer["issued_at"] = f.clock.Now().Format(time.RFC3339Nano)
	}
	if fl.expiresIn > 0 {
		answer["expires_in"] = fl.expiresIn
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(answer)
}

// authorized reports whether the request may read repo, and answers 401 as the registry
// would when it may not.
func (f *fakeRegistry) authorized(w http.ResponseWriter, r *http.Request, fl flavour, repo string, exists bool) bool {
	scope := "repository:" + repo + ":pull"
	bearer, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	tok, issued := f.tokens[bearer]
	f.mu.Unlock()
	valid := hasBearer && issued && tok.scope == scope && f.clock.Now().Before(tok.expires)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	switch r.Host {
	case "quay.io":
		if exists {
			return true // public: with a token or without
		}
		w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="https://quay.io/v2/auth",service="quay.io",scope="%s"`, scope))
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, quayUnauthorized)
		return false
	case "registry-1.docker.io":
		if valid && exists {
			return true
		}
		challenge := fmt.Sprintf(`Bearer realm="%s",service="%s",scope="%s"`, fl.realm, fl.service, scope)
		if valid {
			challenge += `,error="insufficient_scope"` // a good token for a repository that is not there
		}
		w.Header().Set("Www-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, hubUnauthorized, repo)
		return false
	default: // ghcr.io, lscr.io
		if valid {
			return true
		}
		w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="%s",scope="%s"`, fl.realm, fl.service, scope))
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, ghcrUnauthorized)
		return false
	}
}

func (f *fakeRegistry) serveRegistry(w http.ResponseWriter, r *http.Request, fl flavour) {
	if !strings.Contains(r.Header.Get("User-Agent"), "upkeep") {
		f.t.Errorf("%s %s: User-Agent %q does not say who asks", r.Method, r.URL.Path, r.Header.Get("User-Agent"))
	}
	path, isV2 := strings.CutPrefix(r.URL.Path, "/v2/")
	if !isV2 {
		http.NotFound(w, r)
		return
	}
	var repoName, ref string
	var tagsList bool
	if name, ok := strings.CutSuffix(path, "/tags/list"); ok {
		repoName, tagsList = name, true
	} else if i := strings.LastIndex(path, "/manifests/"); i >= 0 {
		repoName, ref = path[:i], path[i+len("/manifests/"):]
	} else {
		f.t.Errorf("%s %s: the client has no business there", r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	repo, exists := f.repos[r.Host+"/"+repoName]
	f.mu.Unlock()
	if !f.authorized(w, r, fl, repoName, exists) {
		return
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if tagsList {
		f.serveTags(w, r, fl, repoName, repo)
		return
	}
	// HEAD is free on Docker Hub; a GET of a manifest is a pull and counts against the limit.
	if r.Method != http.MethodHead {
		f.t.Errorf("%s of a manifest: only HEAD is free of Docker Hub's pull limit", r.Method)
	}
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "application/vnd.oci.image.index.v1+json") || !strings.Contains(accept, "application/vnd.docker.distribution.manifest.list.v2+json") {
		f.t.Errorf("HEAD %s: Accept %q lacks the index types", r.URL.Path, accept)
		if fl.needsOCIAccept {
			// ghcr.io: {"errors":[{"code":"MANIFEST_UNKNOWN","message":"OCI index found, but Accept header does not support OCI indexes"}]}
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	digest, found := repo.digests[ref]
	if !found {
		// Docker Hub for a GET: {"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown","detail":"unknown tag=no-such-tag-xyz"}]}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Every tag of the fixtures is a multi-platform image; quay.io's are Docker manifest lists.
	mediaType := "application/vnd.oci.image.index.v1+json"
	if r.Host == "quay.io" {
		mediaType = "application/vnd.docker.distribution.manifest.list.v2+json"
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Etag", `"`+digest+`"`)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeRegistry) serveTags(w http.ResponseWriter, r *http.Request, fl flavour, repoName string, repo *fakeRepo) {
	if r.Method != http.MethodGet {
		f.t.Errorf("%s of a tag list", r.Method)
	}
	q := r.URL.Query()
	n := fl.maxPage
	if s := q.Get("n"); s != "" {
		asked, err := strconv.Atoi(s)
		if err != nil || asked < 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, hubBadPageSize)
			return
		}
		n = min(asked, fl.maxPage)
	}
	start := 0
	if last := q.Get("last"); last != "" {
		for i, tag := range repo.tags {
			if tag == last {
				start = i + 1
			}
		}
	}
	end := min(start+n, len(repo.tags))
	if end < len(repo.tags) {
		params := "last=" + url.QueryEscape(repo.tags[end-1]) + "&n=" + strconv.Itoa(n)
		if fl.nBeforeLast {
			params = "n=" + strconv.Itoa(n) + "&last=" + url.QueryEscape(repo.tags[end-1])
		}
		w.Header().Set("Link", fmt.Sprintf(`</v2/%s/tags/list?%s>; rel="next"`, repoName, params))
	}
	json.NewEncoder(w).Encode(map[string]any{"name": repoName, "tags": repo.tags[start:end]})
}
