package opnsense

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	_ "time/tzdata" // the tests place "CET" in Europe/Zagreb whatever the machine has installed

	"github.com/pelletier/go-toml/v2"

	"github.com/valicm/upkeep/internal/connect"
	"github.com/valicm/upkeep/internal/report"
)

// Where the test data comes from is written down in testdata/SOURCES.txt. In short: the
// status-*.json files are what OPNsense's real statusAction() prints (stable/26.7, run by
// testdata/gen/run.sh), and the firewall below answers the way ApiControllerBase.php and
// FirmwareController.php do.

const (
	testKey    = "w86XNZob/8Oq8aC5r0kbNarNtdpoQU781fyoeaOBQsBwkXUt"
	testSecret = "XeD26XVrJ5ilAc/EmglCRC+0j2e57tRsjHwFepOseySWLM53pJASeTA3"
)

// firewall is an OPNsense that only has its firmware API.
type firewall struct {
	t         *testing.T
	forbidden bool // the key's user lacks "System: Firmware"
	busy      bool // another firmware action holds the lock

	mu         sync.Mutex
	status     []byte // what GET status answers
	afterCheck []byte // what it answers once a check that was asked for has finished
	checkTakes int    // how many status calls a check takes; below 0 it never finishes
	checking   bool
	calls      []string // "GET status", "POST check", ... in order
}

func (f *firewall) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	answer := func(code int, body string) {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(code)
		io.WriteString(w, body)
	}
	// ApiControllerBase::beforeExecuteRoute: key and secret as basic auth, then the ACL.
	key, secret, ok := r.BasicAuth()
	if !ok || key != testKey || secret != testSecret {
		answer(http.StatusUnauthorized, `{"status":401,"message":"Authentication Failed"}`)
		return
	}
	if f.forbidden {
		answer(http.StatusForbidden, `{"status":403,"message":"Forbidden"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	if r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/json" && len(body) == 0 {
		answer(http.StatusBadRequest, `{"status":400,"message":"Invalid JSON syntax"}`)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/core/firmware/")
	f.calls = append(f.calls, r.Method+" "+action)
	switch action {
	case "status":
		if r.Method != http.MethodGet {
			f.t.Errorf("%s status: only GET reads without making the firewall check", r.Method)
		}
		if f.checking {
			// check.sh removes the old result first and writes the new one at the end.
			if f.checkTakes--; f.checkTakes == 0 {
				f.checking, f.status = false, f.afterCheck
			} else {
				w.Header().Set("Content-Type", "application/json; charset=UTF-8")
				w.Write(fixture(f.t, "status-unchecked.json"))
				return
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.Write(f.status)
	case "running":
		if f.busy || f.checking {
			answer(http.StatusOK, `{"status":"busy"}`)
		} else {
			answer(http.StatusOK, `{"status":"ready"}`)
		}
	case "check":
		if r.Method != http.MethodPost {
			answer(http.StatusOK, `{"status":"failure"}`)
			return
		}
		f.checking = true
		answer(http.StatusOK, `{"msg_uuid":"6f4a4f1c-2f5e-4a0b-9c56-0d6d3c6b1c11","status":"ok"}`)
	default:
		f.t.Errorf("the source called %s %s, which it has no business calling", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *firewall) count(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// keyFile writes the file OPNsense offers for download when a key is created (user.volt).
func keyFile(t *testing.T, key, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fw_upkeep_apikey.txt")
	if err := os.WriteFile(path, []byte("key="+key+"\nsecret="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// newSource builds a source for the firewall at url with a clock that stands still.
func newSource(t *testing.T, url, now string, change func(*Config)) *source {
	t.Helper()
	cfg := Config{Name: "opnsense01", URL: url, KeyFile: keyFile(t, testKey, testSecret), Timezone: "Europe/Zagreb"}
	if change != nil {
		change(&cfg)
	}
	src, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := src.(*source)
	s.now = func() time.Time { return at(now) }
	s.pollEvery = time.Millisecond
	return s
}

// same compares reports as JSON, without the two fields that differ on every run.
func same(t *testing.T, got *report.Report, want report.Report) {
	t.Helper()
	g := *got
	if g.Sent.IsZero() || g.System.AgentVersion == "" {
		t.Errorf("Sent or AgentVersion is not set: %v %q", g.Sent, g.System.AgentVersion)
	}
	g.Sent, g.System.AgentVersion = time.Time{}, ""
	want.Schema = report.Schema
	gj, _ := json.MarshalIndent(g, "", "  ")
	wj, _ := json.MarshalIndent(want, "", "  ")
	if string(gj) != string(wj) {
		t.Errorf("report differs\n got: %s\nwant: %s", gj, wj)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("the report does not validate: %v", err)
	}
}

var (
	community = report.System{
		Name: "opnsense01", Kind: "opnsense", OS: "OPNsense", OSVersion: "26.7.8",
		Kernel: "FreeBSD 15.1-RELEASE-p7", Arch: "amd64", Source: "connector",
	}
	checkedNov18 = at("2026-11-18T02:17:42Z") // "Wed Nov 18 03:17:42 CET 2026"
	checkedNov9  = at("2026-11-09T02:02:11Z") // "Mon Nov  9 03:02:11 CET 2026"
)

const (
	ce267  = "https://docs.opnsense.org/releases/CE_26.7.html"
	advice = `; set check = true for this source, or add a "Firmware update check" job to the firewall's cron settings`
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		now     string
		change  func(*Config)
		want    report.Report
	}{
		{
			name: "an update is available", fixture: "status-update.json", now: "2026-11-18T09:00:00Z",
			want: report.Report{
				System: community,
				Packages: &report.Packages{Manager: "pkg", Pending: 7, ListsUpdated: checkedNov18, Items: []report.PackageUpdate{
					{Name: "opnsense", Installed: "26.7.8", Candidate: "26.7.9"},
					{Name: "os-acme-client", Installed: "4.12", Candidate: "4.13"},
					{Name: "os-theme-cicada", Installed: "1.40", Candidate: "1.41"},
					{Name: "py313-anyio", Candidate: "4.11.0"},
					{Name: "py313-certifi", Installed: "2026.8.3", Candidate: "2026.10.5"},
					{Name: "suricata", Installed: "8.0.2", Candidate: "8.0.3"},
					{Name: "unbound", Installed: "1.24.1", Candidate: "1.24.2"},
				}},
				Software: []report.Software{
					{Name: "OPNsense", Kind: "firmware", Installed: "26.7.8", Latest: "26.7.9", UpdateAvailable: true, URL: ce267, Detail: "7 packages"},
					{Name: "os-acme-client", Kind: "plugin", Installed: "4.12", Latest: "4.13", UpdateAvailable: true},
					{Name: "os-theme-cicada", Kind: "plugin", Installed: "1.40", Latest: "1.41", UpdateAvailable: true},
				},
			},
		},
		{
			name: "no update is available", fixture: "status-none.json", now: "2026-11-18T09:00:00Z",
			want: report.Report{
				System:   community,
				Packages: &report.Packages{Manager: "pkg", ListsUpdated: checkedNov18},
				Software: []report.Software{{Name: "OPNsense", Kind: "firmware", Installed: "26.7.8", Latest: "26.7.8", URL: ce267}},
			},
		},
		{
			// The Business Edition, and the firewall's "this update requires a reboot".
			name: "the update needs a reboot", fixture: "status-be-reboot.json", now: "2026-11-19T08:00:00Z",
			want: report.Report{
				System: report.System{
					Name: "opnsense01", Kind: "opnsense", OS: "OPNsense", OSVersion: "26.10",
					Kernel: "FreeBSD 15.1-RELEASE-p7", Arch: "amd64", Source: "connector",
				},
				// RebootRequired stays false: nothing is waiting for a reboot before the update.
				Packages: &report.Packages{Manager: "pkg", Pending: 7, ListsUpdated: at("2026-11-19T01:41:05Z"), Items: []report.PackageUpdate{
					{Name: "base", Installed: "26.10", Candidate: "26.10.1"},
					{Name: "kernel", Installed: "26.10", Candidate: "26.10.1"},
					{Name: "openssl", Installed: "3.5.4,1", Candidate: "3.5.5,1"},
					{Name: "opnsense-business", Installed: "26.10", Candidate: "26.10.1"},
					{Name: "opnsense-update", Installed: "26.10", Candidate: "26.10.1"},
					{Name: "os-wazuh-agent", Installed: "1.3", Candidate: "1.4"},
					{Name: "py313-typing-extensions", Installed: "4.14.1"}, // to be removed
				}},
				Software: []report.Software{
					{
						Name: "OPNsense", Kind: "firmware", Installed: "26.10", Latest: "26.10.1", UpdateAvailable: true,
						URL: "https://docs.opnsense.org/releases/BE_26.10.html", Detail: "7 packages, the update needs a reboot",
					},
					{Name: "os-wazuh-agent", Kind: "plugin", Installed: "1.3", Latest: "1.4", UpdateAvailable: true},
				},
			},
		},
		{
			name: "the last check is old", fixture: "status-none-old.json", now: "2026-11-18T09:00:00Z",
			want: report.Report{
				System:   community,
				Packages: &report.Packages{Manager: "pkg", ListsUpdated: checkedNov9},
				// ListsUpdated is what tells the server that "nothing pending" is nine days old.
				Software: []report.Software{{
					Name: "OPNsense", Kind: "firmware", Installed: "26.7.8", Latest: "26.7.8", URL: ce267, Detail: "last checked 9 days ago",
				}},
			},
		},
		{
			// After a reboot or an update the firewall has no check result at all.
			name: "never checked", fixture: "status-unchecked.json", now: "2026-11-18T09:00:00Z",
			want: report.Report{
				System: report.System{
					Name: "opnsense01", Kind: "opnsense", OS: "OPNsense", OSVersion: "26.7.8", Arch: "amd64", Source: "connector",
				},
				Software: []report.Software{{
					Name: "OPNsense", Kind: "firmware", Installed: "26.7.8", Latest: "26.7.8", URL: ce267,
					Detail: "not checked for updates since the firewall started or was last updated",
				}},
				Errors: []report.Problem{{Collector: "opnsense", Message: "the firewall has not checked for updates since it started or was last updated" + advice}},
			},
		},
		{
			name: "a major upgrade is offered", fixture: "status-major.json", now: "2026-11-18T09:00:00Z",
			want: report.Report{
				System:   community,
				Packages: &report.Packages{Manager: "pkg", ListsUpdated: checkedNov18},
				Software: []report.Software{{
					Name: "OPNsense", Kind: "firmware", Installed: "26.7.8", Latest: "27.1", UpdateAvailable: true,
					URL: "https://docs.opnsense.org/releases/CE_27.1.html", Detail: "major upgrade, the upgrade needs a reboot",
				}},
			},
		},
		{
			name: "the last check could not reach the mirror", fixture: "status-error.json", now: "2026-11-18T09:00:00Z",
			want: report.Report{
				System: community,
				Software: []report.Software{{
					Name: "OPNsense", Kind: "firmware", Installed: "26.7.8", Latest: "26.7.8", URL: ce267, Detail: "the last update check failed",
				}},
				Errors: []report.Problem{{Collector: "opnsense", Message: "the firewall's last update check failed: No address record found for the selected mirror."}},
			},
		},
		{
			// The daily changelog knows 26.7.9 before a check has seen its packages.
			name: "a release is announced that the last check did not offer", fixture: "status-none-changelog-newer.json", now: "2026-11-18T09:00:00Z",
			want: report.Report{
				System:   community,
				Packages: &report.Packages{Manager: "pkg", ListsUpdated: checkedNov18},
				Software: []report.Software{{
					Name: "OPNsense", Kind: "firmware", Installed: "26.7.8", Latest: "26.7.9", UpdateAvailable: true, URL: ce267,
					Detail: "announced in the changelog, not offered by the last check",
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := &firewall{t: t, status: fixture(t, tt.fixture)}
			srv := httptest.NewServer(fw)
			defer srv.Close()
			s := newSource(t, srv.URL, tt.now, tt.change)
			got, err := s.Fetch(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			same(t, got, tt.want)
			// Check is off: one read, and nothing that makes the firewall contact its mirror.
			if calls := strings.Join(fw.calls, ", "); calls != "GET status" {
				t.Errorf("calls = %s, want only GET status", calls)
			}
			if j, _ := json.Marshal(got); strings.Contains(string(j), testKey) || strings.Contains(string(j), testSecret) {
				t.Error("the report contains the API key")
			}
		})
	}
}

// TestCheck covers when the source asks the firewall to check again.
func TestCheck(t *testing.T) {
	const now = "2026-11-18T09:00:00Z"
	tests := []struct {
		name       string
		check      bool
		before     string // the status when Fetch starts
		checkTakes int
		checkWait  string
		busy       bool
		wantCalls  string
		wantPkgs   int    // pending packages in the report, -1 for no Packages at all
		wantDetail string // of the firmware
		wantErrors string // every problem, joined by " | "
	}{
		{
			name: "check is off: an old check is reported, not renewed", before: "status-none-old.json",
			wantCalls: "GET status", wantDetail: "last checked 9 days ago",
		},
		{
			name: "check is on and the last check is 7 hours old: left alone", check: true, before: "status-none.json",
			wantCalls: "GET status",
		},
		{
			name: "check is on and the last check is old: asked, waited for, reported", check: true, before: "status-none-old.json", checkTakes: 3,
			wantCalls: "GET status, GET running, POST check, GET status, GET status, GET status",
			wantPkgs:  7, wantDetail: "7 packages",
		},
		{
			name: "check is on and the firewall never checked", check: true, before: "status-unchecked.json", checkTakes: 1,
			wantCalls: "GET status, GET running, POST check, GET status",
			wantPkgs:  7, wantDetail: "7 packages",
		},
		{
			name: "the firewall is busy with something else: not asked", check: true, before: "status-none-old.json", busy: true,
			wantCalls: "GET status, GET running", wantDetail: "last checked 9 days ago",
			wantErrors: "the firewall is busy with another firmware action, so no check was asked for",
		},
		{
			// For an agent that runs once from cron and cannot sit and wait.
			name: "check_wait 0: asked, and left for the next report", check: true, before: "status-none-old.json", checkWait: "0",
			wantCalls: "GET status, GET running, POST check", wantDetail: "last checked 9 days ago",
			wantErrors: "a check was asked for; its result will be in the next report",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := &firewall{
				t: t, busy: tt.busy, status: fixture(t, tt.before),
				afterCheck: fixture(t, "status-update.json"), checkTakes: tt.checkTakes,
			}
			srv := httptest.NewServer(fw)
			defer srv.Close()
			s := newSource(t, srv.URL, now, func(c *Config) { c.Check, c.CheckWait = tt.check, tt.checkWait })
			got, err := s.Fetch(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if calls := strings.Join(fw.calls, ", "); calls != tt.wantCalls {
				t.Errorf("calls = %s\n       want %s", calls, tt.wantCalls)
			}
			pkgs := -1
			if got.Packages != nil {
				pkgs = got.Packages.Pending
			}
			if pkgs != tt.wantPkgs {
				t.Errorf("pending packages = %d, want %d", pkgs, tt.wantPkgs)
			}
			if d := got.Software[0].Detail; d != tt.wantDetail {
				t.Errorf("firmware detail = %q, want %q", d, tt.wantDetail)
			}
			var problems []string
			for _, p := range got.Errors {
				problems = append(problems, p.Message)
			}
			if e := strings.Join(problems, " | "); e != tt.wantErrors {
				t.Errorf("errors = %s\n        want %s", e, tt.wantErrors)
			}
		})
	}
}

// A check that never gives a result must not be asked for again on every poll: each one makes
// the firewall contact its mirror.
func TestCheckIsNotRepeated(t *testing.T) {
	fw := &firewall{t: t, status: fixture(t, "status-none-old.json"), checkTakes: -1}
	srv := httptest.NewServer(fw)
	defer srv.Close()
	clock := at("2026-11-18T09:00:00Z")
	s := newSource(t, srv.URL, "", func(c *Config) { c.Check = true; c.CheckWait = "20ms" })
	s.now = func() time.Time { return clock }

	fetch := func() string {
		t.Helper()
		got, err := s.Fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var problems []string
		for _, p := range got.Errors {
			problems = append(problems, p.Message)
		}
		return strings.Join(problems, " | ")
	}

	if got, want := fetch(), "a check was asked for and gave no result within 20ms"; got != want {
		t.Errorf("first fetch: errors = %s\nwant %s", got, want)
	}
	if n := fw.count("POST check"); n != 1 {
		t.Fatalf("checks asked for = %d, want 1", n)
	}

	// The check that died took the old result with it: the firewall is back to "not checked".
	fw.mu.Lock()
	fw.checking, fw.status = false, fixture(t, "status-unchecked.json")
	fw.mu.Unlock()
	clock = clock.Add(5 * time.Minute)
	never := "the firewall has not checked for updates since it started or was last updated"
	if got, want := fetch(), never+" | a check asked for at 2026-11-18 09:00 UTC has given no result"; got != want {
		t.Errorf("second fetch: errors = %s\nwant %s", got, want)
	}
	clock = clock.Add(11 * time.Hour)
	fetch()
	if n := fw.count("POST check"); n != 1 {
		t.Errorf("checks asked for within 12 hours = %d, want 1", n)
	}

	clock = clock.Add(time.Hour)
	fetch()
	fw.mu.Lock()
	fw.checking = false
	fw.mu.Unlock()
	if n := fw.count("POST check"); n != 2 {
		t.Errorf("checks asked for after 12 hours = %d, want 2", n)
	}
}

func TestFetchErrors(t *testing.T) {
	const now = "2026-11-18T09:00:00Z"
	status := fixture(t, "status-none.json")
	tests := []struct {
		name    string
		handler http.Handler              // nil for the firewall
		setup   func(*firewall)           // adjusts the firewall
		change  func(*testing.T, *Config) // adjusts the configuration
		want    string                    // must be in the error
		is      error                     // must match errors.Is, when set
	}{
		{
			name:   "a wrong key gets 401",
			change: func(t *testing.T, c *Config) { c.KeyFile = keyFile(t, testKey, "not-the-secret") },
			want:   "opnsense opnsense01: reading the firmware status: the firewall did not accept the API key (HTTP 401 Unauthorized)",
		},
		{
			name:  "a key without the firmware privilege gets 403",
			setup: func(f *firewall) { f.forbidden = true },
			want:  `the user of the API key lacks the privilege "System: Firmware" (HTTP 403 Forbidden)`,
		},
		{
			name: "the firewall does not answer in time",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done() // until the client gives up
			}),
			change: func(_ *testing.T, c *Config) { c.Timeout = "50ms" },
			want:   "reading the firmware status",
			is:     context.DeadlineExceeded,
		},
		{
			name: "the answer stops half way",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(status[:len(status)/2])
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}),
			change: func(_ *testing.T, c *Config) { c.Timeout = "50ms" },
			want:   "reading the firmware status",
			is:     context.DeadlineExceeded,
		},
		{
			name: "something that is not the API answers",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "<!doctype html><html><body>Login</body></html>")
			}),
			want: "the answer is not the expected JSON",
		},
		{
			// The login page of the web interface is where a wrong URL usually ends up.
			name: "a redirect is not followed",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
			}),
			want: "HTTP 302 Found",
		},
		{
			// FirmwareController::statusAction when product.php gives nothing.
			name: "the firewall cannot read its own firmware data",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"status_msg":"Firmware status check was aborted internally. Please try again.","status":"error"}`)
			}),
			want: "the firewall has no firmware data: Firmware status check was aborted internally. Please try again.",
		},
		{
			name:   "the key file is missing",
			change: func(_ *testing.T, c *Config) { c.KeyFile = filepath.Join(filepath.Dir(c.KeyFile), "gone.txt") },
			want:   "opnsense opnsense01: reading the API key: open ",
			is:     os.ErrNotExist,
		},
		{
			name: "the key file has no secret",
			change: func(t *testing.T, c *Config) {
				c.KeyFile = filepath.Join(t.TempDir(), "key")
				os.WriteFile(c.KeyFile, []byte(testKey+"\n"), 0o600)
			},
			want: "has no key= and secret= lines, and secret_file is not set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := &firewall{t: t, status: status}
			if tt.setup != nil {
				tt.setup(fw)
			}
			var h http.Handler = fw
			if tt.handler != nil {
				h = tt.handler
			}
			srv := httptest.NewServer(h)
			defer srv.Close()
			s := newSource(t, srv.URL, now, func(c *Config) {
				if tt.change != nil {
					tt.change(t, c)
				}
			})
			got, err := s.Fetch(context.Background())
			if err == nil {
				t.Fatalf("no error, report %+v", got)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v\nwant it to contain %q", err, tt.want)
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("error = %v, want errors.Is %v", err, tt.is)
			}
			for _, secret := range []string{testKey, testSecret, "not-the-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error contains a secret: %v", err)
				}
			}
		})
	}
}

// The key can also come as two files with nothing but the key and the secret in them.
func TestKeyAndSecretFiles(t *testing.T) {
	fw := &firewall{t: t, status: fixture(t, "status-none.json")}
	srv := httptest.NewServer(fw)
	defer srv.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "key"), []byte(testKey+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "secret"), []byte(testSecret+"\n"), 0o600)
	s := newSource(t, srv.URL, "2026-11-18T09:00:00Z", func(c *Config) {
		c.KeyFile, c.SecretFile = filepath.Join(dir, "key"), filepath.Join(dir, "secret")
	})
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCertificate(t *testing.T) {
	fw := &firewall{t: t, status: fixture(t, "status-none.json")}
	srv := httptest.NewUnstartedServer(fw)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // refused handshakes are the point here
	srv.StartTLS()                                   // its certificate is for 127.0.0.1 and example.com, from a CA nobody trusts
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "firewall.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	notPEM := filepath.Join(t.TempDir(), "empty.pem")
	os.WriteFile(notPEM, []byte("not a certificate\n"), 0o600)

	tests := []struct {
		name    string
		change  func(*Config)
		wantErr string // "" for success
		newErr  string // New itself fails with this
	}{
		{name: "a certificate that does not verify is refused", wantErr: "certificate"},
		{name: "ca_file trusts the firewall's own certificate", change: func(c *Config) { c.CAFile = caFile }},
		{name: "tls_skip_verify accepts anything", change: func(c *Config) { c.TLSSkipVerify = true }},
		{
			name:   "tls_server_name says which name the certificate must have",
			change: func(c *Config) { c.CAFile, c.TLSServerName = caFile, "example.com" },
		},
		{
			name:    "a certificate for another name is refused",
			change:  func(c *Config) { c.CAFile, c.TLSServerName = caFile, "fw.other.example" },
			wantErr: "certificate",
		},
		{name: "ca_file without a certificate in it", change: func(c *Config) { c.CAFile = notPEM }, newErr: "no PEM certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw.calls = nil
			cfg := Config{Name: "opnsense01", URL: srv.URL, KeyFile: keyFile(t, testKey, testSecret), Timezone: "Europe/Zagreb"}
			if tt.change != nil {
				tt.change(&cfg)
			}
			src, err := New(cfg)
			if tt.newErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.newErr) {
					t.Fatalf("New: error = %v, want %q", err, tt.newErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			src.(*source).now = func() time.Time { return at("2026-11-18T09:00:00Z") }
			_, err = src.Fetch(context.Background())
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatal(err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			case tt.wantErr != "":
				var unknown x509.UnknownAuthorityError
				var name x509.HostnameError
				if !errors.As(err, &unknown) && !errors.As(err, &name) {
					t.Errorf("error = %v, want a certificate verification error", err)
				}
				if len(fw.calls) != 0 {
					t.Errorf("the key was sent to a firewall whose certificate did not verify: %v", fw.calls)
				}
			}
		})
	}
}

func TestNew(t *testing.T) {
	ok := Config{Name: "opnsense01", URL: "https://10.0.0.1", KeyFile: "/etc/upkeep/opnsense01.key"}
	tests := []struct {
		name    string
		change  func(*Config)
		wantErr string
	}{
		{name: "the least there is"},
		{name: "everything", change: func(c *Config) {
			c.SecretFile, c.TLSServerName, c.TLSSkipVerify = "/etc/upkeep/s", "fw.example.net", true
			c.Timeout, c.Check, c.CheckEvery, c.CheckWait, c.Timezone = "30s", true, "24h", "5m", "Europe/Zagreb"
		}},
		{name: "no name", change: func(c *Config) { c.Name = " " }, wantErr: "opnsense: name is missing"},
		{name: "no url", change: func(c *Config) { c.URL = "" }, wantErr: `opnsense opnsense01: url must start with "https://" or "http://"`},
		{name: "no key file", change: func(c *Config) { c.KeyFile = "" }, wantErr: "key_file is missing"},
		{
			// A key with a slash in it does not even parse as a user: it becomes host and path.
			name:    "a key in the url",
			change:  func(c *Config) { c.URL = "https://" + testKey + ":" + testSecret + "@10.0.0.1" },
			wantErr: "url must not contain a user or password",
		},
		{name: "a user in the url", change: func(c *Config) { c.URL = "https://upkeep:hunter2@10.0.0.1" }, wantErr: "url must not contain a user or password"},
		{name: "a url that does not parse", change: func(c *Config) { c.URL = "https://10.0.0.1/pa%ss" }, wantErr: "url is not a valid URL"},
		{name: "a timeout that is no duration", change: func(c *Config) { c.Timeout = "15" }, wantErr: `timeout: "15" is not a duration`},
		{name: "no timeout at all", change: func(c *Config) { c.Timeout = "0s" }, wantErr: "timeout must not be 0"},
		{
			name:    "checking more than twice a day",
			change:  func(c *Config) { c.Check, c.CheckEvery = true, "1h" },
			wantErr: "check_every must be at least 12h0m0s",
		},
		{name: "a time zone nobody knows", change: func(c *Config) { c.Timezone = "Europe/Atlantis" }, wantErr: "timezone: "},
		{name: "a ca_file that is not there", change: func(c *Config) { c.CAFile = "/nonexistent/ca.pem" }, wantErr: "reading the certificates to trust"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ok
			if tt.change != nil {
				tt.change(&cfg)
			}
			src, err := New(cfg)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatal(err)
			case tt.wantErr == "":
				if src.Name() != "opnsense01" {
					t.Errorf("Name() = %q", src.Name())
				}
			case err == nil || !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			case strings.Contains(err.Error(), testSecret) || strings.Contains(err.Error(), "pa%ss") || strings.Contains(err.Error(), "hunter2"):
				t.Errorf("the error contains a secret: %v", err)
			}
		})
	}
}

// The firewall writes the time of its check as date(1) prints it, in its own time zone.
func TestCheckedAt(t *testing.T) {
	zagreb, _ := time.LoadLocation("Europe/Zagreb")
	chicago, _ := time.LoadLocation("America/Chicago")
	tests := []struct {
		in    string
		loc   *time.Location
		want  string // UTC, "" when it cannot be read
		exact bool
	}{
		{"Wed Nov 18 03:17:42 CET 2026", zagreb, "2026-11-18T02:17:42Z", true},
		{"Mon Nov  9 03:02:11 CET 2026", zagreb, "2026-11-09T02:02:11Z", true}, // date pads the day with a space
		{"Wed Jul  1 03:17:42 CEST 2026", zagreb, "2026-07-01T01:17:42Z", true},
		{"Wed Nov 18 03:17:42 UTC 2026", zagreb, "2026-11-18T03:17:42Z", true},
		// A server whose own clock is on UTC still reads a common zone name right.
		{"Wed Nov 18 03:17:42 CET 2026", time.UTC, "2026-11-18T02:17:42Z", true},
		{"Wed Nov 18 03:17:42 EST 2026", zagreb, "2026-11-18T08:17:42Z", true},
		// CST is Chicago, Havana or Shanghai: only the configured zone can tell.
		{"Wed Nov 18 03:17:42 CST 2026", chicago, "2026-11-18T09:17:42Z", true},
		{"Wed Nov 18 03:17:42 CST 2026", zagreb, "2026-11-18T02:17:42Z", false},
		// Zones without a name are printed as an offset.
		{"Wed Nov 18 03:17:42 +01 2026", time.UTC, "2026-11-18T02:17:42Z", true},
		{"Wed Nov 18 03:17:42 -0330 2026", time.UTC, "2026-11-18T06:47:42Z", true},
		{"unknown", zagreb, "", false}, // check.sh's value before it has run date
		{"", zagreb, "", false},
		{"Wed Nov 31 03:17:42 CET 2026", zagreb, "", false},
	}
	for _, tt := range tests {
		got, ok := (&status{LastCheck: tt.in}).checkedAt(tt.loc)
		if !ok {
			if tt.want != "" {
				t.Errorf("%q: not read, want %s", tt.in, tt.want)
			}
			continue
		}
		if g := got.t.Format(time.RFC3339); g != tt.want || got.exact != tt.exact {
			t.Errorf("%q in %s = %s (exact %v), want %s (exact %v)", tt.in, tt.loc, g, got.exact, tt.want, tt.exact)
		}
	}
}

// A time zone name that cannot be placed is said, with what to do about it.
func TestUnknownTimeZoneIsAProblem(t *testing.T) {
	body := strings.ReplaceAll(string(fixture(t, "status-none.json")), "03:17:42 CET 2026", "03:17:42 XYZT 2026")
	srv := httptest.NewServer(&firewall{t: t, status: []byte(body)})
	defer srv.Close()
	got, err := newSource(t, srv.URL, "2026-11-18T09:00:00Z", nil).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := `cannot place the time zone of the firewall's last update check "Wed Nov 18 03:17:42 XYZT 2026": set timezone for this source`
	if len(got.Errors) != 1 || got.Errors[0].Message != want {
		t.Errorf("errors = %+v\nwant %s", got.Errors, want)
	}
}

// A development build is not in the changelog: what the changelog calls newest says nothing.
func TestDevelopmentBuild(t *testing.T) {
	body := strings.ReplaceAll(string(fixture(t, "status-none-changelog-newer.json")), `"product_id":"opnsense"`, `"product_id":"opnsense-devel"`)
	srv := httptest.NewServer(&firewall{t: t, status: []byte(body)})
	defer srv.Close()
	got, err := newSource(t, srv.URL, "2026-11-18T09:00:00Z", nil).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fw := got.Software[0]; fw.UpdateAvailable || fw.Latest != "26.7.8" || fw.Detail != "" {
		t.Errorf("firmware = %+v, want no update from the changelog", fw)
	}
}

// A firewall on a patched first release of a series ("26.10.0p1") reports product_latest
// "26.10.0": the release it already runs, not a newer one. Seen on a business edition firewall.
func TestPatchedReleaseIsNotAnnounced(t *testing.T) {
	for _, tt := range []struct {
		latest string
		want   bool
	}{
		{"26.10.0", false},
		{"26.10.1", true},
	} {
		body := string(fixture(t, "status-none-changelog-newer.json"))
		body = strings.ReplaceAll(body, `"product_version":"26.7.8"`, `"product_version":"26.10.0p1"`)
		body = strings.ReplaceAll(body, `"product_latest":"26.7.9"`, `"product_latest":"`+tt.latest+`"`)
		if !strings.Contains(body, `"product_version":"26.10.0p1"`) || !strings.Contains(body, `"product_latest":"`+tt.latest+`"`) {
			t.Fatal("the fixture no longer has the fields this test rewrites")
		}
		srv := httptest.NewServer(&firewall{t: t, status: []byte(body)})
		got, err := newSource(t, srv.URL, "2026-11-18T09:00:00Z", nil).Fetch(context.Background())
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		fw := got.Software[0]
		if fw.UpdateAvailable != tt.want {
			t.Errorf("installed 26.10.0p1, product_latest %s: UpdateAvailable = %v, want %v (%+v)", tt.latest, fw.UpdateAvailable, tt.want, fw)
		}
		if !tt.want && (fw.Latest != "26.10.0p1" || fw.Detail != "") {
			t.Errorf("installed 26.10.0p1, product_latest %s: firmware = %+v, want the installed version and no detail", tt.latest, fw)
		}
	}
}

func TestRelease(t *testing.T) {
	// The left side is what "opnsense-version -v" prints, the right what latest.php makes of it.
	for in, want := range map[string]string{
		"26.7.8": "26.7.8", "26.7.8_4": "26.7.8", "26.10": "26.10", "26.10_2": "26.10", "26.7.10": "26.7.10", "27.1.r1": "27.1.r1",
		"26.10.0": "26.10", "26.10.0p1": "26.10", "26.10.1": "26.10.1",
	} {
		if got := release(in); got != want {
			t.Errorf("release(%q) = %q, want %q", in, got, want)
		}
	}
}

// The package list of one report is capped; the count is not.
func TestManyPackages(t *testing.T) {
	st := status{Status: "update", LastCheck: "Wed Nov 18 03:17:42 CET 2026", Product: &product{Name: "OPNsense", Version: "26.7.8"}}
	for i := 0; i < report.MaxItems+50; i++ {
		st.Upgrade = append(st.Upgrade, pkg{Name: fmt.Sprintf("py313-package%03d", i), Current: "1", New: "2"})
	}
	body, _ := json.Marshal(struct {
		Status    string   `json:"status"`
		LastCheck string   `json:"last_check"`
		Upgrade   []pkg    `json:"upgrade_packages"`
		Product   *product `json:"product"`
	}{st.Status, st.LastCheck, st.Upgrade, st.Product})
	srv := httptest.NewServer(&firewall{t: t, status: body})
	defer srv.Close()
	got, err := newSource(t, srv.URL, "2026-11-18T09:00:00Z", nil).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Packages.Pending != report.MaxItems+50 || len(got.Packages.Items) != report.MaxItems {
		t.Errorf("pending %d, items %d; want %d and %d", got.Packages.Pending, len(got.Packages.Items), report.MaxItems+50, report.MaxItems)
	}
}

// The configuration as the owner writes it, and the source as an agent on the firewall uses it.
func TestConfigFromTOML(t *testing.T) {
	fw := &firewall{t: t, status: fixture(t, "status-be-reboot.json")}
	srv := httptest.NewServer(fw)
	defer srv.Close()
	doc := `
[[opnsense]]
name = "opnsense02"
url = "` + srv.URL + `"
key_file = "` + keyFile(t, testKey, testSecret) + `"
ca_file = ""
tls_server_name = "opnsense02.example.net"
tls_skip_verify = false
timeout = "10s"
check = false
check_every = "24h"
check_wait = "3m"
timezone = "Europe/Zagreb"
`
	var conf struct {
		OPNsense []Config `toml:"opnsense"`
	}
	dec := toml.NewDecoder(strings.NewReader(doc))
	dec.DisallowUnknownFields() // a setting the struct does not have is a test failure
	if err := dec.Decode(&conf); err != nil {
		t.Fatal(err)
	}
	if len(conf.OPNsense) != 1 {
		t.Fatalf("tables = %d", len(conf.OPNsense))
	}
	src, err := New(conf.OPNsense[0])
	if err != nil {
		t.Fatal(err)
	}
	s := src.(*source)
	if s.timeout != 10*time.Second || s.checkEvery != 24*time.Hour || s.checkWait != 3*time.Minute || s.check {
		t.Errorf("settings not taken over: %+v", s)
	}

	// An agent merges what the source finds into its own report and keeps its own identity.
	r := &report.Report{Schema: report.Schema, System: report.System{Name: "opnsense02", Kind: "freebsd", Source: "agent"}}
	c := connect.AsCollector(src)
	if err := c.Collect(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if c.Name() != "opnsense02" || r.System.Kind != "freebsd" || r.Packages == nil || r.Packages.Pending != 7 || len(r.Software) != 2 {
		t.Errorf("merged report: %+v", r)
	}
}
