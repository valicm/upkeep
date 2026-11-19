package homeassistant

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/valicm/upkeep/internal/connect"
	"github.com/valicm/upkeep/internal/report"
)

// Where the test data comes from is written down in testdata/SOURCES.txt. In short: config.json,
// states-container.json, states-first-start.json, states-installing.json, states-backup-ok.json
// and unauthorized.txt were captured from a running Home Assistant 2026.11.2; the *-haos files
// are built by hand in the captured shape, because a container has no Supervisor.

const testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaXh0dXJlIn0.c2lnbmF0dXJl"

// hass is a Home Assistant that only has the two calls the source makes. prefix is "/core" when
// it plays the Supervisor's proxy.
type hass struct {
	t      *testing.T
	prefix string
	config []byte
	states []byte
	calls  []string
}

func (h *hass) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		// Status, headers and body as captured for a wrong token and for none.
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="http://127.0.0.1:8123/.well-known/oauth-protected-resource"`)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(fixture(h.t, "unauthorized.txt"))
		return
	}
	if r.Method != http.MethodGet {
		h.t.Errorf("%s %s: the source only reads", r.Method, r.URL.Path)
	}
	h.calls = append(h.calls, r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case h.prefix + "/api/config":
		w.Write(h.config)
	case h.prefix + "/api/states":
		w.Write(h.states)
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "404: Not Found")
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "homeassistant.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
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

func newSource(t *testing.T, url string, change func(*Config)) *source {
	t.Helper()
	cfg := Config{Name: "homeassistant", URL: url, TokenFile: tokenFile(t, testToken)}
	if change != nil {
		change(&cfg)
	}
	src, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := src.(*source)
	s.now = func() time.Time { return at("2026-11-19T00:00:00Z") }
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

const (
	noSupervisor = "no update entity for Core: this installation has no Supervisor"
	demoRelease  = "https://www.example.com/release/"
)

func TestFetch(t *testing.T) {
	container := report.System{Name: "homeassistant", Kind: "homeassistant", OS: "Home Assistant", OSVersion: "2026.11.2", Source: "connector"}
	coreOnly := report.Software{Name: "Home Assistant Core", Kind: "core", Installed: "2026.11.2", Detail: noSupervisor}
	// What the demo integration's six entities look like when nothing was done to them.
	demo := func(addOn, progress report.Software) []report.Software {
		return []report.Software{
			coreOnly,
			{Name: "AdGuard Home", Kind: "app", Installed: "1.0.0", Latest: "1.0.0"},
			addOn,
			{Name: "Demo Update No Install", Installed: "1.0.0", Latest: "1.0.1", UpdateAvailable: true, URL: demoRelease + "1.0.1"},
			{Name: "Demo Living Room Bulb", Kind: "firmware", Installed: "1.93.3", Latest: "1.94.2", UpdateAvailable: true, URL: demoRelease + "1.93.3"},
			{Name: "Demo Update with Decimal Progress", Kind: "firmware", Installed: "1.93.3", Latest: "1.94.2", UpdateAvailable: true, URL: demoRelease + "1.93.3"},
			progress,
		}
	}
	addOnWaiting := report.Software{Name: "AdGuard Home", Kind: "app", Installed: "1.0.0", Latest: "1.0.1", UpdateAvailable: true, URL: demoRelease + "1.0.1"}
	addOnSkipped := report.Software{Name: "AdGuard Home", Kind: "app", Installed: "1.0.0", Latest: "1.0.1", URL: demoRelease + "1.0.1", Detail: "1.0.1 skipped in Home Assistant"}
	progressIdle := report.Software{Name: "Demo Update with Progress", Kind: "firmware", Installed: "1.93.3", Latest: "1.94.2", UpdateAvailable: true, URL: demoRelease + "1.93.3"}
	// The same entity once the installation, started for the capture before, had finished.
	progressDone := report.Software{Name: "Demo Update with Progress", Kind: "firmware", Installed: "1.94.2", Latest: "1.94.2", URL: demoRelease + "1.93.3"}

	tests := []struct {
		name   string
		config string
		states string
		change func(*Config)
		want   report.Report
	}{
		{
			// Home Assistant OS: the Supervisor's entities, apps, an integration from HACS,
			// other software, device firmware, and backups on two days of the week.
			name: "Home Assistant OS with updates waiting", config: "config-haos.json", states: "states-haos.json",
			want: report.Report{
				System: report.System{Name: "homeassistant", Kind: "homeassistant", OS: "Home Assistant OS", OSVersion: "18.4", Source: "connector"},
				Software: []report.Software{
					{Name: "Home Assistant Core", Kind: "core", Installed: "2026.11.1", Latest: "2026.11.2", UpdateAvailable: true, URL: "https://www.home-assistant.io/latest-release-notes/"},
					{
						Name: "Home Assistant Operating System", Kind: "os", Installed: "18.4", Latest: "18.5", UpdateAvailable: true,
						URL: "https://github.com/home-assistant/operating-system/releases/tag/18.5", Detail: "the update needs a reboot",
					},
					{
						Name: "Home Assistant Supervisor", Kind: "supervisor", Installed: "2026.11.0", Latest: "2026.11.0",
						URL: "https://github.com/home-assistant/supervisor/releases/tag/2026.11.0", Detail: "updates by itself",
					},
					{Name: "ESPHome Device Builder", Kind: "app", Installed: "2026.10.3", Latest: "2026.11.0", Detail: "2026.11.0 skipped in Home Assistant"},
					{Name: "Mosquitto broker", Kind: "app", Installed: "6.5.2", Latest: "6.5.2"},
					{Name: "upkeep agent", Kind: "app", Installed: "0.3.0", Latest: "0.3.0"}, // an app without an icon
					{Name: "Zigbee2MQTT", Kind: "app", Installed: "2.6.3-1", Latest: "2.7.0-1", UpdateAvailable: true},
					{
						Name: "Adaptive Lighting", Kind: "integration", Installed: "1.25.0", Latest: "1.26.0", UpdateAvailable: true,
						URL: "https://github.com/basnijholt/adaptive-lighting/releases/1.26.0",
					},
					{
						Name: "uptime.example.net Uptime Kuma version", Installed: "2.0.2", Latest: "2.1.0", UpdateAvailable: true,
						URL: "https://github.com/louislam/uptime-kuma/releases/tag/2.1.0",
					},
					// Every ESPHome device has the title "ESPHome": the entity's name tells them apart.
					{Name: "Bedroom sensor Firmware", Kind: "firmware", Installed: "2026.10.3", Latest: "2026.11.0", UpdateAvailable: true, URL: "https://esphome.io/changelog/"},
					{Name: "Hallway sensor Firmware", Kind: "firmware", Installed: "2026.11.0", Latest: "2026.11.0", URL: "https://esphome.io/changelog/"},
				},
				Backups: []report.Backup{{
					Name: "homeassistant automatic backup", Kind: "homeassistant",
					LastSuccess: at("2026-11-16T04:52:13Z"), LastRun: at("2026-11-16T04:45:41Z"), LastResult: "ok",
					MaxAgeHours: 75, // Monday to Thursday is 72 hours and a bit, plus two
					Detail:      "419 MiB, next 2026-11-19 05:12 UTC",
				}},
			},
		},
		{
			// The whole answer of a real instance, all 124 entities: an update skipped, a device
			// that is offline, a version nobody knows, and an automatic backup that failed.
			name: "a container installation", config: "config.json", states: "states-container.json",
			want: report.Report{
				System: container,
				Software: append(demo(addOnSkipped, progressIdle)[:4:4],
					report.Software{Name: "Fixture version unknown", Installed: "2.3.1", Detail: "Home Assistant does not know whether there is an update"},
					report.Software{Name: "Demo Living Room Bulb", Kind: "firmware", Installed: "1.93.3", Latest: "1.94.2", UpdateAvailable: true, URL: demoRelease + "1.93.3"},
					report.Software{Name: "Demo Update with Decimal Progress", Kind: "firmware", Installed: "1.93.3", Latest: "1.94.2", UpdateAvailable: true, URL: demoRelease + "1.93.3"},
					progressIdle,
					report.Software{Name: "Fixture offline plug firmware", Kind: "firmware", Detail: "unavailable in Home Assistant"},
				),
				Backups: []report.Backup{{
					Name: "homeassistant automatic backup", Kind: "homeassistant",
					LastSuccess: at("2026-11-18T23:46:26Z"), LastRun: at("2026-11-18T23:46:46Z"), LastResult: "failed",
					Detail: "backup manager error, next 2026-11-19 05:29 UTC",
				}},
			},
		},
		{
			name: "just installed: updates wait, no backup has run", config: "config.json", states: "states-first-start.json",
			want: report.Report{
				System:   container,
				Software: demo(addOnWaiting, progressIdle),
				Backups: []report.Backup{{
					Name: "homeassistant automatic backup", Kind: "homeassistant", LastResult: "unknown",
					Detail: "no automatic backup has run, none scheduled",
				}},
			},
		},
		{
			name: "an update is being installed and one was skipped", config: "config.json", states: "states-installing.json",
			want: report.Report{
				System: container,
				Software: demo(addOnSkipped, report.Software{
					Name: "Demo Update with Progress", Kind: "firmware", Installed: "1.93.3", Latest: "1.94.2", UpdateAvailable: true,
					URL: demoRelease + "1.93.3", Detail: "installing 40%",
				}),
				Backups: []report.Backup{{
					Name: "homeassistant automatic backup", Kind: "homeassistant", LastResult: "unknown",
					Detail: "no automatic backup has run, none scheduled",
				}},
			},
		},
		{
			name: "the automatic backup worked", config: "config.json", states: "states-backup-ok.json",
			want: report.Report{
				System:   container,
				Software: demo(addOnSkipped, progressDone),
				Backups: []report.Backup{{
					Name: "homeassistant automatic backup", Kind: "homeassistant",
					LastSuccess: at("2026-11-18T23:46:26Z"), LastRun: at("2026-11-18T23:46:26Z"), LastResult: "ok",
					Detail: "0.02 MiB, next 2026-11-19 05:43 UTC",
				}},
			},
		},
		{
			name: "an automatic backup is running", config: "config-haos.json", states: "states-haos-backup-running.json",
			want: report.Report{
				System:   report.System{Name: "homeassistant", Kind: "homeassistant", OS: "Home Assistant", OSVersion: "2026.11.1", Source: "connector"},
				Software: []report.Software{{Name: "Home Assistant Core", Kind: "core", Installed: "2026.11.1", Detail: noSupervisor}},
				Backups: []report.Backup{{
					Name: "homeassistant automatic backup", Kind: "homeassistant",
					LastSuccess: at("2026-11-16T04:52:13Z"), LastRun: at("2026-11-19T05:12:07Z"), LastResult: "running",
					MaxAgeHours: 98, // Thursday to Monday
					Detail:      "next 2026-11-23 04:58 UTC",
				}},
			},
		},
		{
			name: "ignore_backups leaves the backup out", config: "config.json", states: "states-backup-ok.json",
			change: func(c *Config) { c.IgnoreBackups = true },
			want:   report.Report{System: container, Software: demo(addOnSkipped, progressDone)},
		},
		{
			name: "Home Assistant is still starting", config: "config-starting.json", states: "states-backup-ok.json",
			change: func(c *Config) { c.IgnoreBackups = true },
			want: report.Report{
				System: container, Software: demo(addOnSkipped, progressDone),
				Errors: []report.Problem{{Collector: "homeassistant", Message: "Home Assistant is not fully started (state STARTING): entities may be missing"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &hass{t: t, config: fixture(t, tt.config), states: fixture(t, tt.states)}
			srv := httptest.NewServer(h)
			defer srv.Close()
			got, err := newSource(t, srv.URL, tt.change).Fetch(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			same(t, got, tt.want)
			if calls := strings.Join(h.calls, " "); calls != "/api/config /api/states" {
				t.Errorf("calls = %s", calls)
			}
			if j, _ := json.Marshal(got); strings.Contains(string(j), testToken) {
				t.Error("the report contains the token")
			}
		})
	}
}

// An installation without the backup integration's sensors has no Backup: not looked at is
// not the same as never ran.
func TestNoBackupSensors(t *testing.T) {
	var all, kept []json.RawMessage
	if err := json.Unmarshal(fixture(t, "states-container.json"), &all); err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if !strings.Contains(string(e), `"entity_id":"sensor.backup_`) && !strings.Contains(string(e), `"entity_id":"event.backup_`) {
			kept = append(kept, e)
		}
	}
	states, _ := json.Marshal(kept)
	srv := httptest.NewServer(&hass{t: t, config: fixture(t, "config.json"), states: states})
	defer srv.Close()
	got, err := newSource(t, srv.URL, nil).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Backups != nil || len(got.Software) != 9 {
		t.Errorf("backups = %+v, software entries = %d; want none and 9", got.Backups, len(got.Software))
	}
}

func TestFetchErrors(t *testing.T) {
	config, states := fixture(t, "config.json"), fixture(t, "states-container.json")
	stall := func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() } // until the client gives up
	// A handler that answers the configuration and leaves the entities to f.
	statesBy := func(f http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/config" {
				w.Write(config)
				return
			}
			f(w, r)
		})
	}
	tests := []struct {
		name    string
		handler http.Handler              // nil for Home Assistant
		change  func(*testing.T, *Config) // adjusts the configuration
		want    string                    // must be in the error
		is      error                     // must match errors.Is, when set
	}{
		{
			name:   "a wrong token gets 401",
			change: func(t *testing.T, c *Config) { c.TokenFile = tokenFile(t, "not-the-token") },
			want:   "homeassistant homeassistant: reading the configuration: Home Assistant did not accept the access token (HTTP 401 Unauthorized)",
		},
		{
			name: "Home Assistant does not answer in time", handler: http.HandlerFunc(stall),
			change: func(_ *testing.T, c *Config) { c.Timeout = "50ms" },
			want:   "reading the configuration: no answer within 50ms", is: context.DeadlineExceeded,
		},
		{
			name: "the list of entities stops half way",
			handler: statesBy(func(w http.ResponseWriter, r *http.Request) {
				w.Write(states[:len(states)/2])
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}),
			change: func(_ *testing.T, c *Config) { c.Timeout = "50ms" },
			want:   "reading the entities: the answer was not complete within 50ms: reading the answer", is: context.DeadlineExceeded,
		},
		{
			name: "the list of entities is cut off",
			handler: statesBy(func(w http.ResponseWriter, r *http.Request) {
				w.Write(states[:len(states)/2])
			}),
			want: "reading the entities: reading the answer", is: io.ErrUnexpectedEOF,
		},
		{
			name: "something that is not Home Assistant answers",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "<!doctype html><html><body>It works!</body></html>")
			}),
			want: "reading the configuration: the answer is not the expected JSON",
		},
		{
			name: "the entities are not a list",
			handler: statesBy(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"message":"API running."}`)
			}),
			want: "reading the entities: reading the answer: not a list of entities",
		},
		{
			// The address of something else, or of a reverse proxy with a prefix.
			name:   "the url is wrong",
			change: func(_ *testing.T, c *Config) { c.URL += "/hass" },
			want:   "reading the configuration: HTTP 404 Not Found",
		},
		{
			name:   "the token file is missing",
			change: func(_ *testing.T, c *Config) { c.TokenFile = filepath.Join(filepath.Dir(c.TokenFile), "gone") },
			want:   "homeassistant homeassistant: reading the access token: open ", is: os.ErrNotExist,
		},
		{
			name:   "the token file is empty",
			change: func(t *testing.T, c *Config) { c.TokenFile = tokenFile(t, " ") },
			want:   "homeassistant.token is empty",
		},
		{
			name:   "the token file has more than a token",
			change: func(t *testing.T, c *Config) { c.TokenFile = tokenFile(t, "token = \nnot-the-token") },
			want:   "homeassistant.token has more than one line",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h http.Handler = &hass{t: t, config: config, states: states}
			if tt.handler != nil {
				h = tt.handler
			}
			srv := httptest.NewServer(h)
			defer srv.Close()
			s := newSource(t, srv.URL, func(c *Config) {
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
			if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "not-the-token") {
				t.Errorf("the error contains a token: %v", err)
			}
		})
	}
}

func TestCertificate(t *testing.T) {
	h := &hass{t: t, config: fixture(t, "config.json"), states: fixture(t, "states-backup-ok.json")}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // refused handshakes are the point here
	srv.StartTLS()                                   // its certificate is for 127.0.0.1 and example.com, from a CA nobody trusts
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "homeassistant.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)

	tests := []struct {
		name    string
		change  func(*Config)
		wantErr bool
	}{
		{name: "a certificate that does not verify is refused", wantErr: true},
		{name: "ca_file trusts the certificate", change: func(c *Config) { c.CAFile = caFile }},
		{name: "tls_skip_verify accepts anything", change: func(c *Config) { c.TLSSkipVerify = true }},
		{name: "tls_server_name says which name to expect", change: func(c *Config) { c.CAFile, c.TLSServerName = caFile, "example.com" }},
		{name: "a certificate for another name is refused", change: func(c *Config) { c.CAFile, c.TLSServerName = caFile, "ha.other.example" }, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.calls = nil
			_, err := newSource(t, srv.URL, tt.change).Fetch(context.Background())
			if !tt.wantErr {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var unknown x509.UnknownAuthorityError
			var name x509.HostnameError
			if !errors.As(err, &unknown) && !errors.As(err, &name) {
				t.Errorf("error = %v, want a certificate verification error", err)
			}
			if len(h.calls) != 0 {
				t.Errorf("the token was sent to a server whose certificate did not verify: %v", h.calls)
			}
		})
	}
}

// An agent that runs as a Home Assistant app goes through the Supervisor with the token every
// app gets in its environment.
func TestSupervisor(t *testing.T) {
	h := &hass{t: t, prefix: "/core", config: fixture(t, "config-haos.json"), states: fixture(t, "states-haos.json")}
	srv := httptest.NewServer(h)
	defer srv.Close()
	env := map[string]string{"SUPERVISOR_TOKEN": testToken}

	src, err := New(Config{Name: "homeassistant", Supervisor: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := src.(*source).base.JoinPath("api", "states").String(); got != "http://supervisor/core/api/states" {
		t.Errorf("without a url the entities are read from %s, want http://supervisor/core/api/states", got)
	}

	// The proxy's name only resolves inside an app, so the test puts its own address there.
	src, err = New(Config{Name: "homeassistant", Supervisor: true, URL: srv.URL + "/core"})
	if err != nil {
		t.Fatal(err)
	}
	s := src.(*source)
	s.getenv = func(k string) string { return env[k] }
	got, err := s.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls := strings.Join(h.calls, " "); calls != "/core/api/config /core/api/states" {
		t.Errorf("calls = %s", calls)
	}
	if got.System.OS != "Home Assistant OS" || got.System.OSVersion != "18.4" || len(got.Software) != 11 || len(got.Backups) != 1 {
		t.Errorf("report: %+v", got)
	}

	// As an agent's collector the findings join the agent's own report.
	r := &report.Report{Schema: report.Schema, System: report.System{Name: "homeassistant", Kind: "linux", Source: "agent"}}
	if err := connect.AsCollector(src).Collect(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if r.System.Kind != "linux" || len(r.Software) != 11 || len(r.Backups) != 1 {
		t.Errorf("merged report: %+v", r)
	}

	tests := []struct {
		name string
		env  string
		want string
	}{
		{"outside an app there is no token", "", "reading the access token: SUPERVISOR_TOKEN is not set: supervisor = true only works inside a Home Assistant app"},
		{"an app without homeassistant_api is turned away", "token-of-an-app-without-access", `the Supervisor did not let the app through: does its config.yaml have "homeassistant_api: true"? (HTTP 401 Unauthorized)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env["SUPERVISOR_TOKEN"] = tt.env
			_, err := s.Fetch(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v\nwant %q", err, tt.want)
			}
			if err != nil && tt.env != "" && strings.Contains(err.Error(), tt.env) {
				t.Errorf("the error contains the token: %v", err)
			}
		})
	}
}

func TestNew(t *testing.T) {
	ok := Config{Name: "homeassistant", URL: "http://homeassistant.local:8123", TokenFile: "/etc/upkeep/homeassistant.token"}
	tests := []struct {
		name    string
		change  func(*Config)
		wantErr string
	}{
		{name: "the least there is"},
		{name: "everything", change: func(c *Config) {
			c.URL, c.TLSServerName, c.TLSSkipVerify, c.Timeout, c.IgnoreBackups = "https://10.0.0.5:8123", "ha.example.net", true, "45s", true
		}},
		{name: "as an app", change: func(c *Config) { *c = Config{Name: "homeassistant", Supervisor: true} }},
		{name: "no name", change: func(c *Config) { c.Name = "" }, wantErr: "homeassistant: name is missing"},
		{name: "no url", change: func(c *Config) { c.URL = "" }, wantErr: `homeassistant homeassistant: url must start with "https://" or "http://"`},
		{name: "no token file", change: func(c *Config) { c.TokenFile = "" }, wantErr: "token_file is missing (or set supervisor = true in an app)"},
		{name: "both ways in", change: func(c *Config) { c.Supervisor = true }, wantErr: "token_file and supervisor are two different ways in: set one"},
		{name: "a token in the url", change: func(c *Config) { c.URL = "http://" + testToken + "@homeassistant.local:8123" }, wantErr: "url must not contain a user or password"},
		{name: "a query in the url", change: func(c *Config) { c.URL += "/?token=" + testToken }, wantErr: "url must not have a query or fragment"},
		{name: "a timeout that is no duration", change: func(c *Config) { c.Timeout = "soon" }, wantErr: `timeout: "soon" is not a duration`},
		{name: "no timeout at all", change: func(c *Config) { c.Timeout = "0" }, wantErr: "timeout must not be 0"},
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
				if src.Name() != "homeassistant" {
					t.Errorf("Name() = %q", src.Name())
				}
			case err == nil || !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			case strings.Contains(err.Error(), testToken):
				t.Errorf("the error contains the token: %v", err)
			}
		})
	}
}

// What kind of thing an update entity is about has to be read from its attributes.
func TestKind(t *testing.T) {
	tests := []struct {
		name  string
		attrs string
		want  string
	}{
		{"Core, by the Supervisor's title", `{"title":"Home Assistant Core","entity_picture":"/api/brands/integration/homeassistant/icon.png?placeholder=no","supported_features":15}`, "core"},
		{"the operating system", `{"title":"Home Assistant Operating System","supported_features":27}`, "os"},
		{"the Supervisor", `{"title":"Home Assistant Supervisor","supported_features":5}`, "supervisor"},
		{"an app, by its icon", `{"title":"Mosquitto broker","entity_picture":"/api/hassio/addons/core_mosquitto/icon","supported_features":29}`, "app"},
		{"an app without an icon, by the backup it offers", `{"title":"upkeep agent","supported_features":29}`, "app"},
		{"device firmware, by its class", `{"title":"ESPHome","device_class":"firmware","supported_features":1}`, "firmware"},
		{"firmware that offers a backup is still firmware", `{"title":"Zigbee coordinator","device_class":"firmware","supported_features":13}`, "firmware"},
		{"an integration from HACS, by the brand icon", `{"title":null,"entity_picture":"https://brands.home-assistant.io/_/adaptive_lighting/icon.png","supported_features":23}`, "integration"},
		{"other software an integration watches", `{"title":"Uptime Kuma 2.1.0","entity_picture":"/api/brands/integration/uptime_kuma/icon.png","supported_features":16}`, ""},
		{"an entity that is unavailable has few attributes", `{"entity_picture":"/api/brands/integration/template/icon.png","friendly_name":"Plug","supported_features":0}`, ""},
		{"no attributes", `{}`, ""},
	}
	for _, tt := range tests {
		if got := kind(entity{Attr: json.RawMessage(tt.attrs)}.attrs()); got != tt.want {
			t.Errorf("%s: kind = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// Integrations decide what they put into attributes: nothing there may break the report.
func TestSoftwareFromOddAttributes(t *testing.T) {
	tests := []struct {
		name  string
		state string
		attrs string
		want  report.Software
	}{
		{
			"versions given as numbers", "on", `{"installed_version":7,"latest_version":7.1,"friendly_name":"Heat pump Firmware","device_class":"firmware"}`,
			report.Software{Name: "Heat pump Firmware", Kind: "firmware", Installed: "7", Latest: "7.1", UpdateAvailable: true},
		},
		{
			"a release link that is no web address", "on", `{"installed_version":"1","latest_version":"2","friendly_name":"Thing","release_url":"javascript:alert(1)"}`,
			report.Software{Name: "Thing", Installed: "1", Latest: "2", UpdateAvailable: true},
		},
		{
			"progress as a number, as old versions gave it", "on", `{"installed_version":"1","latest_version":"2","friendly_name":"Thing","in_progress":55}`,
			report.Software{Name: "Thing", Installed: "1", Latest: "2", UpdateAvailable: true, Detail: "installing"},
		},
		{
			"a title and no name", "off", `{"installed_version":"1","latest_version":"1","title":"Thing OS"}`,
			report.Software{Name: "Thing OS", Installed: "1", Latest: "1"},
		},
		{
			"neither title nor name", "off", `{"installed_version":"1","latest_version":"1"}`,
			report.Software{Name: "update.thing", Installed: "1", Latest: "1"},
		},
		{
			"attributes that are not an object", "unavailable", `[]`,
			report.Software{Name: "update.thing", Detail: "unavailable in Home Assistant"},
		},
		{
			"a skipped version the entity no longer offers", "off", `{"installed_version":"2","latest_version":"2","skipped_version":"2","friendly_name":"Thing"}`,
			report.Software{Name: "Thing", Installed: "2", Latest: "2"},
		},
	}
	for _, tt := range tests {
		got := software(entity{ID: "update.thing", State: tt.state, Attr: json.RawMessage(tt.attrs)})
		if got != tt.want {
			t.Errorf("%s:\n got %+v\nwant %+v", tt.name, got, tt.want)
		}
	}
}

// The result and the maximum age of the backup follow from the three timestamps and the
// manager's state.
func TestBackupOf(t *testing.T) {
	sensors := func(success, attempt, next, manager string) map[string]entity {
		return map[string]entity{
			backupSuccess: {ID: backupSuccess, State: success},
			backupAttempt: {ID: backupAttempt, State: attempt},
			backupNext:    {ID: backupNext, State: next},
			backupManager: {ID: backupManager, State: manager},
		}
	}
	const (
		mon = "2026-11-16T04:50:00+00:00"
		tue = "2026-11-17T04:50:00+00:00"
		wed = "2026-11-18T04:50:00+00:00"
	)
	tests := []struct {
		name       string
		in         map[string]entity
		wantResult string
		wantMaxAge int
		wantDetail string
	}{
		{"every day, and it worked", sensors(tue, tue, wed, "idle"), "ok", 0, "next 2026-11-18 04:50 UTC"},
		{"every day, the latest failed", sensors(mon, tue, wed, "idle"), "failed", 0, "next 2026-11-18 04:50 UTC"},
		{"once a week", sensors(mon, mon, "2026-11-23T05:20:00+00:00", "idle"), "ok", 171, "next 2026-11-23 05:20 UTC"},
		// Home Assistant was off for weeks and planned the next one from today: a week is the most a schedule allows.
		{"a gap longer than a week", sensors(mon, mon, "2026-12-14T04:50:00+00:00", "idle"), "ok", 171, "next 2026-12-14 04:50 UTC"},
		{"the schedule was switched off", sensors(mon, mon, "unknown", "idle"), "ok", 0, "none scheduled"},
		{"a backup is being restored", sensors(mon, mon, tue, "restore_backup"), "ok", 0, "restoring a backup, next 2026-11-17 04:50 UTC"},
		{"the manager is blocked", sensors(mon, mon, tue, "blocked"), "ok", 0, "the backup manager is blocked, next 2026-11-17 04:50 UTC"},
		// A backup made by hand does not stamp an attempt: the last automatic one still counts.
		{"a manual backup runs", sensors(mon, mon, tue, "create_backup"), "ok", 0, "next 2026-11-17 04:50 UTC"},
		{"the sensors are unavailable", sensors("unavailable", "unavailable", "unavailable", "unavailable"), "unknown", 0, "no automatic backup has run, none scheduled"},
	}
	for _, tt := range tests {
		got, ok := backupOf(tt.in)
		if !ok || got.LastResult != tt.wantResult || got.MaxAgeHours != tt.wantMaxAge || got.Detail != tt.wantDetail {
			t.Errorf("%s: ok %v, result %q, max age %d, detail %q\n want result %q, max age %d, detail %q",
				tt.name, ok, got.LastResult, got.MaxAgeHours, got.Detail, tt.wantResult, tt.wantMaxAge, tt.wantDetail)
		}
	}
	if _, ok := backupOf(map[string]entity{backupManager: {ID: backupManager, State: "idle"}}); ok {
		t.Error("a Backup without the two timestamp sensors")
	}
}

// The configuration as the owner writes it.
func TestConfigFromTOML(t *testing.T) {
	doc := `
[[homeassistant]]
name = "homeassistant"
url = "https://homeassistant.example.net:8123"
token_file = "/etc/upkeep/homeassistant.token"
ca_file = ""
tls_server_name = "homeassistant.example.net"
tls_skip_verify = false
timeout = "30s"
ignore_backups = true

[[homeassistant]]
name = "homeassistant-app"
supervisor = true
`
	var conf struct {
		HomeAssistant []Config `toml:"homeassistant"`
	}
	dec := toml.NewDecoder(strings.NewReader(doc))
	dec.DisallowUnknownFields() // a setting the struct does not have is a test failure
	if err := dec.Decode(&conf); err != nil {
		t.Fatal(err)
	}
	if len(conf.HomeAssistant) != 2 {
		t.Fatalf("tables = %d", len(conf.HomeAssistant))
	}
	first, err := New(conf.HomeAssistant[0])
	if err != nil {
		t.Fatal(err)
	}
	if s := first.(*source); s.timeout != 30*time.Second || !s.ignoreBackups || s.supervisor || s.base.String() != "https://homeassistant.example.net:8123" {
		t.Errorf("settings not taken over: %+v", s)
	}
	second, err := New(conf.HomeAssistant[1])
	if err != nil {
		t.Fatal(err)
	}
	if s := second.(*source); !s.supervisor || s.timeout != defaultTimeout || s.base.String() != "http://supervisor/core" {
		t.Errorf("settings not taken over: %+v", s)
	}
}
