package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/store"
)

var testNow = time.Date(2026, 11, 19, 6, 0, 5, 0, time.UTC)

var quiet = slog.New(slog.DiscardHandler)

// reportFixture is a report as an agent on the homelab's server would send it. No agent
// existed when this was written, so it is written by hand from the format in
// internal/report, with the images that run there.
func reportFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// reportNamed is the smallest report a server accepts.
func reportNamed(name string) string {
	return fmt.Sprintf(`{"schema":1,"system":{"name":%q,"kind":"linux","source":"agent"},"sent":"2026-11-19T06:00:03Z"}`, name)
}

// testAPI is a server with a shared token, one system with a token of its own, one polled
// system, and a dashboard that only says it was reached.
func testAPI(st store.Store) *api {
	shared, pi := hashSecret(sharedToken), hashSecret(piToken)
	return &api{
		store: st, policy: model.DefaultPolicy(), now: func() time.Time { return testNow }, log: quiet, version: "test",
		agentToken:   &shared,
		systemTokens: map[string]secretHash{"pi": pi},
		polled:       map[string]bool{"opnsense01": true},
		dashboard:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "dashboard "+r.URL.Path) }),
	}
}

// brokenStore fails every call, as a database on a full disk does.
type brokenStore struct{ store.Store }

var errDisk = errors.New("disk I/O error: /var/lib/upkeep/upkeep.db")

func (brokenStore) SaveReport(context.Context, *report.Report, time.Time) error { return errDisk }
func (brokenStore) Systems(context.Context) ([]model.SystemState, error)        { return nil, errDisk }

func TestReport(t *testing.T) {
	fixture := reportFixture(t)
	manyItems := func() string {
		var items []string
		for i := range report.MaxItems + 50 {
			items = append(items, fmt.Sprintf(`{"name":"package-%03d"}`, i))
		}
		return `{"schema":1,"system":{"name":"server","source":"agent"},"packages":{"manager":"apt","pending":350,"items":[` + strings.Join(items, ",") + `]}}`
	}()
	tests := []struct {
		name   string
		method string // POST unless set
		auth   string // the Authorization header; "Bearer <shared token>" unless set, "-" for none
		gzip   bool   // the request says its body is compressed
		body   string
		broken bool // the store fails
		// What must come of it.
		status int
		says   string // part of the error in the answer
		stored string // the system that must be in the store afterwards; none when empty
	}{
		{name: "a report with the shared token", body: fixture, status: 200, stored: "server"},
		{name: "the scheme in any case", auth: "bearer " + sharedToken, body: fixture, status: 200, stored: "server"},
		{name: "white space after the report", body: fixture + "\n\n  ", status: 200, stored: "server"},
		{name: "fields a newer agent might add", body: `{"schema":1,"system":{"name":"server","source":"agent","uptime":123},"firmware":{"x":1}}`, status: 200, stored: "server"},
		{name: "a name with spaces around it", body: reportNamed("  server "), status: 200, stored: "server"},

		{name: "no token", auth: "-", body: fixture, status: 401, says: "token"},
		{name: "a wrong token", auth: "Bearer " + strings.Repeat("0", 32), body: fixture, status: 401},
		{name: "the token cut short", auth: "Bearer " + sharedToken[:31], body: fixture, status: 401},
		{name: "an empty token", auth: "Bearer ", body: fixture, status: 401},
		{name: "the token as a password", auth: "Basic " + sharedToken, body: fixture, status: 401},
		{name: "the token without a scheme", auth: sharedToken, body: fixture, status: 401},

		{name: "a system's own token, its own name", auth: "Bearer " + piToken, body: reportNamed("pi"), status: 200, stored: "pi"},
		{name: "a system's own token, another name", auth: "Bearer " + piToken, body: reportNamed("server"), status: 403, says: "may only report pi"},
		{name: "the shared token for a system with its own", body: reportNamed("pi"), status: 403, says: "token of its own"},
		{name: "the name of a polled system", body: reportNamed("opnsense01"), status: 409, says: "polled"},

		{name: "GET", method: "GET", status: 405},
		{name: "PUT", method: "PUT", body: fixture, status: 405},
		{name: "an empty body", body: "", status: 400, says: "not a report"},
		{name: "a compressed body", gzip: true, body: "\x1f\x8b\x08\x00", status: 415, says: "plain JSON"},
		{name: "what is not JSON", body: "pending=3", status: 400, says: "not a report"},
		{name: "JSON that is not a report", body: `[1,2,3]`, status: 400, says: "not a report"},
		{name: "a wrong type in a field", body: `{"schema":"one","system":{"name":"server"}}`, status: 400, says: "not a report"},
		{name: "two reports in one body", body: reportNamed("server") + reportNamed("pi"), status: 400, says: "follows the report"},
		{name: "a body over the limit", body: `{"schema":1,"system":{"name":"server","os":"` + strings.Repeat("x", maxReportBytes) + `"}}`, status: 413, says: "larger than 1 MiB"},
		{name: "a small report and then too much", body: reportNamed("server") + strings.Repeat(" ", maxReportBytes), status: 413},
		{name: "no schema", body: `{"system":{"name":"server"}}`, status: 400, says: "unknown schema"},
		{name: "a schema from the future", body: `{"schema":99,"system":{"name":"server"}}`, status: 400, says: "unknown schema"},
		{name: "no name", body: `{"schema":1,"system":{"kind":"linux"}}`, status: 400, says: "system name"},
		{name: "a name that is a path", body: reportNamed("../../etc/passwd"), status: 400, says: "system name"},
		{name: "a name of two lines", body: reportNamed("server\nother"), status: 400, says: "system name"},
		{name: "a store that fails", body: fixture, broken: true, status: 500, says: "could not be stored"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := store.NewMemory()
			a := testAPI(mem)
			if tt.broken {
				a.store = brokenStore{mem}
			}
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, "/api/v1/report", strings.NewReader(tt.body))
			switch tt.auth {
			case "":
				req.Header.Set("Authorization", "Bearer "+sharedToken)
			case "-":
			default:
				req.Header.Set("Authorization", tt.auth)
			}
			if tt.gzip {
				req.Header.Set("Content-Encoding", "gzip")
			}
			rec := httptest.NewRecorder()
			a.handler().ServeHTTP(rec, req)

			body := rec.Body.String()
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.status, body)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q", ct)
			}
			var answer map[string]string
			if err := json.Unmarshal([]byte(body), &answer); err != nil {
				t.Fatalf("the answer is not JSON: %q", body)
			}
			if !strings.Contains(answer["error"], tt.says) {
				t.Errorf("error %q does not say %q", answer["error"], tt.says)
			}
			for _, secret := range []string{sharedToken, piToken, errDisk.Error()} {
				if strings.Contains(body, secret) {
					t.Errorf("the answer gives away %q", secret)
				}
			}
			switch tt.status {
			case 401:
				if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
					t.Errorf("WWW-Authenticate = %q", got)
				}
			case 405:
				if got := rec.Header().Get("Allow"); got != "POST" {
					t.Errorf("Allow = %q", got)
				}
			}

			systems, _ := mem.Systems(t.Context())
			if tt.stored == "" {
				if len(systems) != 0 {
					t.Errorf("a refused report was stored: %v", systems[0].Report.System.Name)
				}
				return
			}
			if len(systems) != 1 || systems[0].Report.System.Name != tt.stored {
				t.Fatalf("stored %d systems, want %q", len(systems), tt.stored)
			}
			if !systems[0].ReceivedAt.Equal(testNow) {
				t.Errorf("stored with %v, want the time of arrival %v", systems[0].ReceivedAt, testNow)
			}
			if answer["status"] != "stored" || answer["system"] != tt.stored {
				t.Errorf("answer = %v", answer)
			}
		})
	}

	t.Run("the fixture arrives whole", func(t *testing.T) {
		mem := store.NewMemory()
		post(t, testAPI(mem), sharedToken, fixture, 200)
		got, err := mem.System(t.Context(), "server")
		if err != nil {
			t.Fatal(err)
		}
		var want report.Report
		if err := json.Unmarshal([]byte(fixture), &want); err != nil {
			t.Fatal(err)
		}
		g, _ := json.Marshal(got.Report)
		w, _ := json.Marshal(want)
		if string(g) != string(w) {
			t.Errorf("stored report differs\n got: %s\nwant: %s", g, w)
		}
		if len(got.Report.Containers) != 9 || got.Report.Packages.Items[0].Name != "openssl" || got.Report.Backups[0].LastResult != "ok" {
			t.Errorf("the fixture was not read as written: %+v", got.Report)
		}
	})
	t.Run("the source is agent whatever the report says", func(t *testing.T) {
		for _, claimed := range []string{"connector", "", "root"} {
			mem := store.NewMemory()
			post(t, testAPI(mem), sharedToken, fmt.Sprintf(`{"schema":1,"system":{"name":"server","source":%q}}`, claimed), 200)
			if got, _ := mem.System(t.Context(), "server"); got.Report.System.Source != "agent" {
				t.Errorf("claimed %q, stored %q", claimed, got.Report.System.Source)
			}
		}
	})
	t.Run("a package list longer than the format allows is cut", func(t *testing.T) {
		mem := store.NewMemory()
		post(t, testAPI(mem), sharedToken, manyItems, 200)
		got, _ := mem.System(t.Context(), "server")
		if n := len(got.Report.Packages.Items); n != report.MaxItems || got.Report.Packages.Pending != 350 {
			t.Errorf("%d items stored, pending %d; want %d items and the count as sent", n, got.Report.Packages.Pending, report.MaxItems)
		}
	})
	t.Run("a server without any token accepts nothing", func(t *testing.T) {
		mem := store.NewMemory()
		a := testAPI(mem)
		a.agentToken, a.systemTokens = nil, nil
		for _, token := range []string{"", sharedToken} {
			post(t, a, token, fixture, 401)
		}
	})
}

func post(t *testing.T, a *api, token, body string, want int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/report", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	a.handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, want, rec.Body)
	}
}

func get(a *api, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	a.handler().ServeHTTP(rec, req)
	return rec
}

func TestState(t *testing.T) {
	ctx := t.Context()
	mem := store.NewMemory()
	a := testAPI(mem)

	t.Run("who may read it", func(t *testing.T) {
		tests := []struct {
			name, method, token string
			status              int
		}{
			{"the shared token", "GET", sharedToken, 200},
			{"no token", "GET", "", 401},
			{"a wrong token", "GET", strings.Repeat("0", 32), 401},
			// It may report pi; it is not meant to learn what is out of date everywhere else.
			{"a single system's token", "GET", piToken, 401},
			{"POST", "POST", sharedToken, 405},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest(tt.method, "/api/v1/state", nil)
				if tt.token != "" {
					req.Header.Set("Authorization", "Bearer "+tt.token)
				}
				rec := httptest.NewRecorder()
				a.handler().ServeHTTP(rec, req)
				if rec.Code != tt.status {
					t.Errorf("status = %d, want %d", rec.Code, tt.status)
				}
				if tt.status != 200 && strings.Contains(rec.Body.String(), "systems") {
					t.Errorf("a refused request got the state: %s", rec.Body)
				}
			})
		}
	})

	t.Run("an empty server gives empty lists, not null", func(t *testing.T) {
		rec := get(a, "/api/v1/state", sharedToken)
		for _, want := range []string{`"systems":[]`, `"image_checks":[]`, `"findings":[]`, `"version":"test"`, `"generated":"2026-11-19T06:00:05Z"`} {
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("the state lacks %s: %s", want, rec.Body)
			}
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q", got)
		}
	})

	t.Run("systems, checks and findings", func(t *testing.T) {
		post(t, a, sharedToken, reportFixture(t), 200)
		post(t, a, piToken, reportNamed("pi"), 200)
		gitea := model.ImageCheck{Image: "docker.io/gitea/gitea:1.23.6", Tag: "1.23.6", NewerPatch: "1.23.8", CheckedAt: testNow.Add(-time.Hour)}
		ollama := model.ImageCheck{Image: "docker.io/ollama/ollama:latest", Tag: "latest", Error: "asking registry-1.docker.io: 429", CheckedAt: testNow.Add(-time.Minute)}
		if err := errors.Join(mem.SaveImageCheck(ctx, ollama), mem.SaveImageCheck(ctx, gitea)); err != nil {
			t.Fatal(err)
		}

		rec := get(a, "/api/v1/state", sharedToken)
		if rec.Code != 200 {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		var got stateJSON
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Systems) != 2 || got.Systems[0].Name != "pi" || got.Systems[1].Name != "server" {
			t.Fatalf("systems = %+v", got.Systems)
		}
		if s := got.Systems[1]; !s.ReceivedAt.Equal(testNow) || s.Report.System.OSVersion != "13.7" || len(s.Report.Containers) != 9 {
			t.Errorf("the server's report is not whole: %+v", s)
		}
		if len(got.ImageChecks) != 2 || got.ImageChecks[0].Image != gitea.Image || got.ImageChecks[0].NewerPatch != "1.23.8" ||
			got.ImageChecks[1].Error != ollama.Error || !got.ImageChecks[0].CheckedAt.Equal(gitea.CheckedAt) {
			t.Errorf("image checks = %+v", got.ImageChecks)
		}
		// The findings are the ones the dashboard and the mail show: model.Findings, in its order.
		systems, _ := mem.Systems(ctx)
		checks, _ := mem.ImageChecks(ctx)
		want := model.Findings(systems, checks, testNow, a.policy)
		if len(want) < 4 || len(got.Findings) != len(want) {
			t.Fatalf("%d findings, want %d (and at least 4 from this fixture)", len(got.Findings), len(want))
		}
		for i, f := range want {
			g := got.Findings[i]
			if g.System != f.System || g.Category != string(f.Category) || g.Severity != f.Severity.String() || g.Title != f.Title || g.Detail != f.Detail {
				t.Errorf("finding %d = %+v, want %+v", i, g, f)
			}
		}
		// The names scripts rely on.
		for _, key := range []string{`"received_at":`, `"report":`, `"image_checks":`, `"newer_patch":"1.23.8"`, `"severity":"warn"`, `"category":"reboot"`, `"title":"reboot required"`} {
			if !strings.Contains(rec.Body.String(), key) {
				t.Errorf("the state lacks %s", key)
			}
		}
	})

	t.Run("a store that fails", func(t *testing.T) {
		b := testAPI(brokenStore{mem})
		rec := get(b, "/api/v1/state", sharedToken)
		if rec.Code != 500 || strings.Contains(rec.Body.String(), "upkeep.db") {
			t.Errorf("status = %d, body %s", rec.Code, rec.Body)
		}
	})
}

func TestHealth(t *testing.T) {
	a := testAPI(store.NewMemory())
	a.dashboardUser = "valentino" // a supervisor has no password and needs none here
	pass := hashSecret(dashPass)
	a.dashboardPassword = &pass
	tests := []struct {
		method string
		status int
		body   string
	}{
		{"GET", 200, "ok\n"},
		{"HEAD", 200, ""},
		{"POST", 405, ""},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			a.handler().ServeHTTP(rec, httptest.NewRequest(tt.method, "/healthz", nil))
			if rec.Code != tt.status || (tt.body != "" && rec.Body.String() != tt.body) {
				t.Errorf("status = %d, body %q", rec.Code, rec.Body)
			}
		})
	}
}

func TestDashboardPassword(t *testing.T) {
	pass := hashSecret(dashPass)
	tests := []struct {
		name       string
		protected  bool
		user, pass string // sent when user is set
		bearer     string
		path       string
		status     int
	}{
		{name: "no password configured", path: "/", status: 200},
		{name: "no password configured, any page", path: "/systems/server", status: 200},
		{name: "nothing sent", protected: true, path: "/", status: 401},
		{name: "the right user and password", protected: true, user: "valentino", pass: dashPass, path: "/updates", status: 200},
		{name: "a wrong password", protected: true, user: "valentino", pass: "lozinka", path: "/", status: 401},
		{name: "an empty password", protected: true, user: "valentino", pass: "", path: "/", status: 401},
		{name: "a wrong user", protected: true, user: "root", pass: dashPass, path: "/", status: 401},
		{name: "static files are behind it too", protected: true, path: "/static/app.css", status: 401},
		// The agents' token is on every machine; it must not open the pages.
		{name: "the agents' token is not a password", protected: true, bearer: sharedToken, path: "/", status: 401},
		{name: "the agents' token as the password", protected: true, user: "valentino", pass: sharedToken, path: "/", status: 401},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAPI(store.NewMemory())
			if tt.protected {
				a.dashboardUser, a.dashboardPassword = "valentino", &pass
			}
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.user != "" {
				req.SetBasicAuth(tt.user, tt.pass)
			}
			if tt.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tt.bearer)
			}
			rec := httptest.NewRecorder()
			a.handler().ServeHTTP(rec, req)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			switch tt.status {
			case 200:
				if got := rec.Body.String(); got != "dashboard "+tt.path {
					t.Errorf("the dashboard did not get the request: %q", got)
				}
			case 401:
				if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, `Basic realm="upkeep"`) {
					t.Errorf("WWW-Authenticate = %q", got)
				}
				if strings.Contains(rec.Body.String(), "dashboard /") {
					t.Error("the page was sent without the password")
				}
			}
		})
	}

	t.Run("the API needs its token, not the password", func(t *testing.T) {
		a := testAPI(store.NewMemory())
		a.dashboardUser, a.dashboardPassword = "valentino", &pass
		if rec := get(a, "/api/v1/state", sharedToken); rec.Code != 200 {
			t.Errorf("state with the token behind a dashboard password: %d", rec.Code)
		}
		req := httptest.NewRequest("GET", "/api/v1/state", nil)
		req.SetBasicAuth("valentino", dashPass)
		rec := httptest.NewRecorder()
		a.handler().ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("state with the dashboard password: %d, want 401", rec.Code)
		}
	})
}

// A machine that was taken out of service can be removed, by whoever holds the shared token
// and nobody else.
func TestForget(t *testing.T) {
	del := func(a *api, method, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		a.handler().ServeHTTP(rec, req)
		return rec
	}
	tests := []struct {
		name   string
		method string
		path   string
		token  string
		broken bool
		status int
		left   []string // the systems in the store afterwards
	}{
		{name: "the shared token forgets one system", method: http.MethodDelete, path: "/api/v1/systems/old-pi", token: sharedToken,
			status: 200, left: []string{"server"}},
		{name: "an escaped name nobody reported", method: http.MethodDelete, path: "/api/v1/systems/guest%20house", token: sharedToken,
			status: 404, left: []string{"old-pi", "server"}},
		{name: "a system nobody reported", method: http.MethodDelete, path: "/api/v1/systems/nobody", token: sharedToken,
			status: 404, left: []string{"old-pi", "server"}},
		{name: "no name", method: http.MethodDelete, path: "/api/v1/systems/", token: sharedToken, status: 404, left: []string{"old-pi", "server"}},
		{name: "more than a name", method: http.MethodDelete, path: "/api/v1/systems/old-pi/report", token: sharedToken,
			status: 404, left: []string{"old-pi", "server"}},
		{name: "a system's own token is not enough", method: http.MethodDelete, path: "/api/v1/systems/old-pi", token: piToken,
			status: 401, left: []string{"old-pi", "server"}},
		{name: "no token", method: http.MethodDelete, path: "/api/v1/systems/old-pi", status: 401, left: []string{"old-pi", "server"}},
		{name: "GET is not a way to delete", method: http.MethodGet, path: "/api/v1/systems/old-pi", token: sharedToken,
			status: 405, left: []string{"old-pi", "server"}},
		{name: "a store that fails", method: http.MethodDelete, path: "/api/v1/systems/old-pi", token: sharedToken, broken: true,
			status: 500, left: []string{"old-pi", "server"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			mem := store.NewMemory()
			for _, name := range []string{"server", "old-pi"} {
				if err := mem.SaveReport(ctx, &report.Report{Schema: 1, System: report.System{Name: name, Source: "agent"}}, testNow); err != nil {
					t.Fatal(err)
				}
			}
			var st store.Store = mem
			if tc.broken {
				st = failingDelete{mem}
			}
			rec := del(testAPI(st), tc.method, tc.path, tc.token)
			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d; body: %s", rec.Code, tc.status, rec.Body)
			}
			if strings.Contains(rec.Body.String(), errDisk.Error()) {
				t.Errorf("the store's error is in the answer: %s", rec.Body)
			}
			var left []string
			systems, _ := mem.Systems(ctx)
			for _, s := range systems {
				left = append(left, s.Report.System.Name)
			}
			if fmt.Sprint(left) != fmt.Sprint(tc.left) {
				t.Errorf("systems left: %v, want %v", left, tc.left)
			}
		})
	}
}

type failingDelete struct{ store.Store }

func (failingDelete) DeleteSystem(context.Context, string) error { return errDisk }
