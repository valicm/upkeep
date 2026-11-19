package web

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/demo"
	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/store"
)

// testNow is the moment every test happens at.
var testNow = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

func noFindings([]model.SystemState, map[string]model.ImageCheck, time.Time, model.Policy) []model.Finding {
	return nil
}

func demoStore(t *testing.T) store.Store {
	t.Helper()
	s := store.NewMemory()
	if err := demo.Fill(context.Background(), s, testNow); err != nil {
		t.Fatalf("fill the demo store: %v", err)
	}
	return s
}

func handlerFor(s store.Store, f findingsFunc) http.Handler {
	return Handler(Options{
		Store:    s,
		Policy:   model.DefaultPolicy(),
		Now:      func() time.Time { return testNow },
		Version:  "test",
		findings: f,
	})
}

func demoHandler(t *testing.T) http.Handler {
	t.Helper()
	return handlerFor(demoStore(t), demoFindings)
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// element is one start tag of a parsed page.
type element struct {
	name  string
	attrs map[string]string
}

// document is a page taken apart: its tags, and its text the way a reader sees it.
type document struct {
	elements []element
	text     string
}

// parsePage reads a page with a strict XML parser. The templates write markup that is valid as
// XML too, so this proves what "well-formed" means here: every tag closed and nested properly,
// every attribute quoted, no stray "<" or "&" from data. Text inside <script> and <style> does
// not exist: the pages have no inline code.
func parsePage(t *testing.T, body string) document {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(body))
	dec.Strict = true
	var doc document
	var text []string
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			line, col := dec.InputPos()
			t.Fatalf("page is not well-formed at line %d, column %d: %v\n%s", line, col, err, excerpt(body, line))
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			depth++
			e := element{name: tok.Name.Local, attrs: map[string]string{}}
			for _, a := range tok.Attr {
				if _, dup := e.attrs[a.Name.Local]; dup {
					t.Errorf("<%s> has the attribute %q twice", e.name, a.Name.Local)
				}
				e.attrs[a.Name.Local] = a.Value
			}
			doc.elements = append(doc.elements, e)
		case xml.EndElement:
			depth--
		case xml.CharData:
			if s := strings.Join(strings.Fields(string(tok)), " "); s != "" {
				text = append(text, s)
			}
		}
	}
	if depth != 0 {
		t.Errorf("page ends with %d tags still open", depth)
	}
	doc.text = strings.Join(text, " ")
	return doc
}

func excerpt(body string, line int) string {
	lines := strings.Split(body, "\n")
	from, to := max(line-3, 0), min(line+1, len(lines))
	return strings.Join(lines[from:to], "\n")
}

// checkPage holds every rule that is the same for all pages.
func checkPage(t *testing.T, rec *httptest.ResponseRecorder) document {
	t.Helper()
	h := rec.Header()
	if got := h.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := h.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, a page must not be stored", got)
	}
	checkSecurityHeaders(t, h)
	body := rec.Body.String()
	if !strings.HasPrefix(body, "<!DOCTYPE html>") {
		t.Errorf("page does not start with the doctype: %.40q", body)
	}
	doc := parsePage(t, body)

	ids := map[string]bool{}
	scripts := 0
	for _, e := range doc.elements {
		if id, ok := e.attrs["id"]; ok {
			if id == "" || strings.ContainsAny(id, " \t\n") {
				t.Errorf("<%s> has an unusable id %q", e.name, id)
			}
			if ids[id] {
				t.Errorf("id %q is used twice", id)
			}
			ids[id] = true
		}
		for name, value := range e.attrs {
			if strings.HasPrefix(name, "on") {
				t.Errorf("<%s> has an event handler attribute %s=%q", e.name, name, value)
			}
			if name == "style" {
				t.Errorf("<%s> has an inline style, which the Content-Security-Policy forbids", e.name)
			}
		}
		switch e.name {
		case "script":
			scripts++
			if !strings.Contains(e.attrs["src"], "static/") {
				t.Errorf("script that is not one of the static files: %v", e.attrs)
			}
		case "style", "iframe", "object", "embed", "form", "base":
			t.Errorf("unexpected <%s> element", e.name)
		}
		// Whatever the browser loads by itself must come from this server.
		for _, attr := range []string{"src", "href"} {
			ref, ok := e.attrs[attr]
			if !ok || (e.name == "a" && e.attrs["rel"] == "noopener noreferrer") {
				continue
			}
			u, err := url.Parse(ref)
			if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(ref, "/") {
				t.Errorf("<%s %s=%q> is not a relative address on this server", e.name, attr, ref)
			}
		}
		if e.name == "a" && e.attrs["rel"] == "noopener noreferrer" {
			u, err := url.Parse(e.attrs["href"])
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				t.Errorf("outside link with an address that is not a web address: %q", e.attrs["href"])
			}
		}
	}
	if scripts != 2 {
		t.Errorf("page has %d script elements, want the 2 static ones", scripts)
	}
	// Only a page that shows state asks the script to keep it fresh.
	for _, e := range doc.elements {
		if _, live := e.attrs["data-live"]; e.name == "main" && live != (rec.Code == http.StatusOK) {
			t.Errorf("status %d and data-live %v do not go together", rec.Code, live)
		}
	}
	return doc
}

func checkSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self'", "frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("Content-Security-Policy %q lacks %q", csp, want)
		}
	}
	for _, loose := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:", "data:", "*"} {
		if strings.Contains(csp, loose) {
			t.Errorf("Content-Security-Policy %q allows %q", csp, loose)
		}
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := h.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", got)
	}
}

func wantText(t *testing.T, doc document, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(doc.text, want) {
			t.Errorf("page does not say %q", want)
		}
	}
}

func wantNoText(t *testing.T, doc document, unwanted ...string) {
	t.Helper()
	for _, s := range unwanted {
		if strings.Contains(doc.text, s) {
			t.Errorf("page says %q and should not", s)
		}
	}
}

// TestPages renders every page against the demo homelab and looks for the facts a reader
// comes for.
func TestPages(t *testing.T) {
	h := demoHandler(t)
	tests := []struct {
		name   string
		path   string
		title  string
		want   []string
		absent []string
	}{
		{
			name: "overview", path: "/", title: "Overview · upkeep",
			want: []string{
				// The row of numbers.
				"Systems 7 1 silent",
				"Need attention 4 2 broken, 8 to do",
				"OS updates 19 4 security, 1 reboot",
				"Container updates 9 of 17, 3 update themselves",
				"Backups late or failed 3 1 failed, 1 never ran, 1 late",
				// The list: what is broken, what should be done, and folded away what is only news.
				"Needs attention 10",
				"Broken 2", "Should be done 8", "Worth knowing 14",
				"broken: server Backup backup restic-backup failed last run 2026-11-19 05:00 UTC; exit-code 3; last success 2026-11-17 05:00 UTC",
				"to do: server OS updates 12 package updates, 3 security security: liblzma5, libssl3t64, openssl-provider-legacy",
				"to know: opnsense Software OPNsense 26.10.1 available installed 26.10; 41 packages, needs a reboot",
				// The table of systems, each with the worst of its findings in front.
				"broken: server 12 · 3 security waiting 6 of 9 newer — 1 of 2 failed 4 min ago",
				"should be done: ops01 4 no 2 of 6 newer — late 2 min ago",
				"broken: dns02 none known no 1 of 1 newer — never silent 3 d ago",
				"should be done: storage 3 · 1 security no 1 of 1 unchecked — running 7 min ago 1 problem",
				"worth knowing: opnsense — — — 1 of 3 newer — 11 min ago",
				"nothing to do: opnsense02 — — — 3 current — 11 min ago",
				"worth knowing: homeassistant — — — 2 of 6 newer ok 9 min ago",
				"upkeep test",
			},
			absent: []string{"Nothing needs attention"},
		},
		{
			name: "updates", path: "/updates", title: "Updates · upkeep",
			want: []string{
				// Packages: counts, the list with both versions, the security mark.
				"12 pending, 3 security apt · lists refreshed 5 h ago",
				"List the 12 packages",
				"libssl3t64 3.5.1-1 3.5.7-1~deb13u3 security",
				"tzdata 2025b-4 2026f-0+deb13u1",
				// The reboot and why.
				"Reboot waiting kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed",
				"Reboot not needed",
				// Containers: image, running tag, what is newer, whether it updates itself.
				"gitea docker.io/gitea/gitea 1.23.6 patch 1.23.8 minor 1.27.3 no",
				"gitea-db docker.io/library/mariadb 11.4.13 minor 11.8.9 major 13.0.2 no",
				"unifi-db docker.io/library/mongo 7.0.48 major 9.0.8 no",
				"ollama docker.io/ollama/ollama latest tag was rebuilt yes",
				"uptime-kuma docker.io/louislam/uptime-kuma 2 tag was rebuilt no",
				"photoprism docker.io/photoprism/photoprism 251130 up to date no",
				"mailpit docker.io/axllent/mailpit latest up to date yes",
				"medimorec localhost/medimorec-server current local image no",
				"materia ghcr.io/stryan/materia @sha256:",
				"pinned by digest",
				"adguardhome-sync ghcr.io/bakito/adguardhome-sync v0.8.2 not checked",
				"restic-server docker.io/restic/rest-server 0.14.0 check failed asking what docker.io/restic/rest-server:0.14.0 points at: too many requests",
				// Software: installed, latest, notes.
				"OPNsense firmware 26.10 26.10.1 update 41 packages, needs a reboot · release notes",
				"Home Assistant Core core 2026.11.1 2026.11.2 update release notes",
				"Zigbee2MQTT app 2.6.3-1 2.7.0-1 update release notes",
				"Mosquitto broker app 6.5.2 6.5.2 current",
				// A system with nothing pending says so.
				"opnsense02 nothing to update",
			},
		},
		{
			name: "backups", path: "/backups", title: "Backups · upkeep",
			want: []string{
				"1 failed 1 late 1 never 1 running 2 ok",
				"server restic-backup failed late 2 d ago failed, 5 h ago 26 h default restic exit-code 3",
				"dns02 restic-backup never never unknown 26 h default restic restic-backup.timer has not fired yet",
				"ops01 restic-backup late 40 h ago ok, 40 h ago 26 h default restic snapshot 7c1e09ab, 3.1 GiB",
				"storage restic-backup running 24 h ago running, 10 min ago 26 h default restic",
				"homeassistant automatic backup ok 9 h ago ok, 9 h ago 2 d homeassistant Home Assistant 2026.11.1, 412 MiB",
				"server mariadb-dump ok 6 h ago ok, 6 h ago 26 h default systemd",
				"Systems that report no backup: opnsense , opnsense02 .",
			},
		},
		{
			name: "system with an agent", path: "/systems/server", title: "server · upkeep",
			want: []string{
				"server broken",
				"System Debian GNU/Linux 13 (trixie) 13.7 linux",
				"Kernel 6.12.107+deb13-amd64 amd64",
				"Reports through an installed agent that pushes its report upkeep 0.1.0 linux/amd64",
				"Last report 4 min ago received 2026-11-19 09:56:00 UTC, built 2026-11-19 09:55:58 UTC",
				"Needs attention 9",
				"broken Backup backup restic-backup failed",
				"to do Reboot reboot required kernel 6.12.107+deb13-amd64 running",
				"to know Container gitea: 1.23.8 available patch update of docker.io/gitea/gitea:1.23.6; also 1.27.3 (minor)",
				"Every collector did its job.",
				"12 pending, 3 security",
				"gitea docker.io/gitea/gitea 1.23.6 patch 1.23.8 minor 1.27.3 no running podman 3 wk ago",
				"Registries asked 35 min ago .",
				"restic-backup failed late 2 d ago failed, 5 h ago 26 h default restic exit-code 3",
				`"name": "server"`,
				`"reboot_reason": "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"`,
				"Open it as a JSON file",
			},
			absent: []string{"ops01", "Zigbee2MQTT", "no report since"},
		},
		{
			name: "system with a collector problem", path: "/systems/storage", title: "storage · upkeep",
			want: []string{
				"storage should be done",
				"Collector problems 1",
				"ospkg apt-get update: exit status 100: Temporary failure resolving 'deb.debian.org'",
				"Last report 7 min ago 1 problem",
				"running 24 h ago running, 10 min ago",
			},
		},
		{
			name: "system behind a connector", path: "/systems/opnsense", title: "opnsense · upkeep",
			want: []string{
				"opnsense worth knowing",
				"System OPNsense 26.10 opnsense",
				"Reports through a connector: the server asks the system's API",
				"OPNsense firmware 26.10 26.10.1 update",
				"This system reports no backup.",
			},
			absent: []string{"OS packages", "Containers"},
		},
		{
			name: "system that went silent", path: "/systems/dns02", title: "dns02 · upkeep",
			want: []string{
				"dns02 broken",
				"Last report silent 3 d ago received 2026-11-16 08:00:00 UTC",
				"broken Reporting no report since 2026-11-16 08:00 UTC silent for 3 days",
				"restic-backup never never unknown",
			},
		},
		{
			name: "system with nothing to do", path: "/systems/opnsense02", title: "opnsense02 · upkeep",
			want: []string{"opnsense02 nothing to do", "Nothing needs attention on this system."},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := get(t, h, tc.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", tc.path, rec.Code)
			}
			doc := checkPage(t, rec)
			wantText(t, doc, tc.title)
			wantText(t, doc, tc.want...)
			wantNoText(t, doc, tc.absent...)
		})
	}
}

// reversed gives the findings of the demo back to front: as unsorted as they can be.
func reversed(states []model.SystemState, checks map[string]model.ImageCheck, now time.Time, p model.Policy) []model.Finding {
	fs := demoFindings(states, checks, now, p)
	for i, j := 0, len(fs)-1; i < j; i, j = i+1, j-1 {
		fs[i], fs[j] = fs[j], fs[i]
	}
	return fs
}

// TestOrder checks the places where order is the message.
func TestOrder(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		findings findingsFunc
		order    []string
	}{
		{
			name: "findings as model.Findings sorts them: nothing moves", path: "/", findings: demoFindings,
			order: []string{
				"Broken 2", "no report since 2026-11-16", "backup restic-backup failed",
				"Should be done 8", "backup restic-backup never succeeded", "reboot required", "package lists not refreshed since 2026-11-15",
				"Worth knowing 14", "adguard: tag latest was rebuilt", "Zigbee2MQTT 2.7.0-1 available", "1 image could not be checked",
				"Systems 7",
			},
		},
		{
			name: "findings in any order: the worst still come first, and nothing else moves", path: "/", findings: reversed,
			order: []string{
				"Broken 2", "backup restic-backup failed", "no report since 2026-11-16",
				"Should be done 8", "package lists not refreshed since 2026-11-15", "reboot required", "backup restic-backup never succeeded",
				"Worth knowing 14", "1 image could not be checked", "Zigbee2MQTT 2.7.0-1 available", "adguard: tag latest was rebuilt",
				"Systems 7",
			},
		},
		{
			name: "one system's findings keep their order too", path: "/systems/server", findings: demoFindings,
			order: []string{"backup restic-backup failed", "reboot required", "12 package updates", "gitea-db: 11.8.9 available", "unifi: 10.6.109-ls155 available"},
		},
		{
			name: "backups: what needs a person first", path: "/backups", findings: demoFindings,
			order: []string{"exit-code 3", "snapshot 7c1e09ab", "has not fired yet", "started by restic-backup.timer", "Home Assistant 2026.11.1", "mariadb-dump"},
		},
		{
			name: "packages: security updates first, then by name", path: "/updates", findings: demoFindings,
			order: []string{"liblzma5", "libssl3t64", "openssl-provider-legacy", "base-files", "bash", "tzdata"},
		},
		{
			name: "containers: those with something newer first, then by name", path: "/systems/server", findings: demoFindings,
			order: []string{"gitea docker.io", "gitea-db docker.io", "ollama docker.io", "unifi-db docker.io", "materia ghcr.io", "medimorec localhost", "photoprism docker.io"},
		},
		{
			name: "software: updates first, then as the source lists it", path: "/systems/homeassistant", findings: demoFindings,
			order: []string{"Home Assistant Core core", "Zigbee2MQTT app", "Home Assistant Operating System os", "Home Assistant Supervisor", "Mosquitto broker", "ESPHome Device Builder"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := checkPage(t, get(t, handlerFor(demoStore(t), tc.findings), tc.path))
			at := 0
			for _, s := range tc.order {
				i := strings.Index(doc.text[at:], s)
				if i < 0 {
					t.Fatalf("%q does not come after what should be before it", s)
				}
				at += i + len(s)
			}
		})
	}
}

// TestWorthKnowingIsFolded checks that news does not bury what has to be done: findings that
// are only worth knowing are folded away while something is broken or waiting, and open when
// they are all there is.
func TestWorthKnowingIsFolded(t *testing.T) {
	onlyNews := func(states []model.SystemState, checks map[string]model.ImageCheck, now time.Time, p model.Policy) []model.Finding {
		var out []model.Finding
		for _, f := range demoFindings(states, checks, now, p) {
			if f.Severity == model.Info {
				out = append(out, f)
			}
		}
		return out
	}
	tests := []struct {
		name     string
		findings findingsFunc
		wantFold bool
		wantOpen bool
		want     []string
	}{
		{"something to do", demoFindings, true, false, []string{"Needs attention 10", "Worth knowing 14"}},
		{"only news", onlyNews, true, true, []string{"Need attention 0 14 to know", "Nothing needs attention.", "Worth knowing 14", "OPNsense 26.10.1 available"}},
		{"nothing at all", noFindings, false, false, []string{"Need attention 0 nothing to do", "Nothing needs attention."}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := checkPage(t, get(t, handlerFor(demoStore(t), tc.findings), "/"))
			wantText(t, doc, tc.want...)
			fold, open := false, false
			for _, e := range doc.elements {
				if e.name == "details" && e.attrs["id"] == "worth-knowing" {
					fold = true
					_, open = e.attrs["open"]
				}
			}
			if fold != tc.wantFold || open != tc.wantOpen {
				t.Errorf("folded list present %v, open %v; want %v, %v", fold, open, tc.wantFold, tc.wantOpen)
			}
		})
	}
}

func TestNotFound(t *testing.T) {
	h := demoHandler(t)
	tests := []struct {
		path string
		want string
	}{
		{"/systems/nope", "No system called “nope” has reported to this server."},
		{"/systems/Server", "No system called “Server” has reported"},
		{"/systems/nope/report.json", "No system called “nope” has reported"},
		{"/systems/", "There is no such page."},
		{"/nope", "There is no such page."},
		{"/updates/extra", "There is no such page."},
		{"/static/nope.css", "There is no such page."},
		{"/static/", "There is no such page."},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			rec := get(t, h, tc.path)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s = %d, want 404", tc.path, rec.Code)
			}
			wantText(t, checkPage(t, rec), tc.want)
		})
	}
}

// TestEmptyStates covers a server nobody reported to, and one where all is well.
func TestEmptyStates(t *testing.T) {
	quiet := store.NewMemory()
	fine := report.Report{
		Schema:   report.Schema,
		System:   report.System{Name: "calm", Kind: "linux", Source: "agent"},
		Sent:     testNow,
		Packages: &report.Packages{Manager: "apt"},
	}
	if err := quiet.SaveReport(context.Background(), &fine, testNow); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		store store.Store
		path  string
		want  []string
	}{
		{"nobody reported, overview", store.NewMemory(), "/", []string{"Systems 0 none has reported yet", "Need attention 0 no system to look at",
			"OS updates 0 none reported", "Container updates 0 none reported", "Backups late or failed 0 none reported", "No system has reported yet."}},
		{"nobody reported, updates", store.NewMemory(), "/updates", []string{"No system has reported yet."}},
		{"nobody reported, backups", store.NewMemory(), "/backups", []string{"No system reports a backup yet."}},
		{"all is well, overview", quiet, "/", []string{"Systems 1 all reporting", "Need attention 0 nothing to do", "OS updates 0 none pending", "Nothing needs attention.", "calm none no — — — just now"}},
		{"all is well, updates", quiet, "/updates", []string{"calm nothing to update", "up to date apt", "Reboot not needed"}},
		{"all is well, backups", quiet, "/backups", []string{"No system reports a backup yet.", "Systems that report no backup: calm ."}},
		{"all is well, system", quiet, "/systems/calm", []string{"calm nothing to do", "Nothing needs attention on this system.", "This system reports no backup."}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := get(t, handlerFor(tc.store, noFindings), tc.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", tc.path, rec.Code)
			}
			wantText(t, checkPage(t, rec), tc.want...)
		})
	}
}

// hostile is text that tries to leave the place a template puts it in.
var hostile = []string{
	`<script>alert(1)</script>`,
	`"><img src=x onerror=alert(2)>`,
	`' onmouseover='alert(3)`,
	`</td></tr></table><h1>gone</h1>`,
	`a b?c#d%2Fe&f=g`,
	`javascript:alert(4)`,
	`{{.Name}} ]]> <!-- -->`,
}

// hostileName is the hostile string as a system may be called: a report whose name has a slash
// is refused before it is stored (report.Validate), every other character gets through.
func hostileName(x string) string { return strings.ReplaceAll(x, "/", "") }

// hostileStore holds one system per hostile string, with that string in every field a report
// has, and the same strings in the image checks.
func hostileStore(t *testing.T) (store.Store, []model.Finding) {
	t.Helper()
	s := store.NewMemory()
	var findings []model.Finding
	for _, x := range hostile {
		r := report.Report{
			Schema: report.Schema,
			System: report.System{Name: hostileName(x), Kind: x, OS: x, OSVersion: x, Kernel: x, Arch: x, Source: "agent", AgentVersion: x},
			Sent:   testNow,
			Packages: &report.Packages{
				Manager: x, Pending: 2, Security: 1, RebootRequired: true, RebootReason: x,
				Items:    []report.PackageUpdate{{Name: x, Installed: x, Candidate: x, Security: true}},
				KeptBack: []report.PackageUpdate{{Name: x, Installed: x, Candidate: x, Reason: x}},
			},
			Software:   []report.Software{{Name: x, Kind: x, Installed: x, Latest: x, UpdateAvailable: true, URL: x, Detail: x}},
			Containers: []report.Container{{Name: x, Image: x, ImageID: x, Digest: x, Digests: []string{x}, State: x, AutoUpdate: x, Runtime: x}},
			Backups:    []report.Backup{{Name: x, Kind: x, LastResult: x, Detail: x}},
			Errors:     []report.Problem{{Collector: x, Message: x}},
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("the hostile name %q would never be stored: %v", hostileName(x), err)
		}
		if err := s.SaveReport(context.Background(), &r, testNow); err != nil {
			t.Fatal(err)
		}
		check := model.ImageCheck{Image: x, Tag: x, TagDigest: x + "!", NewerPatch: x, NewerMinor: x, NewerMajor: x, Error: x, Note: x, CheckedAt: testNow}
		if err := s.SaveImageCheck(context.Background(), check); err != nil {
			t.Fatal(err)
		}
		findings = append(findings, model.Finding{System: hostileName(x), Category: model.Category(x), Severity: model.Crit, Title: x, Detail: x})
	}
	return s, findings
}

// TestEscaping proves that hostile text in reports, checks and findings comes out as text:
// the pages stay well-formed, gain no element or attribute, and every link still leads to
// the system it names.
func TestEscaping(t *testing.T) {
	s, findings := hostileStore(t)
	h := handlerFor(s, func([]model.SystemState, map[string]model.ImageCheck, time.Time, model.Policy) []model.Finding {
		return findings
	})

	var systemLinks []string
	for _, path := range []string{"/", "/updates", "/backups"} {
		t.Run(path, func(t *testing.T) {
			rec := get(t, h, path)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d", path, rec.Code)
			}
			// checkPage fails on any script, event handler, style or outside address.
			doc := checkPage(t, rec)
			for _, x := range hostile {
				if !strings.Contains(doc.text, strings.Join(strings.Fields(x), " ")) {
					t.Errorf("%q is not shown as plain text", x)
				}
			}
			count := map[string]int{}
			for _, e := range doc.elements {
				count[e.name]++
				if e.name != "a" {
					continue
				}
				href := e.attrs["href"]
				if strings.HasPrefix(href, "./systems/") && path == "/" {
					systemLinks = append(systemLinks, strings.TrimPrefix(href, "./"))
				}
				// "javascript:" inside a path is a name; at the front it would be code.
				if u, err := url.Parse(href); err != nil || u.Scheme != "" {
					t.Errorf("a link that is not a plain address on this server: %q", href)
				}
			}
			// The templates write one heading and no picture; more would have come from data.
			if count["h1"] != 1 || count["img"] != 0 {
				t.Errorf("elements appeared that no template writes: %d h1, %d img", count["h1"], count["img"])
			}
		})
	}

	// Every system's own page is reachable through its link, and holds too.
	seen := map[string]bool{}
	for _, href := range systemLinks {
		if seen[href] {
			continue
		}
		seen[href] = true
		t.Run(href, func(t *testing.T) {
			rec := get(t, h, "/"+href)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /%s = %d, the link does not lead to the system", href, rec.Code)
			}
			doc := checkPage(t, rec)
			count := map[string]int{}
			for _, e := range doc.elements {
				count[e.name]++
				if e.name == "a" && e.attrs["rel"] == "noopener noreferrer" {
					t.Errorf("a release notes link was made from %q", e.attrs["href"])
				}
			}
			if count["h1"] != 1 || count["img"] != 0 {
				t.Errorf("elements appeared that no template writes: %d h1, %d img", count["h1"], count["img"])
			}
			raw := get(t, h, "/"+href+"/report.json")
			if raw.Code != http.StatusOK || !json.Valid(raw.Body.Bytes()) {
				t.Errorf("the raw report behind %s is not served as JSON (status %d)", href, raw.Code)
			}
		})
	}
	if len(seen) != len(hostile) {
		t.Errorf("the overview links to %d systems, want %d", len(seen), len(hostile))
	}
}

// TestLinks follows every address on every page. Once at "/", once under a prefix the way a
// reverse proxy may mount the dashboard: links are relative, so both must work.
func TestLinks(t *testing.T) {
	inner := demoHandler(t)
	mounts := []struct {
		name   string
		prefix string
		h      http.Handler
	}{
		{"at the root", "", inner},
		{"under a prefix", "/tools/upkeep", http.StripPrefix("/tools/upkeep", inner)},
	}
	for _, m := range mounts {
		t.Run(m.name, func(t *testing.T) {
			queue := []string{m.prefix + "/"}
			seen := map[string]bool{queue[0]: true}
			pages, outside := 0, 0
			for len(queue) > 0 {
				at := queue[0]
				queue = queue[1:]
				rec := get(t, m.h, at)
				if rec.Code != http.StatusOK {
					t.Errorf("GET %s = %d", at, rec.Code)
					continue
				}
				if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
					continue
				}
				pages++
				base, err := url.Parse(at)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range parsePage(t, rec.Body.String()).elements {
					for _, attr := range []string{"href", "src"} {
						ref, ok := e.attrs[attr]
						if !ok {
							continue
						}
						u, err := base.Parse(ref)
						if err != nil {
							t.Errorf("%s: unusable address %q", at, ref)
							continue
						}
						if u.Host != "" {
							outside++
							continue
						}
						if !strings.HasPrefix(u.Path, m.prefix+"/") {
							t.Errorf("%s: %q leaves the dashboard: %s", at, ref, u.Path)
							continue
						}
						if u.Fragment != "" && u.Path == base.Path {
							continue // a jump within the page; ids are checked below
						}
						u.Fragment = ""
						if next := u.String(); !seen[next] {
							seen[next] = true
							queue = append(queue, next)
						}
					}
				}
			}
			// 3 pages and 7 systems.
			if pages != 10 {
				t.Errorf("reached %d pages by following links, want 10", pages)
			}
			if outside == 0 {
				t.Error("no release notes link was found")
			}
		})
	}
}

// TestJumpLinks checks that every link within a page has a target.
func TestJumpLinks(t *testing.T) {
	h := demoHandler(t)
	for _, path := range []string{"/", "/updates"} {
		doc := checkPage(t, get(t, h, path))
		ids := map[string]bool{}
		for _, e := range doc.elements {
			ids[e.attrs["id"]] = true
		}
		jumps := 0
		for _, e := range doc.elements {
			if href := e.attrs["href"]; e.name == "a" && strings.HasPrefix(href, "#") {
				jumps++
				if !ids[href[1:]] {
					t.Errorf("%s: the link %q has no target", path, href)
				}
			}
		}
		if jumps == 0 {
			t.Errorf("%s: no link within the page", path)
		}
	}
}

func TestStatic(t *testing.T) {
	h := demoHandler(t)
	page := checkPage(t, get(t, h, "/"))
	var refs []string
	for _, e := range page.elements {
		for _, attr := range []string{"href", "src"} {
			if ref := e.attrs[attr]; strings.HasPrefix(ref, "./static/") {
				refs = append(refs, strings.TrimPrefix(ref, "."))
			}
		}
	}
	if len(refs) != 4 {
		t.Fatalf("the overview loads %d static files, want the stylesheet, the icon and two scripts: %v", len(refs), refs)
	}
	types := map[string]string{".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
	for _, ref := range refs {
		t.Run(ref, func(t *testing.T) {
			name, _, _ := strings.Cut(ref, "?")
			rec := get(t, h, ref)
			if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
				t.Fatalf("GET %s = %d with %d bytes", ref, rec.Code, rec.Body.Len())
			}
			if got, want := rec.Header().Get("Content-Type"), types[name[strings.LastIndex(name, "."):]]; got != want {
				t.Errorf("Content-Type = %q, want %q", got, want)
			}
			// The address carries the content's version: keep it for good.
			if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
				t.Errorf("Cache-Control with the version = %q", got)
			}
			checkSecurityHeaders(t, rec.Header())

			// Without the version, or with an old one, the browser must ask each time...
			for _, stale := range []string{name, name + "?v=0000"} {
				plain := get(t, h, stale)
				if got := plain.Header().Get("Cache-Control"); plain.Code != http.StatusOK || got != "no-cache" {
					t.Errorf("GET %s = %d, Cache-Control %q, want 200 and no-cache", stale, plain.Code, got)
				}
			}
			// ...and gets a short answer when nothing changed.
			etag := rec.Header().Get("ETag")
			if etag == "" {
				t.Fatal("no ETag")
			}
			req := httptest.NewRequest(http.MethodGet, name, nil)
			req.Header.Set("If-None-Match", etag)
			again := httptest.NewRecorder()
			h.ServeHTTP(again, req)
			if again.Code != http.StatusNotModified || again.Body.Len() != 0 {
				t.Errorf("GET %s with the ETag = %d with %d bytes, want 304 and none", name, again.Code, again.Body.Len())
			}
		})
	}
}

// TestStaticIsSelfContained looks into the embedded files for anything a browser would fetch
// from another host.
func TestStaticIsSelfContained(t *testing.T) {
	files, _ := loadStatic()
	for name, a := range files {
		body := string(a.body)
		for _, bad := range []string{"http://", "https://", "//fonts", "@import", "url("} {
			if name == "favicon.svg" && bad == "http://" {
				continue // the SVG namespace is a name, nothing is fetched
			}
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
	for _, name := range []string{"app.css", "app.js", "theme.js", "favicon.svg"} {
		if _, ok := files[name]; !ok {
			t.Errorf("%s is not embedded", name)
		}
	}
}

func TestRawReport(t *testing.T) {
	s := demoStore(t)
	h := handlerFor(s, demoFindings)
	rec := get(t, h, "/systems/storage/report.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	checkSecurityHeaders(t, rec.Header())
	var got report.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	want, err := s.System(context.Background(), "storage")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want.Report)
	if string(a) != string(b) {
		t.Errorf("the served report differs from the stored one:\n%s\n%s", a, b)
	}
}

func TestMethods(t *testing.T) {
	h := demoHandler(t)
	// HEAD is GET without the body.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("HEAD / = %d", rec.Code)
	}
	// The dashboard only shows things: nothing can be sent to it.
	for _, path := range []string{"/", "/updates", "/systems/server"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("x=1")))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want it refused", path, rec.Code)
		}
	}
}

// brokenStore fails the way a database does, with details that are nobody's business.
type brokenStore struct{ store.Store }

var errSecretPath = errors.New("open /var/lib/upkeep/secret-place/upkeep.db: permission denied")

func (brokenStore) Systems(context.Context) ([]model.SystemState, error) { return nil, errSecretPath }

func TestStoreError(t *testing.T) {
	// The handler logs the cause, as it should; the test's output does not need it.
	old := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	defer slog.SetDefault(old)

	tests := []struct {
		name  string
		store store.Store
	}{
		{"the store fails", brokenStore{store.NewMemory()}},
		{"no store at all", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := handlerFor(tc.store, noFindings)
			for _, path := range []string{"/", "/updates", "/backups", "/systems/server", "/systems/server/report.json"} {
				rec := get(t, h, path)
				if rec.Code != http.StatusInternalServerError {
					t.Errorf("GET %s = %d, want 500", path, rec.Code)
				}
				if strings.Contains(rec.Body.String(), "secret-place") {
					t.Errorf("GET %s shows the store's error to the browser", path)
				}
				wantText(t, checkPage(t, rec), "The stored state could not be read.")
			}
		})
	}
}

// TestRealFindings runs the pages with model.Findings itself, whatever it says today, and with
// everything a caller may leave out left out.
func TestRealFindings(t *testing.T) {
	tests := []struct {
		name   string
		policy model.Policy
		want   []string
	}{
		{"the default policy", model.DefaultPolicy(), []string{"Systems 7 1 silent", "ops01 4 no 2 of 6 newer — late"}},
		// As for model.Findings, a threshold of zero is a rule switched off.
		{"no thresholds", model.Policy{}, []string{"Systems 7 all reporting", "ops01 4 no 2 of 6 newer — ok"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := Handler(Options{Store: demoStore(t), Policy: tc.policy, Now: func() time.Time { return testNow }})
			for _, path := range []string{"/", "/updates", "/backups", "/systems/server", "/systems/dns02", "/systems/homeassistant"} {
				rec := get(t, h, path)
				if rec.Code != http.StatusOK {
					t.Errorf("GET %s = %d", path, rec.Code)
					continue
				}
				doc := checkPage(t, rec)
				wantText(t, doc, "upkeep dev")
				if path == "/" {
					wantText(t, doc, tc.want...)
				}
			}
		})
	}
}

// TestFindingsDecideTheColour checks that a cell of the overview takes its state from the
// findings when they speak about it, and keeps its own reading when they do not.
func TestFindingsDecideTheColour(t *testing.T) {
	s := demoStore(t)
	reboot := func(sv sysView) mark { return sv.RebootMark }
	packages := func(sv sysView) mark { return sv.OSMark }
	tests := []struct {
		name     string
		findings []model.Finding
		system   string
		cell     func(sysView) mark
		want     mark
	}{
		{"no finding: the row's own reading", nil,
			"server", reboot, mark{toneWarn, "waiting", "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"}},
		{"the findings call it news", []model.Finding{{System: "server", Category: model.CategoryReboot, Severity: model.Info}},
			"server", reboot, mark{toneInfo, "waiting", "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"}},
		{"the findings call it broken", []model.Finding{{System: "server", Category: model.CategoryReboot, Severity: model.Crit}},
			"server", reboot, mark{toneCrit, "waiting", "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"}},
		{"the worst of several findings counts", []model.Finding{
			{System: "server", Category: model.CategoryReboot, Severity: model.Info},
			{System: "server", Category: model.CategoryReboot, Severity: model.Crit},
			{System: "server", Category: model.CategoryReboot, Severity: model.Warn},
		}, "server", reboot, mark{toneCrit, "waiting", "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"}},
		{"a finding about something else", []model.Finding{{System: "server", Category: model.CategoryBackup, Severity: model.Crit}},
			"server", reboot, mark{toneWarn, "waiting", "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"}},
		{"a finding about another system", []model.Finding{{System: "ops01", Category: model.CategoryReboot, Severity: model.Crit}},
			"server", reboot, mark{toneWarn, "waiting", "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"}},
		{"a severity from a newer build", []model.Finding{{System: "server", Category: model.CategoryReboot, Severity: model.Severity(9)}},
			"server", reboot, mark{toneCrit, "waiting", "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"}},
		{"a severity below the known ones", []model.Finding{{System: "server", Category: model.CategoryReboot, Severity: model.Severity(-3)}},
			"server", reboot, mark{toneInfo, "waiting", "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"}},
		// dns02 has nothing pending, but its package lists are days old and the findings say so.
		{"nothing pending and nothing found", nil,
			"dns02", packages, mark{toneOK, "none", ""}},
		{"nothing pending, but the findings doubt it", []model.Finding{{System: "dns02", Category: model.CategoryOS, Severity: model.Warn}},
			"dns02", packages, mark{toneWarn, "none known", "the list above says why"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			states, _ := s.Systems(context.Background())
			snap := &snapshot{states: states, findings: tc.findings, now: testNow, policy: model.DefaultPolicy()}
			found := false
			for _, sv := range snap.systemViews("./") {
				if sv.Name == tc.system {
					found = true
					if got := tc.cell(sv); got != tc.want {
						t.Errorf("cell is %+v, want %+v", got, tc.want)
					}
				}
			}
			if !found {
				t.Fatalf("no system %s", tc.system)
			}
			// And the page still renders, whatever the severity.
			h := handlerFor(s, func([]model.SystemState, map[string]model.ImageCheck, time.Time, model.Policy) []model.Finding {
				return tc.findings
			})
			if rec := get(t, h, "/"); rec.Code != http.StatusOK {
				t.Errorf("GET / = %d", rec.Code)
			}
		})
	}
}

// What a report says beside "pending": packages an upgrade would leave alone, a registry
// answer that may be incomplete, and a container whose running image is not known. None of
// them may read as "all is well".
func TestHeldBackNotesAndUnknownImages(t *testing.T) {
	const index, amd64 = "sha256:1111111111111111111111111111111111111111111111111111111111111111", "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	s := store.NewMemory()
	r := report.Report{
		Schema: report.Schema,
		System: report.System{Name: "held", Kind: "linux", Source: "agent"},
		Sent:   testNow,
		Packages: &report.Packages{
			Manager: "apt",
			KeptBack: []report.PackageUpdate{
				{Name: "libssl3t64", Installed: "3.5.1-1", Candidate: "3.5.7-1~deb13u3", Reason: "held"},
				{Name: "tzdata", Installed: "2025b-4", Candidate: "2026f-0+deb13u1", Reason: "kept back"},
			},
		},
		Containers: []report.Container{
			// Known by two digests, of which the registry names one: up to date.
			{Name: "mongo", Image: "docker.io/library/mongo:7.0.48", Digest: amd64, Digests: []string{index, amd64}, State: "running"},
			// The report does not say which image runs.
			{Name: "nameless", Image: "docker.io/library/redis:6", State: "running"},
		},
	}
	if err := s.SaveReport(context.Background(), &r, testNow); err != nil {
		t.Fatal(err)
	}
	for _, c := range []model.ImageCheck{
		{Image: "docker.io/library/mongo:7.0.48", Tag: "7.0.48", TagDigest: index, CheckedAt: testNow,
			Note: "only the first 10000 tags of docker.io/library/mongo were read, newer ones may be missing"},
		{Image: "docker.io/library/redis:6", Tag: "6", TagDigest: index, CheckedAt: testNow},
	} {
		if err := s.SaveImageCheck(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	h := handlerFor(s, model.Findings)

	overview := checkPage(t, get(t, h, "/"))
	wantText(t, overview,
		"Container updates 0 1 of 2 unchecked", // not "all 2 current"
		"2 package updates held back",          // the finding
		"on hold: libssl3t64",
		"held 2 held back no 1 of 2 unchecked", // the system's row
	)

	system := checkPage(t, get(t, h, "/systems/held"))
	wantText(t, system,
		"2 newer versions held back, not counted above",
		"libssl3t64 3.5.1-1 3.5.7-1~deb13u3 held",
		"tzdata 2025b-4 2026f-0+deb13u1 kept back",
		"up to date only the first 10000 tags of docker.io/library/mongo were read",
		"no newer tag",
	)
	if strings.Contains(system.text, "was rebuilt") {
		t.Error("an image known by the digest the tag points at is shown as rebuilt")
	}
}

// A polled system whose connector fails has reported nothing new: the first tile must not
// call that "all reporting", also before it has been quiet long enough to count as silent.
func TestUnreachedConnectorIsNotAllReporting(t *testing.T) {
	s := store.NewMemory()
	for _, r := range []report.Report{
		{Schema: report.Schema, System: report.System{Name: "server", Kind: "linux", Source: "agent"}, Sent: testNow},
		{Schema: report.Schema, System: report.System{Name: "opnsense", Kind: "opnsense", Source: "connector"}, Sent: testNow,
			Errors: []report.Problem{{Collector: model.ConnectorProblem, Message: "no answer within 15s"}}},
	} {
		if err := s.SaveReport(context.Background(), &r, testNow.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	doc := checkPage(t, get(t, handlerFor(s, model.Findings), "/"))
	wantText(t, doc, "Systems 2 1 not answering", "connector failed", "opnsense — — — — —")
	if strings.Contains(doc.text, "all reporting") {
		t.Error("the overview says that all systems are reporting")
	}
}
