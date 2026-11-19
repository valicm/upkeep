// Package web is the dashboard: the pages someone opens to see what needs doing.
//
//	/                            the numbers, the list "needs attention" and every system in one table
//	/updates                     everything that can be updated, system by system
//	/backups                     every backup of every system
//	/systems/{name}              all of one system, with its raw report
//	/systems/{name}/report.json  that report alone
//	/static/{file}               the stylesheet, two scripts and the icon
//
// The pages are rendered on the server and are complete without JavaScript. Every address in
// them is relative, so a reverse proxy may serve the dashboard at "/" or under any prefix it
// strips. What needs attention is decided by model.Findings alone; this package only adds how
// to show one row: which word, which mark.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/store"
)

// Everything the browser needs is inside the binary: the dashboard asks no other host for
// anything.
//
//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Options is what the dashboard needs from the server.
type Options struct {
	Store   store.Store
	Policy  model.Policy     // as for model.Findings: a threshold of zero is switched off
	Now     func() time.Time // nil: time.Now
	Version string           // shown in the footer

	// findings stands in for model.Findings in this package's tests.
	findings findingsFunc
}

type findingsFunc func([]model.SystemState, map[string]model.ImageCheck, time.Time, model.Policy) []model.Finding

// contentSecurityPolicy lets the browser load this origin's own stylesheet, scripts and icon and
// nothing else: no inline code, no frames, no forms. Whatever a report smuggles into a page can
// then at worst show up as text.
const contentSecurityPolicy = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; " +
	"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// storeTimeout bounds one page's reads, so a stuck database gives an error page and not a
// browser tab that spins forever.
const storeTimeout = 10 * time.Second

// Handler serves the dashboard's pages and its static files.
func Handler(opts Options) http.Handler {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.findings == nil {
		opts.findings = model.Findings
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	d := &dashboard{opts: opts, pages: parsePages()}
	d.static, d.asset = loadStatic()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.overview)
	mux.HandleFunc("GET /updates", d.updates)
	mux.HandleFunc("GET /backups", d.backups)
	mux.HandleFunc("GET /systems/{name}", d.system)
	mux.HandleFunc("GET /systems/{name}/report.json", d.rawReport)
	mux.HandleFunc("GET /static/{file}", d.staticFile)
	mux.HandleFunc("/", d.notFound)
	return secure(mux)
}

type dashboard struct {
	opts   Options
	pages  map[string]*template.Template
	static map[string]asset
	asset  string // changes whenever a static file does
}

// secure sets the headers every response carries.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// Release notes are on other hosts: they need not learn this dashboard's address.
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// parsePages builds one template set per page: the layout, the shared parts and the page.
func parsePages() map[string]*template.Template {
	pages := map[string]*template.Template{}
	for _, name := range []string{"overview", "updates", "backups", "system", "message"} {
		pages[name] = template.Must(template.New("layout.html").Funcs(template.FuncMap{"count": count}).ParseFS(templateFS,
			"templates/layout.html", "templates/parts.html", "templates/"+name+".html"))
	}
	return pages
}

// asset is one embedded static file.
type asset struct {
	body  []byte
	ctype string
}

var contentTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
	".svg": "image/svg+xml",
}

// loadStatic reads the embedded files and derives one version from all of them. The pages put
// that version into the files' addresses, which is what lets a browser keep them for good.
func loadStatic() (map[string]asset, string) {
	entries, err := staticFS.ReadDir("static")
	if err != nil {
		panic("web: read embedded static files: " + err.Error())
	}
	files := map[string]asset{}
	sum := sha256.New()
	for _, e := range entries {
		body, err := staticFS.ReadFile("static/" + e.Name())
		if err != nil {
			panic("web: read embedded " + e.Name() + ": " + err.Error())
		}
		ctype, ok := contentTypes[path.Ext(e.Name())]
		if !ok {
			panic("web: no content type for embedded " + e.Name())
		}
		files[e.Name()] = asset{body: body, ctype: ctype}
		fmt.Fprintf(sum, "%s %d\n", e.Name(), len(body))
		sum.Write(body)
	}
	return files, hex.EncodeToString(sum.Sum(nil))[:12]
}

func (d *dashboard) staticFile(w http.ResponseWriter, r *http.Request) {
	a, ok := d.static[r.PathValue("file")]
	if !ok {
		d.notFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.ctype)
	h.Set("ETag", `"`+d.asset+`"`)
	if r.URL.Query().Get("v") == d.asset {
		// The address names this exact content, so the browser never has to ask again.
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(a.body))
}

// rootFor returns the relative path from the requested page back to "/". It counts the path
// as the browser sees it, escapes included.
func rootFor(r *http.Request) string {
	if n := strings.Count(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/"); n > 0 {
		return strings.Repeat("../", n)
	}
	return "./"
}

func (d *dashboard) page(r *http.Request, now time.Time, nav, title string) page {
	return page{
		Live:      true,
		Title:     title,
		Nav:       nav,
		Root:      rootFor(r),
		Asset:     d.asset,
		Version:   d.opts.Version,
		Generated: newTimeView(now, now),
		Clock:     now.Format("15:04:05"),
	}
}

// load reads the state once for one request and derives the findings from it.
func (d *dashboard) load(r *http.Request) (*snapshot, error) {
	if d.opts.Store == nil {
		return nil, errors.New("no store configured")
	}
	ctx, cancel := context.WithTimeout(r.Context(), storeTimeout)
	defer cancel()
	states, err := d.opts.Store.Systems(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the systems: %w", err)
	}
	checks, err := d.opts.Store.ImageChecks(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the image checks: %w", err)
	}
	now := d.opts.Now()
	return &snapshot{
		states:   states,
		checks:   checks,
		findings: d.opts.findings(states, checks, now, d.opts.Policy),
		now:      now,
		policy:   d.opts.Policy,
	}, nil
}

// loadOrFail is load for a handler: on an error it has answered the request already.
func (d *dashboard) loadOrFail(w http.ResponseWriter, r *http.Request) *snapshot {
	snap, err := d.load(r)
	if err != nil {
		// The cause goes to the log only: it may name files and addresses.
		slog.Error("web: load state", "path", r.URL.Path, "err", err)
		d.message(w, r, http.StatusInternalServerError, "Something went wrong",
			"The stored state could not be read. The server's log says why.")
		return nil
	}
	return snap
}

func (d *dashboard) overview(w http.ResponseWriter, r *http.Request) {
	if snap := d.loadOrFail(w, r); snap != nil {
		d.render(w, r, http.StatusOK, "overview", snap.overview(d.page(r, snap.now, "overview", "Overview")))
	}
}

func (d *dashboard) updates(w http.ResponseWriter, r *http.Request) {
	if snap := d.loadOrFail(w, r); snap != nil {
		d.render(w, r, http.StatusOK, "updates", snap.updates(d.page(r, snap.now, "updates", "Updates")))
	}
}

func (d *dashboard) backups(w http.ResponseWriter, r *http.Request) {
	if snap := d.loadOrFail(w, r); snap != nil {
		d.render(w, r, http.StatusOK, "backups", snap.backups(d.page(r, snap.now, "backups", "Backups")))
	}
}

// find returns the state of one system from a snapshot.
func (s *snapshot) find(name string) (model.SystemState, bool) {
	for _, st := range s.states {
		if st.Report.System.Name == name {
			return st, true
		}
	}
	return model.SystemState{}, false
}

func (d *dashboard) system(w http.ResponseWriter, r *http.Request) {
	snap := d.loadOrFail(w, r)
	if snap == nil {
		return
	}
	name := r.PathValue("name")
	st, ok := snap.find(name)
	if !ok {
		d.unknownSystem(w, r, name)
		return
	}
	raw, err := json.MarshalIndent(st.Report, "", "  ")
	if err != nil {
		slog.Error("web: encode report", "system", name, "err", err)
		raw = []byte("the report could not be shown as JSON")
	}
	p := d.page(r, snap.now, "", name)
	d.render(w, r, http.StatusOK, "system", systemPage{
		page:    p,
		S:       snap.systemView(st, p.Root, newVerdicts(snap.findings), anchors{}),
		Raw:     string(raw),
		RawHref: systemHref(p.Root, name) + "/report.json",
	})
}

// rawReport serves the stored report exactly as a source sent it, for scripts and for reading.
func (d *dashboard) rawReport(w http.ResponseWriter, r *http.Request) {
	snap := d.loadOrFail(w, r)
	if snap == nil {
		return
	}
	name := r.PathValue("name")
	st, ok := snap.find(name)
	if !ok {
		d.unknownSystem(w, r, name)
		return
	}
	raw, err := json.MarshalIndent(st.Report, "", "  ")
	if err != nil {
		slog.Error("web: encode report", "system", name, "err", err)
		d.message(w, r, http.StatusInternalServerError, "Something went wrong", "The report could not be shown as JSON.")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.Write(append(raw, '\n'))
}

func (d *dashboard) unknownSystem(w http.ResponseWriter, r *http.Request, name string) {
	d.message(w, r, http.StatusNotFound, "Unknown system", "No system called “"+name+"” has reported to this server.")
}

func (d *dashboard) notFound(w http.ResponseWriter, r *http.Request) {
	d.message(w, r, http.StatusNotFound, "Not found", "There is no such page.")
}

type messagePage struct {
	page
	Text string
}

// message answers with a page that only says one thing: an error, or that something is not
// there.
func (d *dashboard) message(w http.ResponseWriter, r *http.Request, status int, title, text string) {
	p := d.page(r, d.opts.Now(), "", title)
	p.Live = false // an error that reloads itself every minute helps nobody
	d.render(w, r, status, "message", messagePage{page: p, Text: text})
}

// render builds the whole page before it sends anything, so a template that fails gives a
// clean error and never half a page.
func (d *dashboard) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := d.pages[name].ExecuteTemplate(&buf, "layout.html", data); err != nil {
		slog.Error("web: build page", "page", name, "path", r.URL.Path, "err", err)
		http.Error(w, "the page could not be built", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// The page is the state of this moment: a stored copy would be a lie.
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}
