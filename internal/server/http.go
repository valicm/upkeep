package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/store"
)

const (
	// maxReportBytes is far more than a report needs: 300 packages and 100 containers are
	// about 100 KiB.
	maxReportBytes = 1 << 20
	// storeTimeout bounds what one request may spend in the database.
	storeTimeout = 10 * time.Second
)

// api is the server's HTTP side: reports come in, the state goes out, and everything else is
// the dashboard's.
type api struct {
	store   store.Store
	policy  model.Policy
	now     func() time.Time
	log     *slog.Logger
	version string

	agentToken   *secretHash           // the shared token; nil when there is none
	systemTokens map[string]secretHash // tokens that may report one name only
	polled       map[string]bool       // names that belong to connectors

	dashboardUser     string // empty: the dashboard asks for no password
	dashboardPassword *secretHash
	dashboard         http.Handler
}

func (a *api) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/report", a.report)
	mux.HandleFunc("/api/v1/state", a.state)
	mux.HandleFunc("/api/v1/systems/", a.forget)
	mux.HandleFunc("/healthz", a.health)
	mux.HandleFunc("/", a.pages)
	return mux
}

// respond writes a JSON answer. Answers of the API are never to be kept or guessed at.
func respond(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func refuse(w http.ResponseWriter, status int, why string) {
	respond(w, status, map[string]string{"error": why})
}

// allow answers a request with the wrong method and reports whether the method was right.
func allow(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	refuse(w, http.StatusMethodNotAllowed, "only "+method+" is allowed here")
	return false
}

// bearer says whose token a request carries: the shared one, the one of a single system, or
// none that is known. Every known token is compared, so the time taken does not tell which
// one came close.
func (a *api) bearer(r *http.Request) (shared bool, system string, ok bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return false, "", false
	}
	shared = a.agentToken.matches(token)
	for name, hash := range a.systemTokens {
		if hash.matches(token) {
			system = name
		}
	}
	return shared, system, shared || system != ""
}

func (a *api) unauthorized(w http.ResponseWriter, r *http.Request) {
	a.log.Warn("request without a valid token", "path", r.URL.Path, "from", r.RemoteAddr)
	w.Header().Set("WWW-Authenticate", `Bearer realm="upkeep"`)
	refuse(w, http.StatusUnauthorized, "a valid token is needed: Authorization: Bearer <token>")
}

// report takes one report from an agent.
func (a *api) report(w http.ResponseWriter, r *http.Request) {
	if !allow(w, r, http.MethodPost) {
		return
	}
	shared, system, ok := a.bearer(r)
	if !ok {
		a.unauthorized(w, r)
		return
	}

	if enc := r.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		// Said plainly, instead of "invalid character" for a body that is compressed.
		refuse(w, http.StatusUnsupportedMediaType, "send the report as plain JSON, not with Content-Encoding "+enc)
		return
	}
	var rep report.Report
	var tooBig *http.MaxBytesError
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReportBytes))
	err := dec.Decode(&rep)
	if err == nil {
		// One report and nothing after it.
		switch _, after := dec.Token(); {
		case after == io.EOF:
		case errors.As(after, &tooBig):
			err = after
		default:
			err = errors.New("something follows the report")
		}
	}
	switch {
	case errors.As(err, &tooBig):
		refuse(w, http.StatusRequestEntityTooLarge, "the report is larger than 1 MiB")
		return
	case err != nil:
		refuse(w, http.StatusBadRequest, "the body is not a report: "+err.Error())
		return
	}

	// Whatever came in over this endpoint came from an agent, whatever it says about itself.
	rep.System.Source = "agent"
	rep.System.Name = strings.TrimSpace(rep.System.Name)
	if err := rep.Validate(); err != nil {
		refuse(w, http.StatusBadRequest, "the report is not usable: "+err.Error())
		return
	}
	name := rep.System.Name
	_, hasOwnToken := a.systemTokens[name]
	switch {
	case system != "" && system != name:
		a.log.Warn("report refused: the token belongs to another system", "token_of", system, "reported", name, "from", r.RemoteAddr)
		refuse(w, http.StatusForbidden, "this token may only report "+system)
		return
	case system == "" && shared && hasOwnToken:
		a.log.Warn("report refused: the system has a token of its own", "reported", name, "from", r.RemoteAddr)
		refuse(w, http.StatusForbidden, name+" has a token of its own and must use it")
		return
	case a.polled[name]:
		a.log.Warn("report refused: the name belongs to a connector", "reported", name, "from", r.RemoteAddr)
		refuse(w, http.StatusConflict, name+" is polled by the server and cannot be reported by an agent")
		return
	}
	if p := rep.Packages; p != nil {
		p.Items = p.Items[:min(len(p.Items), report.MaxItems)]
		p.KeptBack = p.KeptBack[:min(len(p.KeptBack), report.MaxItems)]
	}

	ctx, cancel := context.WithTimeout(r.Context(), storeTimeout)
	defer cancel()
	if err := a.store.SaveReport(ctx, &rep, a.now()); err != nil {
		a.log.Error("report not stored", "system", name, "error", err)
		refuse(w, http.StatusInternalServerError, "the report could not be stored")
		return
	}
	a.log.Info("report stored", "system", name, "from", r.RemoteAddr)
	respond(w, http.StatusOK, map[string]string{"status": "stored", "system": name})
}

// The state as scripts read it. The field names are part of the interface: only add.
type stateJSON struct {
	Generated   time.Time        `json:"generated"`
	Version     string           `json:"version"`
	Systems     []systemJSON     `json:"systems"`
	ImageChecks []imageCheckJSON `json:"image_checks"`
	Findings    []findingJSON    `json:"findings"`
}

type systemJSON struct {
	Name       string        `json:"name"`
	ReceivedAt time.Time     `json:"received_at"`
	Report     report.Report `json:"report"`
}

type imageCheckJSON struct {
	Image      string    `json:"image"`
	Tag        string    `json:"tag,omitempty"`
	TagDigest  string    `json:"tag_digest,omitempty"`
	NewerPatch string    `json:"newer_patch,omitempty"`
	NewerMinor string    `json:"newer_minor,omitempty"`
	NewerMajor string    `json:"newer_major,omitempty"`
	CheckedAt  time.Time `json:"checked_at,omitzero"`
	Error      string    `json:"error,omitempty"`
	Note       string    `json:"note,omitempty"`
}

type findingJSON struct {
	System   string `json:"system"`
	Category string `json:"category"`
	Severity string `json:"severity"` // "info", "warn", "crit"
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

// state gives everything the dashboard shows, as JSON. It names every machine and what is
// out of date on it, so only the shared token opens it: a token that may report one system
// is not meant to read about all the others.
func (a *api) state(w http.ResponseWriter, r *http.Request) {
	if !allow(w, r, http.MethodGet) {
		return
	}
	if shared, _, _ := a.bearer(r); !shared {
		a.unauthorized(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), storeTimeout)
	defer cancel()
	systems, err := a.store.Systems(ctx)
	var checks map[string]model.ImageCheck
	if err == nil {
		checks, err = a.store.ImageChecks(ctx)
	}
	if err != nil {
		a.log.Error("state not read", "error", err)
		refuse(w, http.StatusInternalServerError, "the state could not be read")
		return
	}
	now := a.now()
	out := stateJSON{
		Generated: now, Version: a.version,
		Systems: []systemJSON{}, ImageChecks: []imageCheckJSON{}, Findings: []findingJSON{},
	}
	for _, s := range systems {
		out.Systems = append(out.Systems, systemJSON{Name: s.Report.System.Name, ReceivedAt: s.ReceivedAt, Report: s.Report})
	}
	for _, c := range checks {
		out.ImageChecks = append(out.ImageChecks, imageCheckJSON{
			Image: c.Image, Tag: c.Tag, TagDigest: c.TagDigest, NewerPatch: c.NewerPatch,
			NewerMinor: c.NewerMinor, NewerMajor: c.NewerMajor, CheckedAt: c.CheckedAt, Error: c.Error, Note: c.Note,
		})
	}
	sort.Slice(out.ImageChecks, func(i, j int) bool { return out.ImageChecks[i].Image < out.ImageChecks[j].Image })
	for _, f := range model.Findings(systems, checks, now, a.policy) {
		out.Findings = append(out.Findings, findingJSON{
			System: f.System, Category: string(f.Category), Severity: f.Severity.String(), Title: f.Title, Detail: f.Detail,
		})
	}
	respond(w, http.StatusOK, out)
}

// forget removes a system that no longer exists: a machine that was taken out of service
// would otherwise stay on the dashboard as silent for ever. One that is still there comes
// back with its next report, so nothing is lost by forgetting the wrong one. Like the state,
// it takes the shared token.
func (a *api) forget(w http.ResponseWriter, r *http.Request) {
	if !allow(w, r, http.MethodDelete) {
		return
	}
	if shared, _, _ := a.bearer(r); !shared {
		a.unauthorized(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/systems/")
	if name == "" || strings.Contains(name, "/") {
		refuse(w, http.StatusNotFound, "name the system: DELETE /api/v1/systems/<name>")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), storeTimeout)
	defer cancel()
	_, err := a.store.System(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		refuse(w, http.StatusNotFound, "no system called "+name+" has reported")
		return
	}
	if err == nil {
		err = a.store.DeleteSystem(ctx, name)
	}
	if err != nil {
		a.log.Error("system not forgotten", "system", name, "error", err)
		refuse(w, http.StatusInternalServerError, "the system could not be removed")
		return
	}
	a.log.Info("system forgotten", "system", name, "from", r.RemoteAddr)
	respond(w, http.StatusOK, map[string]string{"status": "forgotten", "system": name})
}

// health tells a supervisor that the server is up. It says nothing about the systems.
func (a *api) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		allow(w, r, http.MethodGet)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, "ok\n")
}

// pages hands everything else to the dashboard, behind its password when one is set.
func (a *api) pages(w http.ResponseWriter, r *http.Request) {
	if a.dashboardUser != "" {
		user, password, _ := r.BasicAuth()
		// Both are always compared, so a wrong user takes as long as a wrong password.
		wantUser := hashSecret(a.dashboardUser)
		userOK := wantUser.matches(user)
		passwordOK := a.dashboardPassword.matches(password)
		if !userOK || !passwordOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="upkeep", charset="UTF-8"`)
			http.Error(w, "the dashboard needs a user and a password", http.StatusUnauthorized)
			return
		}
	}
	a.dashboard.ServeHTTP(w, r)
}
