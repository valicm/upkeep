// Package homeassistant reads from Home Assistant what it knows itself about pending updates and
// about its own backups. The server polls it; an agent running as a Home Assistant app can use
// the same source through the Supervisor.
//
// It makes two calls to the REST API, both only reading: GET /api/config for the version of
// Core, and GET /api/states for every entity, of which it keeps two kinds.
//
// Update entities ("update.*"). Every integration that can tell about an update has one: the
// Supervisor for Core, the operating system, itself and each app, and integrations for the
// firmware of devices. The state is "on" when an update waits. The source reports what Home
// Assistant says and does not judge versions itself, so a version the owner chose to skip is
// not an update here either; the Detail says it was skipped.
//
// The backup sensors of the backup integration, as one Backup: when the last automatic backup
// succeeded, when one was last tried, what the backup manager is doing and when the next is due.
// An installation without these sensors gets no Backup at all. They are found by the entity ids
// Home Assistant gives them; sensors the owner renamed are not found.
//
// Two ways in. With token_file, a long-lived access token made on the user's profile page. With
// supervisor = true, for an agent that runs as an app on the same machine, the Supervisor's
// proxy at http://supervisor/core with the token it puts into the SUPERVISOR_TOKEN environment
// variable of every app; the app's config.yaml needs "homeassistant_api: true" for that.
//
// Read in home-assistant/core at 2026.11.2, under homeassistant/components: update/const.py and
// update/entity.py (the attributes, and how state follows from versions and a skipped version),
// hassio/update.py (titles, pictures and release links of Core, the operating system, the
// Supervisor and apps), backup/sensor.py, backup/coordinator.py, backup/event.py,
// backup/manager.py and backup/config.py (the sensors, the manager's states, when an attempt and
// a success are stamped, the schedule), api/__init__.py (the two calls).
// The picture of an integration installed through HACS is from hacs/integration,
// custom_components/hacs/update.py. The Supervisor's proxy is described at
// https://contributors.home-assistant.io/apps/guides/communication/.
package homeassistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/connect"
	"github.com/valicm/upkeep/internal/connect/internal/httpapi"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/version"
)

// Config is one [[homeassistant]] table of the server's configuration, or the agent's local equivalent.
type Config struct {
	Name string `toml:"name"` // the system's name on the dashboard
	URL  string `toml:"url"`  // "http://homeassistant.local:8123"; with supervisor it defaults to the Supervisor's proxy

	TokenFile  string `toml:"token_file"` // a file with a long-lived access token
	Supervisor bool   `toml:"supervisor"` // run as a Home Assistant app: use the Supervisor's proxy and its token, no token_file

	CAFile        string `toml:"ca_file"`         // PEM certificates to trust instead of the system's
	TLSServerName string `toml:"tls_server_name"` // the name in the certificate, when url has an address
	TLSSkipVerify bool   `toml:"tls_skip_verify"` // accept any certificate; the certificate is checked unless this is set

	Timeout string `toml:"timeout"` // for one request, default "20s"

	IgnoreBackups bool `toml:"ignore_backups"` // do not report Home Assistant's own backups, e.g. when something else backs it up
}

const (
	defaultTimeout  = 20 * time.Second
	supervisorProxy = "http://supervisor/core"
	supervisorToken = "SUPERVISOR_TOKEN"
	maxConfig       = 4 << 20
	maxStates       = 128 << 20 // every entity with all its attributes: a few megabytes on a large installation
	collector       = "homeassistant"
)

// The entities of the backup integration. Their ids come from the device "Backup" and the
// entity names in backup/strings.json, and are the ones a real 2026.11.2 gave them.
const (
	backupManager = "sensor.backup_backup_manager_state"
	backupNext    = "sensor.backup_next_scheduled_automatic_backup"
	backupSuccess = "sensor.backup_last_successful_automatic_backup"
	backupAttempt = "sensor.backup_last_attempted_automatic_backup"
	backupSize    = "sensor.backup_last_successful_automatic_backup_size"
	backupEvent   = "event.backup_automatic_backup"
)

type source struct {
	name          string
	base          *url.URL
	client        *http.Client
	tokenFile     string
	supervisor    bool
	timeout       time.Duration
	ignoreBackups bool

	now    func() time.Time    // the clock, replaced in tests
	getenv func(string) string // the environment, replaced in tests
}

// New returns the source.
func New(cfg Config) (connect.Source, error) {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		return nil, errors.New("homeassistant: name is missing")
	}
	fail := func(err error) (connect.Source, error) { return nil, fmt.Errorf("homeassistant %s: %w", name, err) }

	switch {
	case cfg.Supervisor && cfg.TokenFile != "":
		return fail(errors.New("token_file and supervisor are two different ways in: set one"))
	case !cfg.Supervisor && cfg.TokenFile == "":
		return fail(errors.New("token_file is missing (or set supervisor = true in an app)"))
	}
	if cfg.Supervisor && strings.TrimSpace(cfg.URL) == "" {
		cfg.URL = supervisorProxy
	}
	base, err := httpapi.BaseURL(cfg.URL)
	if err != nil {
		return fail(err)
	}
	timeout, err := httpapi.Duration("timeout", cfg.Timeout, defaultTimeout)
	if err != nil {
		return fail(err)
	}
	if timeout == 0 {
		return fail(errors.New("timeout must not be 0"))
	}
	client, err := httpapi.NewClient(httpapi.TLS{CAFile: cfg.CAFile, ServerName: cfg.TLSServerName, SkipVerify: cfg.TLSSkipVerify})
	if err != nil {
		return fail(err)
	}
	return &source{
		name: name, base: base, client: client, tokenFile: cfg.TokenFile, supervisor: cfg.Supervisor,
		timeout: timeout, ignoreBackups: cfg.IgnoreBackups, now: time.Now, getenv: os.Getenv,
	}, nil
}

func (s *source) Name() string { return s.name }

// Fetch asks Home Assistant for its version and its entities and builds the report.
func (s *source) Fetch(ctx context.Context) (*report.Report, error) {
	token, err := s.token()
	if err != nil {
		return nil, fmt.Errorf("homeassistant %s: reading the access token: %w", s.name, err)
	}
	var core coreConfig
	err = s.get(ctx, token, "config", maxConfig, func(r io.Reader) error { return json.NewDecoder(r).Decode(&core) })
	if err != nil {
		return nil, fmt.Errorf("homeassistant %s: reading the configuration: %w", s.name, err)
	}
	var updates []entity
	backup := map[string]entity{}
	err = s.get(ctx, token, "states", maxStates, func(r io.Reader) error {
		return eachEntity(r, func(e entity) {
			switch {
			case strings.HasPrefix(e.ID, "update."):
				updates = append(updates, e)
			case strings.HasPrefix(e.ID, "sensor.backup_") || e.ID == backupEvent:
				backup[e.ID] = e
			}
		})
	})
	if err != nil {
		return nil, fmt.Errorf("homeassistant %s: reading the entities: %w", s.name, err)
	}
	return s.build(core, updates, backup), nil
}

// token is read on every fetch, so a replaced token works without a restart.
func (s *source) token() (string, error) {
	if !s.supervisor {
		return httpapi.ReadSecret(s.tokenFile)
	}
	t := strings.TrimSpace(s.getenv(supervisorToken))
	if t == "" {
		return "", errors.New(supervisorToken + " is not set: supervisor = true only works inside a Home Assistant app")
	}
	return t, nil
}

func (s *source) get(ctx context.Context, token, what string, limit int64, read func(io.Reader) error) error {
	req, err := http.NewRequest(http.MethodGet, s.base.JoinPath("api", what).String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	err = httpapi.Do(ctx, s.client, req, s.timeout, limit, read)
	var se *httpapi.StatusError
	if errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden) {
		if s.supervisor {
			return fmt.Errorf(`the Supervisor did not let the app through: does its config.yaml have "homeassistant_api: true"? (%w)`, err)
		}
		return fmt.Errorf("Home Assistant did not accept the access token (%w)", err)
	}
	return err
}

// coreConfig is the part of GET /api/config that is of use here.
type coreConfig struct {
	Version string `json:"version"` // of Home Assistant Core
	State   string `json:"state"`   // "RUNNING" once everything is loaded
}

// entity is one element of GET /api/states. The attributes stay raw until an entity is wanted:
// most of the answer is lights and sensors.
type entity struct {
	ID    string          `json:"entity_id"`
	State string          `json:"state"`
	Attr  json.RawMessage `json:"attributes"`
}

// eachEntity reads the list one entity at a time, so that the whole answer is never in memory.
func eachEntity(r io.Reader, keep func(entity)) error {
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil {
		return err
	} else if t != json.Delim('[') {
		return errors.New("not a list of entities")
	}
	for dec.More() {
		var e entity
		if err := dec.Decode(&e); err != nil {
			return err
		}
		keep(e)
	}
	_, err := dec.Token()
	return err
}

// attrs are the attributes of one entity. Integrations are free in what they put there, so every
// value is read for what it is and not for what it should be.
type attrs map[string]any

func (e entity) attrs() attrs {
	var a attrs
	json.Unmarshal(e.Attr, &a) // attributes that are not an object count as none
	return a
}

func (a attrs) text(key string) string {
	switch v := a[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func (a attrs) number(key string) (float64, bool) {
	v, ok := a[key].(float64)
	return v, ok
}

func (a attrs) yes(key string) bool {
	switch v := a[key].(type) {
	case bool:
		return v
	case float64:
		return v != 0 // older versions gave the progress of an installation as a number
	}
	return false
}

const featureBackup = 8 // UpdateEntityFeature.BACKUP: a backup can be made before installing

// kind says what an update entity is about, as far as its state tells. The REST API does not say
// which integration an entity belongs to, so this goes by what only one of them does.
func kind(a attrs) string {
	picture := a.text("entity_picture")
	features, _ := a.number("supported_features")
	switch title := a.text("title"); {
	// The Supervisor's three own entities have fixed titles.
	case title == "Home Assistant Core":
		return "core"
	case title == "Home Assistant Operating System":
		return "os"
	case title == "Home Assistant Supervisor":
		return "supervisor"
	// An app shows its own icon, which the Supervisor serves.
	case strings.HasPrefix(picture, "/api/hassio/addons/"):
		return "app"
	case a.text("device_class") == "firmware":
		return "firmware"
	// An app without an icon. Besides firmware, sorted out above, the Supervisor is the only
	// integration whose entities offer a backup before installing (looked up in the update
	// platform of every integration in 2026.11.2; an entity the owner wrote as a template can too).
	case int(features)&featureBackup != 0:
		return "app"
	// An integration installed through HACS shows the brand icon from the web.
	case strings.HasPrefix(picture, "https://brands.home-assistant.io/"):
		return "integration"
	}
	return ""
}

// software turns one update entity into a Software entry.
func software(e entity) report.Software {
	a := e.attrs()
	sw := report.Software{
		Kind:      kind(a),
		Installed: a.text("installed_version"),
		Latest:    a.text("latest_version"),
		URL:       link(a.text("release_url")),
	}
	// The title names the software, and for device firmware that is the same for every device
	// ("ESPHome"): there the entity's own name tells them apart.
	title, friendly := a.text("title"), strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(a.text("friendly_name"), " Update"), " update"))
	switch {
	case title != "" && (friendly == "" || sw.Kind == "core" || sw.Kind == "os" || sw.Kind == "supervisor" || sw.Kind == "app"):
		sw.Name = title
	case friendly != "":
		sw.Name = friendly
	default:
		sw.Name = e.ID
	}

	var details []string
	switch e.State {
	case "on":
		sw.UpdateAvailable = true
		if sw.Kind == "os" {
			// The Supervisor's own note on every operating system update.
			details = append(details, "the update needs a reboot")
		}
	case "off":
		if skipped := a.text("skipped_version"); skipped != "" && skipped != sw.Installed {
			details = append(details, skipped+" skipped in Home Assistant")
		}
	case "unavailable":
		details = append(details, "unavailable in Home Assistant")
	default: // "unknown": the installed or the latest version is not known
		details = append(details, "Home Assistant does not know whether there is an update")
	}
	if a.yes("in_progress") {
		installing := "installing"
		if pct, ok := a.number("update_percentage"); ok {
			installing += fmt.Sprintf(" %.0f%%", pct)
		}
		details = append(details, installing)
	}
	if a.yes("auto_update") {
		details = append(details, "updates by itself")
	}
	sw.Detail = strings.Join(details, ", ")
	return sw
}

// link keeps a release link only when it is a web address: it ends up as a link on a page.
func link(s string) string {
	if u, err := url.Parse(s); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return s
}

// order puts Home Assistant itself first, then what runs on it, then the devices.
var order = map[string]int{"core": 0, "os": 1, "supervisor": 2, "app": 3, "integration": 4, "": 5, "firmware": 6}

func (s *source) build(core coreConfig, updates []entity, backup map[string]entity) *report.Report {
	r := &report.Report{
		Schema: report.Schema,
		Sent:   s.now().UTC(),
		System: report.System{
			Name: s.name, Kind: "homeassistant", OS: "Home Assistant", OSVersion: core.Version,
			Source: "connector", AgentVersion: version.String(),
		},
	}
	if core.State != "" && core.State != "RUNNING" {
		r.Errors = append(r.Errors, report.Problem{Collector: collector, Message: fmt.Sprintf(
			"Home Assistant is not fully started (state %s): entities may be missing", core.State)})
	}

	hasCore := false
	for _, e := range updates {
		sw := software(e)
		switch sw.Kind {
		case "core":
			hasCore = true
		case "os":
			// With Home Assistant OS the system line shows the operating system; Core is in the list.
			if sw.Installed != "" {
				r.System.OS, r.System.OSVersion = "Home Assistant OS", sw.Installed
			}
		}
		r.Software = append(r.Software, sw)
	}
	if !hasCore && core.Version != "" {
		// Without a Supervisor nothing in Home Assistant watches for a new Core.
		r.Software = append(r.Software, report.Software{
			Name: "Home Assistant Core", Kind: "core", Installed: core.Version,
			Detail: "no update entity for Core: this installation has no Supervisor",
		})
	}
	sort.SliceStable(r.Software, func(i, j int) bool {
		a, b := r.Software[i], r.Software[j]
		if order[a.Kind] != order[b.Kind] {
			return order[a.Kind] < order[b.Kind]
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})

	if b, ok := backupOf(backup); ok && !s.ignoreBackups {
		r.Backups = append(r.Backups, b)
	}
	return r
}

// backupOf builds the one Backup from the backup integration's entities.
func backupOf(e map[string]entity) (report.Backup, bool) {
	_, hasSuccess := e[backupSuccess]
	_, hasAttempt := e[backupAttempt]
	if !hasSuccess && !hasAttempt {
		return report.Backup{}, false
	}
	success, attempt, next := timestamp(e[backupSuccess]), timestamp(e[backupAttempt]), timestamp(e[backupNext])
	b := report.Backup{Name: "homeassistant automatic backup", Kind: "homeassistant", LastSuccess: success, LastRun: attempt}
	if attempt.IsZero() {
		b.LastRun = success
	}
	manager := e[backupManager].State
	event := e[backupEvent].attrs()

	// The manager stamps an attempt when it starts and a success when it is done, so an
	// attempt newer than the last success is a backup that failed, or one that still runs.
	var details []string
	switch {
	case attempt.After(success) && manager == "create_backup":
		b.LastResult = "running"
	case attempt.After(success):
		b.LastResult = "failed"
		// The event entity tells about the latest backup of any kind; it counts when it failed too.
		if reason := event.text("failed_reason"); event.text("event_type") == "failed" && reason != "" {
			details = append(details, strings.ReplaceAll(reason, "_", " "))
		}
	case !success.IsZero():
		b.LastResult = "ok"
		if size, err := strconv.ParseFloat(e[backupSize].State, 64); err == nil {
			details = append(details, amount(size)+" "+orDefault(e[backupSize].attrs().text("unit_of_measurement"), "MiB"))
		}
	default:
		b.LastResult = "unknown"
		details = append(details, "no automatic backup has run")
	}
	switch manager {
	case "blocked":
		details = append(details, "the backup manager is blocked")
	case "receive_backup":
		details = append(details, "receiving a backup")
	case "restore_backup":
		details = append(details, "restoring a backup")
	}
	if next.IsZero() {
		details = append(details, "none scheduled")
	} else {
		details = append(details, "next "+next.Format("2006-01-02 15:04 UTC"))
	}
	b.Detail = strings.Join(details, ", ")

	// Backups can be scheduled for some days of the week only. The time from the last run to
	// the next is then longer than the server's default maximum age, and says how long a
	// backup may go without a newer one. A week, and the hour within which the start time is
	// drawn, is the longest a schedule allows; a longer gap means Home Assistant was off and
	// missed some.
	if gap := next.Sub(attempt); !attempt.IsZero() && !next.IsZero() && gap > 26*time.Hour {
		gap = min(gap, (7*24+1)*time.Hour)
		b.MaxAgeHours = int(math.Ceil(gap.Hours())) + 2 // two more for the backup itself to finish
	}
	return b, true
}

// timestamp reads the state of a timestamp sensor. "unknown" and "unavailable" give the zero time.
func timestamp(e entity) time.Time {
	t, err := time.Parse(time.RFC3339, e.State)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// amount prints a size with the digits that matter: "412", "9.4", "0.02".
func amount(v float64) string {
	switch {
	case v >= 100:
		return strconv.FormatFloat(v, 'f', 0, 64)
	case v >= 1:
		return strconv.FormatFloat(v, 'f', 1, 64)
	default:
		return strconv.FormatFloat(v, 'f', 2, 64)
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
