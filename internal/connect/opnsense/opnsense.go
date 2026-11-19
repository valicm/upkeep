// Package opnsense reads the firmware state of an OPNsense firewall through its API. The server
// polls it; an agent on the firewall can run the same source against https://127.0.0.1.
//
// What it asks. GET /api/core/firmware/status, the call the firewall's own firmware page makes.
// It reads files on the firewall and contacts nobody. The answer has two parts of different age:
//
//   - the result of the firewall's LAST update check: pending packages, whether a major upgrade
//     is offered, whether the update restarts the firewall, and when that check ran. A reboot or
//     an installed update throws the result away, and until the next check the firewall only
//     says that it has not checked;
//   - the installed version and the newest release of the installed series, taken from the
//     changelog the firewall fetches by itself once a day. So a new release shows up within a
//     day with no check at all. Hotfixes that keep the version, plugin updates and the package
//     list need a check.
//
// When it makes the firewall check again. Never, unless check is set: a check makes the
// firewall contact its mirror, and OPNsense does not check by itself either (that takes a
// "Firmware update check" job under System > Settings > Cron). With check set, the source asks
// when the last check is older than check_every, which cannot be set below 12 hours, so at most
// twice a day. It asks only when no other firmware action runs, then waits up to check_wait for
// the result.
//
// What it reports when the last check is old. Everything it has, with the time of that check as
// Packages.ListsUpdated: the server judges the age of package lists the same way for every
// package manager, so the source does not call an old check a problem itself. From a day and a
// half on, the firmware's Detail says how old the check is. No check at all is different: there
// are no package lists then, Packages stays empty, and Errors says so, because "nothing known" is
// not "nothing pending". The firewall writes the time of its check as text in its own time zone;
// timezone names the zone when the text alone does not settle it.
//
// A pending reboot. The firewall's needs_reboot means "installing this update restarts the
// firewall", not "a reboot is waiting": rebooting now would change nothing. It goes into the
// firmware's Detail, and Packages.RebootRequired stays false.
//
// The API key. OPNsense has one privilege for the whole firmware API, "System: Firmware", and
// matches it on the path alone. Reading the status needs it, asking for a check needs it, and it
// also allows installing updates, rebooting and powering off; there is no read-only one. Give
// the key to a user with that single privilege and keep the key file readable by upkeep only.
// This source sends GET status and, with check set, GET running and POST check, nothing else.
// (The dashboard's call, /api/diagnostics/system/system_information, needs only "Lobby:
// Dashboard". It tells the version and a translated sentence on whether updates wait, no more,
// and this source does not use it.)
//
// Read in opnsense/core, branch stable/26.7 (the Business Edition 26.10 is built from it), under
// src/opnsense: mvc/app/controllers/OPNsense/Core/Api/FirmwareController.php (statusAction,
// checkAction, runningAction), scripts/firmware/product.php, check.sh and latest.php,
// service/conf/actions.d/actions_firmware.conf, mvc/app/models/OPNsense/Core/ACL/ACL.xml
// (page-system-firmware-manualupdate), mvc/app/controllers/OPNsense/Base/ApiControllerBase.php
// (key and secret as HTTP basic auth, the 401 and 403 answers),
// mvc/app/controllers/OPNsense/Diagnostics/Api/SystemController.php (how the dashboard tells an
// update from the changelog) and, outside src/opnsense, src/etc/inc/plugins.inc.d/core.inc (the
// daily changelog job, the only firmware job that runs unasked) and src/etc/rc.subr.d/tmp (a
// boot empties /tmp, where the result of a check is kept).
package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/valicm/upkeep/internal/connect"
	"github.com/valicm/upkeep/internal/connect/internal/httpapi"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/version"
)

// Config is one [[opnsense]] table of the server's configuration, or the agent's local equivalent.
type Config struct {
	Name string `toml:"name"` // the system's name on the dashboard
	URL  string `toml:"url"`  // "https://192.0.2.1", or "https://127.0.0.1" for an agent on the firewall

	KeyFile    string `toml:"key_file"`    // the apikey.txt OPNsense offers for download (key=..., secret=...), or a file with only the key
	SecretFile string `toml:"secret_file"` // a file with only the secret, when key_file has only the key

	CAFile        string `toml:"ca_file"`         // PEM certificates to trust instead of the system's, e.g. the firewall's self-signed one
	TLSServerName string `toml:"tls_server_name"` // the name in the certificate, when url has an address
	TLSSkipVerify bool   `toml:"tls_skip_verify"` // accept any certificate; the certificate is checked unless this is set

	Timeout string `toml:"timeout"` // for one request, default "15s"

	Check      bool   `toml:"check"`       // let the source ask the firewall to check for updates; it does not unless this is set
	CheckEvery string `toml:"check_every"` // not more often than this; default and minimum "12h"
	CheckWait  string `toml:"check_wait"`  // how long to wait for the result of a check, default "2m"

	Timezone string `toml:"timezone"` // the firewall's time zone, e.g. "Europe/Zagreb"; default is this machine's
}

const (
	defaultTimeout   = 15 * time.Second
	minCheckEvery    = 12 * time.Hour // a check makes the firewall contact its mirror: twice a day is plenty
	defaultCheckWait = 2 * time.Minute
	oldCheck         = 36 * time.Hour // older than a daily check that ran late: worth a word in the Detail
	defaultPollEvery = 3 * time.Second
	maxBody          = 8 << 20 // a status with hundreds of packages is some hundred kilobytes
	collector        = "opnsense"
)

type source struct {
	name       string
	base       *url.URL
	client     *http.Client
	keyFile    string
	secretFile string
	loc        *time.Location

	timeout    time.Duration
	check      bool
	checkEvery time.Duration
	checkWait  time.Duration
	pollEvery  time.Duration // how often to look for the result of a check

	now func() time.Time // the clock, replaced in tests

	mu    sync.Mutex
	asked time.Time // when this process last asked for a check
}

// New returns the source.
func New(cfg Config) (connect.Source, error) {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		return nil, errors.New("opnsense: name is missing")
	}
	fail := func(err error) (connect.Source, error) { return nil, fmt.Errorf("opnsense %s: %w", name, err) }

	base, err := httpapi.BaseURL(cfg.URL)
	if err != nil {
		return fail(err)
	}
	if cfg.KeyFile == "" {
		return fail(errors.New("key_file is missing"))
	}
	s := &source{
		name: name, base: base, keyFile: cfg.KeyFile, secretFile: cfg.SecretFile,
		loc: time.Local, check: cfg.Check, pollEvery: defaultPollEvery, now: time.Now,
	}
	for _, d := range []struct {
		setting, value string
		def            time.Duration
		into           *time.Duration
	}{
		{"timeout", cfg.Timeout, defaultTimeout, &s.timeout},
		{"check_every", cfg.CheckEvery, minCheckEvery, &s.checkEvery},
		{"check_wait", cfg.CheckWait, defaultCheckWait, &s.checkWait},
	} {
		if *d.into, err = httpapi.Duration(d.setting, d.value, d.def); err != nil {
			return fail(err)
		}
	}
	if s.timeout == 0 {
		return fail(errors.New("timeout must not be 0"))
	}
	if s.checkEvery < minCheckEvery {
		return fail(fmt.Errorf("check_every must be at least %s: every check makes the firewall contact its mirror", minCheckEvery))
	}
	if cfg.Timezone != "" {
		if s.loc, err = time.LoadLocation(cfg.Timezone); err != nil {
			return fail(fmt.Errorf("timezone: %w", err))
		}
	}
	s.client, err = httpapi.NewClient(httpapi.TLS{CAFile: cfg.CAFile, ServerName: cfg.TLSServerName, SkipVerify: cfg.TLSSkipVerify})
	if err != nil {
		return fail(err)
	}
	return s, nil
}

func (s *source) Name() string { return s.name }

// Fetch reads the firmware status, asks for a fresh check first when that is allowed and due,
// and builds the report.
func (s *source) Fetch(ctx context.Context) (*report.Report, error) {
	a, err := s.credentials()
	if err != nil {
		return nil, fmt.Errorf("opnsense %s: reading the API key: %w", s.name, err)
	}
	st, err := s.status(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("opnsense %s: reading the firmware status: %w", s.name, err)
	}
	var note string
	if s.check {
		st, note = s.refresh(ctx, a, st)
	}
	return s.build(st, note), nil
}

// auth is the API key and its secret. It is only ever handed to SetBasicAuth.
type auth struct{ key, secret string }

// credentials reads the key on every fetch, so a replaced key works without a restart.
func (s *source) credentials() (auth, error) {
	if s.secretFile != "" {
		key, err := httpapi.ReadSecret(s.keyFile)
		if err != nil {
			return auth{}, err
		}
		secret, err := httpapi.ReadSecret(s.secretFile)
		if err != nil {
			return auth{}, err
		}
		return auth{key, secret}, nil
	}
	b, err := os.ReadFile(s.keyFile)
	if err != nil {
		return auth{}, err
	}
	var a auth
	for _, line := range strings.Split(string(b), "\n") {
		switch k, v, _ := strings.Cut(strings.TrimSpace(line), "="); k {
		case "key":
			a.key = v
		case "secret":
			a.secret = v
		}
	}
	if a.key == "" || a.secret == "" {
		return auth{}, fmt.Errorf("%s has no key= and secret= lines, and secret_file is not set", s.keyFile)
	}
	return a, nil
}

// call sends one request to the firmware API and decodes the JSON answer.
func (s *source) call(ctx context.Context, a auth, method, action string, into any) error {
	var body io.Reader
	if method == http.MethodPost {
		// The API answers 400 to a JSON request without a body.
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, s.base.JoinPath("api", "core", "firmware", action).String(), body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(a.key, a.secret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	err = httpapi.Do(ctx, s.client, req, s.timeout, maxBody, func(r io.Reader) error {
		return json.NewDecoder(r).Decode(into)
	})
	var se *httpapi.StatusError
	if errors.As(err, &se) {
		switch se.Code {
		case http.StatusUnauthorized:
			return fmt.Errorf("the firewall did not accept the API key (%w)", err)
		case http.StatusForbidden:
			return fmt.Errorf(`the user of the API key lacks the privilege "System: Firmware" (%w)`, err)
		}
	}
	return err
}

func (s *source) status(ctx context.Context, a auth) (*status, error) {
	var st status
	if err := s.call(ctx, a, http.MethodGet, "status", &st); err != nil {
		return nil, err
	}
	if st.Product == nil {
		// The firewall could not read its own version data and has nothing but a message.
		return nil, fmt.Errorf("the firewall has no firmware data: %s", orUnknown(st.StatusMsg))
	}
	return &st, nil
}

// refresh asks the firewall to check for updates when its last check is older than check_every,
// and waits for the result. It returns the status to report and, when that is not a fresh one,
// the reason.
func (s *source) refresh(ctx context.Context, a auth, old *status) (*status, string) {
	now := s.now()
	if at, ok := old.checkedAt(s.loc); ok && now.Sub(at.t) < s.checkEvery {
		return old, ""
	}

	// The firewall's own time stamp is the main brake. This one is for a check that leaves no
	// result behind, so that a broken firewall is not asked again on every poll.
	s.mu.Lock()
	before := s.asked
	if !before.IsZero() && now.Sub(before) < s.checkEvery {
		s.mu.Unlock()
		return old, fmt.Sprintf("a check asked for at %s has given no result", stamp(before))
	}
	s.asked = now
	s.mu.Unlock()
	notAsked := func() {
		s.mu.Lock()
		s.asked = before
		s.mu.Unlock()
	}

	var run struct {
		Status string `json:"status"`
	}
	if err := s.call(ctx, a, http.MethodGet, "running", &run); err != nil {
		notAsked()
		return old, "could not ask the firewall whether it is busy: " + err.Error()
	}
	if run.Status != "ready" {
		// An update may be installing. A check would not start anyway: they share one lock.
		notAsked()
		return old, "the firewall is busy with another firmware action, so no check was asked for"
	}
	var started struct {
		Status string `json:"status"`
	}
	if err := s.call(ctx, a, http.MethodPost, "check", &started); err != nil {
		return old, "could not ask the firewall to check for updates: " + err.Error()
	}
	if started.Status != "ok" {
		return old, fmt.Sprintf("the firewall refused to check for updates (status %q)", started.Status)
	}

	if s.checkWait == 0 {
		return old, "a check was asked for; its result will be in the next report"
	}
	// The check runs in the background and removes the old result first. The new one is there
	// when the status carries a different check time.
	wait := time.NewTimer(s.checkWait)
	defer wait.Stop()
	tick := time.NewTicker(s.pollEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return old, "a check was asked for, but there was no time to wait for its result"
		case <-wait.C:
			return old, fmt.Sprintf("a check was asked for and gave no result within %s", s.checkWait)
		case <-tick.C:
		}
		if st, err := s.status(ctx, a); err == nil && st.LastCheck != "" && st.LastCheck != old.LastCheck {
			return st, ""
		}
	}
}

// status is the answer of GET /api/core/firmware/status: the last check's result with the
// product data added. Without a check it has only status, status_msg and product.
type status struct {
	Status       string `json:"status"` // "update", "upgrade" (major), "none", "error"
	StatusMsg    string `json:"status_msg"`
	StatusReboot flag   `json:"status_reboot"` // installing what is offered restarts the firewall
	LastCheck    string `json:"last_check"`    // the output of date(1), empty without a check
	OSVersion    string `json:"os_version"`    // "FreeBSD 15.1-RELEASE-p7"
	Target       string `json:"product_target"`
	MajorVersion string `json:"upgrade_major_version"`

	New       []pkg `json:"new_packages"`
	Reinstall []pkg `json:"reinstall_packages"`
	Upgrade   []pkg `json:"upgrade_packages"`
	Downgrade []pkg `json:"downgrade_packages"`
	Remove    []pkg `json:"remove_packages"`
	Sets      []pkg `json:"upgrade_sets"` // base, kernel and packages of a major upgrade

	Product *product `json:"product"`
}

// The answer also has all_packages and all_sets. They are left alone on purpose: PHP writes
// them as an object when filled and as an empty list when not.

type product struct {
	ID      string `json:"product_id"`      // "opnsense", "opnsense-business"
	Name    string `json:"product_name"`    // "OPNsense"
	Version string `json:"product_version"` // "26.7.8", "26.7.8_4"
	Latest  string `json:"product_latest"`  // newest release of the series in the changelog, or the installed one
	Series  string `json:"product_series"`  // "26.7"
	Arch    string `json:"product_arch"`
}

type pkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`         // new, reinstalled and removed packages
	Current string `json:"current_version"` // upgraded and downgraded ones
	New     string `json:"new_version"`
}

// flag is a yes or no that the firewall writes as "1" or "0".
type flag bool

func (f *flag) UnmarshalJSON(b []byte) error {
	v := strings.Trim(string(b), `"`)
	*f = v == "1" || v == "true"
	return nil
}

// pending lists what the offered update changes, counted the way the firewall counts: one entry
// for each package name, whether it is upgraded, new, reinstalled, downgraded or removed.
func (st *status) pending() []report.PackageUpdate {
	byName := map[string]report.PackageUpdate{}
	for _, p := range st.New {
		byName[p.Name] = report.PackageUpdate{Name: p.Name, Candidate: p.Version}
	}
	for _, p := range st.Reinstall {
		byName[p.Name] = report.PackageUpdate{Name: p.Name, Installed: p.Version, Candidate: p.Version}
	}
	for _, p := range st.Upgrade {
		byName[p.Name] = report.PackageUpdate{Name: p.Name, Installed: p.Current, Candidate: p.New}
	}
	for _, p := range st.Downgrade {
		byName[p.Name] = report.PackageUpdate{Name: p.Name, Installed: p.Current, Candidate: p.New}
	}
	for _, p := range st.Remove {
		byName[p.Name] = report.PackageUpdate{Name: p.Name, Installed: p.Version}
	}
	out := make([]report.PackageUpdate, 0, len(byName))
	for _, p := range byName {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// build turns a status into the report. note says why a wanted check gave no fresh status.
func (s *source) build(st *status, note string) *report.Report {
	now := s.now()
	p := st.Product
	r := &report.Report{
		Schema: report.Schema,
		Sent:   now.UTC(),
		System: report.System{
			Name: s.name, Kind: "opnsense", OS: orDefault(p.Name, "OPNsense"), OSVersion: p.Version,
			Kernel: st.OSVersion, Arch: p.Arch, Source: "connector", AgentVersion: version.String(),
		},
	}
	problem := func(format string, args ...any) {
		r.Errors = append(r.Errors, report.Problem{Collector: collector, Message: fmt.Sprintf(format, args...)})
	}

	// Decided the way the firewall's dashboard does: the changelog names a newer release when
	// product_latest differs from the installed version without its package revision, and it
	// does not cover development builds. Both sides are cut the same way: a firewall on
	// "26.10.0p1" reports product_latest "26.10.0", which is the release it already runs.
	announced := p.Latest != "" && release(p.Latest) != release(p.Version) && !strings.Contains(p.ID, "-devel")
	fw := report.Software{
		Name: orDefault(p.Name, "OPNsense"), Kind: "firmware", Installed: p.Version, Latest: p.Version,
		UpdateAvailable: announced, URL: releaseNotes(p.ID, p.Series),
	}
	if announced {
		fw.Latest = p.Latest
	}
	var what, age []string // the two halves of the firmware's Detail

	// How old is what the firewall knows?
	at, parsed := st.checkedAt(s.loc)
	switch {
	case st.LastCheck == "":
		advice := ""
		if !s.check {
			advice = `; set check = true for this source, or add a "Firmware update check" job to the firewall's cron settings`
		}
		age = append(age, "not checked for updates since the firewall started or was last updated")
		problem("the firewall has not checked for updates since it started or was last updated%s", advice)
	case !parsed:
		problem("cannot read the time of the firewall's last update check %q", st.LastCheck)
	default:
		if !at.exact {
			problem("cannot place the time zone of the firewall's last update check %q: set timezone for this source", st.LastCheck)
		}
		if old := now.Sub(at.t); old > oldCheck {
			age = append(age, "last checked "+ago(old)+" ago")
		}
	}
	if note != "" {
		problem("%s", note)
	}

	// What did the last check find?
	if st.LastCheck != "" {
		lists := report.Packages{Manager: "pkg"}
		if parsed {
			lists.ListsUpdated = at.t
		}
		switch st.Status {
		case "update":
			items := st.pending()
			lists.Pending = len(items)
			lists.Items = items[:min(len(items), report.MaxItems)]
			r.Packages = &lists
			fw.UpdateAvailable = true
			for _, u := range st.Upgrade {
				if u.Name == st.Target || u.Name == p.ID {
					fw.Latest = u.New
				}
			}
			what = append(what, plural(len(items), "package"))
			if st.StatusReboot {
				what = append(what, "the update needs a reboot")
			}
			if st.MajorVersion != "" && len(st.Sets) > 0 {
				what = append(what, "then a major upgrade to "+st.MajorVersion)
			}
		case "upgrade":
			r.Packages = &lists
			fw.UpdateAvailable = true
			fw.Latest = orDefault(st.MajorVersion, fw.Latest)
			fw.URL = orDefault(releaseNotes(p.ID, st.MajorVersion), fw.URL)
			what = append(what, "major upgrade")
			if st.StatusReboot {
				what = append(what, "the upgrade needs a reboot")
			}
		case "none":
			r.Packages = &lists
			if announced {
				what = append(what, "announced in the changelog, not offered by the last check")
			}
		case "error":
			// The mirror could not be used, so the package lists were not refreshed either.
			what = append(what, "the last update check failed")
			problem("the firewall's last update check failed: %s", orUnknown(st.StatusMsg))
		default:
			problem("the firewall reports a firmware status this version of upkeep does not know: %q", st.Status)
		}
	}

	fw.Detail = strings.Join(append(what, age...), ", ")
	r.Software = append(r.Software, fw)
	// Plugins, the packages named os-*, are in the package list too. They get their own line
	// because they are what the owner installed by name.
	for _, u := range st.Upgrade {
		if strings.HasPrefix(u.Name, "os-") {
			r.Software = append(r.Software, report.Software{
				Name: u.Name, Kind: "plugin", Installed: u.Current, Latest: u.New, UpdateAvailable: true,
			})
		}
	}
	return r
}

// revision splits a version where latest.php does, to compare it with a changelog entry:
// "26.7.8_4" is release "26.7.8".
var revision = regexp.MustCompile(`\.0|[p_-]`)

func release(v string) string { return revision.Split(v, 2)[0] }

var series = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)

// releaseNotes is the page of a series in OPNsense's documentation: CE_26.7.html for the
// community edition, BE_26.10.html for the business edition.
func releaseNotes(productID, s string) string {
	if !series.MatchString(s) {
		return ""
	}
	edition := "CE"
	if strings.HasSuffix(productID, "-business") {
		edition = "BE"
	}
	return "https://docs.opnsense.org/releases/" + edition + "_" + s + ".html"
}

// checkTime is when the firewall last checked. exact is false when its time zone was a guess.
type checkTime struct {
	t     time.Time
	exact bool
}

// zones are abbreviations that mean one offset everywhere. Names such as CST, IST or BST mean
// several and are left to the timezone setting.
var zones = map[string]int{
	"UTC": 0, "GMT": 0, "WET": 0, "WEST": 1, "CET": 1, "CEST": 2, "EET": 2, "EEST": 3, "MSK": 3,
	"EST": -5, "EDT": -4, "CDT": -5, "MDT": -6, "PST": -8, "PDT": -7, "AKST": -9, "AKDT": -8, "HST": -10,
	"JST": 9, "KST": 9, "AWST": 8, "AEST": 10, "AEDT": 11, "NZST": 12, "NZDT": 13, "SAST": 2,
}

var numericZone = regexp.MustCompile(`^([+-])([0-9]{2})([0-9]{2})?$`)

// checkedAt parses last_check, which check.sh fills with the plain output of date(1) in the
// firewall's own time zone: "Wed Nov 18 03:17:42 CET 2026". time.Parse is no help here: it reads
// a zone name it does not know as UTC without saying so.
func (st *status) checkedAt(loc *time.Location) (checkTime, bool) {
	f := strings.Fields(st.LastCheck)
	if len(f) != 6 {
		return checkTime{}, false
	}
	wall, err := time.Parse("Jan 2 15:04:05 2006", f[1]+" "+f[2]+" "+f[3]+" "+f[5])
	if err != nil {
		return checkTime{}, false
	}
	in := func(l *time.Location) time.Time {
		return time.Date(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), wall.Second(), 0, l).UTC()
	}
	zone := f[4]
	if m := numericZone.FindStringSubmatch(zone); m != nil {
		hours, _ := strconv.Atoi(m[2])
		minutes, _ := strconv.Atoi(m[3]) // "+01" has none
		off := hours*3600 + minutes*60
		if m[1] == "-" {
			off = -off
		}
		return checkTime{in(time.FixedZone(zone, off)), true}, true
	}
	// The configured zone first: it settles names that mean different things in different places.
	if t := in(loc); zoneName(t.In(loc)) == zone {
		return checkTime{t, true}, true
	}
	if hours, ok := zones[zone]; ok {
		return checkTime{in(time.FixedZone(zone, hours*3600)), true}, true
	}
	return checkTime{in(loc), false}, true
}

func zoneName(t time.Time) string {
	name, _ := t.Zone()
	return name
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// ago says a duration the way a person would: "9 days", "37 hours".
func ago(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return plural(int(d/(24*time.Hour)), "day")
	case d >= 2*time.Hour:
		return plural(int(d/time.Hour), "hour")
	default:
		return plural(int(d/time.Minute), "minute")
	}
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orUnknown(s string) string { return orDefault(s, "no reason given") }
