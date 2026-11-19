package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/valicm/upkeep/internal/connect"
	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/notify"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/store"
)

// ImageChecker is what the scheduler needs of the registry client: one question about one
// image, with a failure inside the answer.
type ImageChecker interface {
	Check(ctx context.Context, image string) model.ImageCheck
}

// Connector is one system the server polls: its source, and the kind its configuration
// table gives it, for the day the source cannot say anything itself.
type Connector struct {
	Source connect.Source
	Kind   string // "opnsense", "homeassistant"
}

// The keys of the scheduler's own state in the store.
const (
	keyMailSent        = "mail.sent"        // when the last digest went out, RFC 3339
	keyMailFingerprint = "mail.fingerprint" // notify.Fingerprint of the findings it carried
)

const (
	// connectorTimeout is the longest one connector may take to answer. Each request a
	// connector makes has a shorter limit of its own; this one is for all of them together,
	// and long enough for a firewall that is asked to look for updates first and takes
	// minutes to do so.
	connectorTimeout = 5 * time.Minute
	imageTimeout     = 2 * time.Minute // for everything a registry is asked about one image
	parallel         = 4               // connectors polled, and images asked about, at a time
	registryRetry    = 30 * time.Minute
	// checkKept is how long the answer about an image stays after the last container that
	// ran it is gone from the reports: long enough for a machine that is down for some days
	// to come back to what was known about its images.
	checkKept = 7 * 24 * time.Hour
	// registryTick is how often the scheduler looks for images that are due. Most times it
	// finds none; a container that is new in a report is then checked within minutes and
	// does not wait for the next round.
	registryTick = 5 * time.Minute
	// registryStartDelay lets the connectors answer first, so that the first round already
	// knows their containers.
	registryStartDelay = time.Minute
	mailTick           = time.Minute
	// mailStartDelay lets the connectors answer once before a digest is put together.
	mailStartDelay = 2 * time.Minute
	// mailChangeGap keeps "on change" from sending a mail for every report of a busy hour.
	mailChangeGap = 10 * time.Minute
	mailRetry     = 5 * time.Minute
	mailForgotten = time.Hour // the pause after a digest whose sending could not be recorded
	maxProblem    = 500       // characters of a connector's error kept in the report
)

// Scheduler does what the server does without being asked: it polls the connectors, asks
// the registries about the images in the reports, and sends the digest.
type Scheduler struct {
	Store      store.Store
	Values     store.KeyValue
	Connectors []Connector
	Registry   ImageChecker  // nil: registries are not asked
	Policy     model.Policy  // the same thresholds the dashboard uses
	Mail       notify.Config // not Enabled: no mail
	Log        *slog.Logger  // nil: slog.Default

	ConnectorInterval time.Duration // how often every connector is polled; 0: 15 minutes
	RegistryInterval  time.Duration // how long an answer about an image stays good; 0: 6 hours

	Now  func() time.Time                                                               // nil: time.Now
	Send func(ctx context.Context, cfg notify.Config, subject, text, html string) error // nil: notify.Send

	mu             sync.Mutex
	mailRetryAfter time.Time // after a failed send: do not try again before this
}

func (s *Scheduler) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// A Scheduler built without intervals must not spin: it gets the configuration's defaults.
func (s *Scheduler) connectorInterval() time.Duration {
	if s.ConnectorInterval > 0 {
		return s.ConnectorInterval
	}
	return 15 * time.Minute
}

func (s *Scheduler) registryInterval() time.Duration {
	if s.RegistryInterval > 0 {
		return s.RegistryInterval
	}
	return 6 * time.Hour
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Run works until ctx is done and returns when everything it started has stopped.
func (s *Scheduler) Run(ctx context.Context) {
	var wg sync.WaitGroup
	if len(s.Connectors) > 0 {
		wg.Go(func() { every(ctx, 0, s.connectorInterval(), s.PollConnectors) })
	}
	if s.Registry != nil {
		wg.Go(func() { every(ctx, registryStartDelay, min(registryTick, s.registryInterval()), s.CheckImages) })
	}
	if s.Mail.Enabled() {
		wg.Go(func() { every(ctx, mailStartDelay, mailTick, s.MailDigest) })
	}
	wg.Wait()
}

// every calls f after delay and then again after each interval, until ctx is done. A run
// that takes longer than the interval makes the next one late, never two at once.
func every(ctx context.Context, delay, interval time.Duration, f func(context.Context)) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		f(ctx)
		timer.Reset(interval)
	}
}

// each runs f for every item, at most "parallel" at a time, and waits for all of them.
func each[T any](items []T, f func(T)) {
	var wg sync.WaitGroup
	slots := make(chan struct{}, parallel)
	for _, item := range items {
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			f(item)
		})
	}
	wg.Wait()
}

// PollConnectors asks every connector once and stores what it says. One that fails is
// stored too, as a problem of its system: a wrong API key must be on the dashboard, not
// only in a log.
func (s *Scheduler) PollConnectors(ctx context.Context) {
	each(s.Connectors, func(c Connector) { s.poll(ctx, c) })
}

func (s *Scheduler) poll(ctx context.Context, c Connector) {
	name := c.Source.Name()
	// Done before the next round starts.
	r, err := fetch(ctx, c.Source, min(connectorTimeout, s.connectorInterval()))
	if ctx.Err() != nil {
		return // the server is stopping; that is not the connector's failure
	}
	now := s.now()
	if err == nil {
		// The configuration decides the name and that this came from a connector; the
		// source decides the rest.
		fixed := *r
		fixed.System.Name, fixed.System.Source = name, "connector"
		if fixed.Schema == 0 {
			fixed.Schema = report.Schema
		}
		if fixed.System.Kind == "" {
			fixed.System.Kind = c.Kind
		}
		if fixed.Sent.IsZero() {
			fixed.Sent = now
		}
		if err = fixed.Validate(); err == nil {
			s.save(ctx, &fixed, now)
			return
		}
		err = fmt.Errorf("the connector's report is not usable: %w", err)
	}
	s.logger().Warn("connector failed", "system", name, "error", err)

	// Keep what the system said last and when, and put the failure next to it. The arrival
	// time stays, so a connector that keeps failing becomes a silent source like any other.
	failed := report.Report{
		Schema: report.Schema, Sent: now,
		System: report.System{Name: name, Kind: c.Kind, Source: "connector"},
	}
	received := now
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	prev, perr := s.Store.System(sctx, name)
	cancel()
	switch {
	case perr == nil && prev.Report.System.Source == "connector":
		failed, received = prev.Report, prev.ReceivedAt
		kept := make([]report.Problem, 0, len(failed.Errors)+1)
		for _, p := range failed.Errors {
			if p.Collector != model.ConnectorProblem {
				kept = append(kept, p)
			}
		}
		failed.Errors = kept
	case perr != nil && !errors.Is(perr, store.ErrNotFound):
		s.logger().Error("connector failure not stored", "system", name, "error", perr)
		return
	}
	failed.Errors = append(failed.Errors, report.Problem{Collector: model.ConnectorProblem, Message: clip(err.Error(), maxProblem)})
	s.save(ctx, &failed, received)
}

// fetch asks one source, with a time limit, and turns a panic in it into an error: one
// broken connector must not take the dashboard down.
func fetch(ctx context.Context, src connect.Source, limit time.Duration) (r *report.Report, err error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			r, err = nil, fmt.Errorf("the connector crashed: %v", p)
		}
	}()
	r, err = src.Fetch(ctx)
	if err == nil && r == nil {
		err = errors.New("the connector returned nothing")
	}
	return r, err
}

func (s *Scheduler) save(ctx context.Context, r *report.Report, received time.Time) {
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	if err := s.Store.SaveReport(ctx, r, received); err != nil {
		s.logger().Error("connector report not stored", "system", r.System.Name, "error", err)
	}
}

// clip shortens a message to n bytes without cutting a character in half.
func clip(msg string, n int) string {
	if len(msg) <= n {
		return msg
	}
	for n > 0 && msg[n]&0xC0 == 0x80 {
		n--
	}
	return msg[:n] + "…"
}

// CheckImages asks the registry about every image in the latest reports whose last answer
// is older than RegistryInterval, or failed at least half an hour ago.
func (s *Scheduler) CheckImages(ctx context.Context) {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	systems, err := s.Store.Systems(sctx)
	var checks map[string]model.ImageCheck
	if err == nil {
		checks, err = s.Store.ImageChecks(sctx)
	}
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			s.logger().Error("images not checked: the state could not be read", "error", err)
		}
		return
	}
	now := s.now()
	seen := map[string]bool{}
	var due []string
	for _, st := range systems {
		for _, c := range st.Report.Containers {
			if seen[c.Image] {
				continue
			}
			seen[c.Image] = true
			if !checkable(c.Image) {
				continue
			}
			if prev, ok := checks[c.Image]; !ok || s.isDue(prev, now) {
				due = append(due, c.Image)
			}
		}
	}
	sort.Strings(due)
	// Images nobody runs any more: their answers would stay in the state for ever.
	for image, prev := range checks {
		if seen[image] || now.Sub(prev.CheckedAt) < checkKept {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, storeTimeout)
		if err := s.Store.DeleteImageCheck(sctx, image); err != nil && ctx.Err() == nil {
			s.logger().Error("old registry check not removed", "image", image, "error", err)
		}
		cancel()
	}
	each(due, func(image string) {
		if ctx.Err() != nil {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, imageTimeout)
		check := s.Registry.Check(cctx, image)
		cancel()
		if ctx.Err() != nil {
			return // stopping: an answer cut short is not worth keeping
		}
		check.Image = image
		if check.CheckedAt.IsZero() {
			check.CheckedAt = s.now()
		}
		if prev, ok := checks[image]; ok {
			check = keepKnown(prev, check)
		}
		if check.Error != "" {
			s.logger().Warn("registry check failed", "image", image, "error", check.Error)
		}
		sctx, cancel := context.WithTimeout(ctx, storeTimeout)
		defer cancel()
		if err := s.Store.SaveImageCheck(sctx, check); err != nil {
			s.logger().Error("registry check not stored", "image", image, "error", err)
		}
	})
}

// isDue reports whether an image that was asked about before should be asked about again.
func (s *Scheduler) isDue(prev model.ImageCheck, now time.Time) bool {
	age := now.Sub(prev.CheckedAt)
	switch {
	case age < 0:
		return true // the clock was set back; the old answer's age is unknown
	case prev.Error != "":
		return age >= min(registryRetry, s.registryInterval())
	}
	return age >= s.registryInterval()
}

// keepKnown fills what a failed check could not find out with what the last one knew. A
// registry that is down for an afternoon must not make a known update disappear and come
// back; a newer version stays newer.
func keepKnown(prev, cur model.ImageCheck) model.ImageCheck {
	if cur.Error == "" {
		return cur
	}
	for _, f := range []struct{ cur, prev *string }{
		{&cur.Tag, &prev.Tag}, {&cur.TagDigest, &prev.TagDigest},
		{&cur.NewerPatch, &prev.NewerPatch}, {&cur.NewerMinor, &prev.NewerMinor}, {&cur.NewerMajor, &prev.NewerMajor},
	} {
		if *f.cur == "" {
			*f.cur = *f.prev
		}
	}
	return cur
}

// checkable reports whether a registry can be asked about an image reference. It cannot for
// an image built on the machine itself ("localhost/..."), for one pinned by digest without
// a tag (there is nothing it could move to), or for a bare image ID.
func checkable(image string) bool {
	name, _, pinned := strings.Cut(image, "@")
	host, _, hasHost := strings.Cut(name, "/")
	last := name[strings.LastIndexByte(name, '/')+1:]
	switch {
	case name == "":
		return false
	case hasHost && (host == "localhost" || strings.HasPrefix(host, "localhost:")):
		return false
	case pinned && !strings.Contains(last, ":"):
		return false
	case !hasHost && isImageID(name):
		return false
	}
	return true
}

// isImageID recognises what a runtime prints for a container started from an image without
// a name: "sha256:..." or 12 to 64 hex digits.
func isImageID(s string) bool {
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) < 12 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// MailDigest sends the digest when the schedule says it is time: once after each daily or
// weekly moment, or when the findings are not the ones of the last mail.
func (s *Scheduler) MailDigest(ctx context.Context) {
	sched, err := notify.ParseSchedule(s.Mail.Schedule)
	if err != nil {
		s.logger().Error("no digest", "error", err) // Load refuses such a schedule; this is for other callers
		return
	}
	now := s.now()
	s.mu.Lock()
	wait := now.Before(s.mailRetryAfter)
	s.mu.Unlock()
	if wait {
		return
	}

	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	systems, err := s.Store.Systems(sctx)
	var checks map[string]model.ImageCheck
	var sentText, lastPrint string
	if err == nil {
		checks, err = s.Store.ImageChecks(sctx)
	}
	if err == nil {
		sentText, err = s.Values.Value(sctx, keyMailSent)
	}
	if err == nil {
		lastPrint, err = s.Values.Value(sctx, keyMailFingerprint)
	}
	if err != nil {
		if ctx.Err() == nil {
			s.logger().Error("no digest: the state could not be read", "error", err)
		}
		return
	}
	// What was mailed must be remembered even when the server is told to stop right after
	// sending, or the same digest goes out again when it starts.
	remember := func(key, value string) error {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
		defer cancel()
		err := s.Values.SetValue(wctx, key, value)
		if err != nil {
			s.logger().Error("digest state not stored", "key", key, "error", err)
		}
		return err
	}
	lastSent, _ := time.Parse(time.RFC3339, sentText) // unreadable counts as never
	if lastSent.After(now) {
		// The clock was set back. Counting from a moment that has not come yet would keep
		// the digest away until it has: count from now instead.
		lastSent = now
		remember(keyMailSent, now.Format(time.RFC3339))
	}
	findings := model.Findings(systems, checks, now, s.Policy)
	fingerprint := notify.Fingerprint(findings)
	switch {
	case sched.OnChange && fingerprint == lastPrint:
		return
	case sched.OnChange && lastPrint == "" && len(findings) == 0:
		remember(keyMailFingerprint, fingerprint) // a new server with nothing to say stays quiet
		return
	case sched.OnChange && !lastSent.IsZero() && now.Sub(lastSent) < mailChangeGap:
		return // soon; whatever else changes until then goes into the same mail
	case !sched.OnChange && lastSent.IsZero():
		// First start: the next moment on the schedule is the first digest, not one that
		// passed before this server existed.
		remember(keyMailSent, now.Format(time.RFC3339))
		return
	case !sched.OnChange && !lastSent.Before(sched.Last(now)):
		return
	}

	subject, text, html := notify.Render(s.Mail, systems, findings, now)
	send := s.Send
	if send == nil {
		send = notify.Send
	}
	pause := func(d time.Duration) {
		s.mu.Lock()
		s.mailRetryAfter = now.Add(d)
		s.mu.Unlock()
	}
	if err := send(ctx, s.Mail, subject, text, html); err != nil {
		if ctx.Err() == nil {
			s.logger().Error("digest not sent", "error", err, "retry_in", mailRetry.String())
		}
		pause(mailRetry)
		return
	}
	s.logger().Info("digest sent", "subject", subject, "recipients", len(s.Mail.To))
	if errors.Join(remember(keyMailSent, now.Format(time.RFC3339)), remember(keyMailFingerprint, fingerprint)) != nil {
		// Without that memory the next look would send the same mail again, and the one
		// after that: better one digest late than one a minute.
		pause(mailForgotten)
	}
}
