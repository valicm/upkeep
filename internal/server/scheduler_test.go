package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/valicm/upkeep/internal/connect"
	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/notify"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/store"
)

// clock is a time the test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// source is a connector that answers what the test tells it to.
type source struct {
	name   string
	answer func(ctx context.Context) (*report.Report, error)
	calls  atomic.Int32
}

func (s *source) Name() string { return s.name }

func (s *source) Fetch(ctx context.Context) (*report.Report, error) {
	s.calls.Add(1)
	return s.answer(ctx)
}

// firewall is what an OPNsense connector reports when all is well.
func firewall(version string) *report.Report {
	return &report.Report{
		Schema: report.Schema,
		System: report.System{Name: "whatever the connector thinks", Kind: "opnsense", OS: "OPNsense", OSVersion: version, Source: "connector"},
		Sent:   time.Date(2026, 11, 19, 6, 0, 0, 0, time.UTC),
		Software: []report.Software{
			{Name: "OPNsense", Kind: "firmware", Installed: version, Latest: version},
		},
		Errors: []report.Problem{{Collector: "plugins", Message: "the plugin list was empty"}},
	}
}

func problems(r report.Report) []string {
	out := []string{}
	for _, p := range r.Errors {
		out = append(out, p.Collector+": "+p.Message)
	}
	return out
}

func titles(fs []model.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Severity.String()+" "+f.Title)
	}
	return out
}

func TestPollConnectors(t *testing.T) {
	start := time.Date(2026, 11, 19, 6, 0, 0, 0, time.UTC)
	denied := errors.New("asking for the firmware status: 401 Unauthorized")
	type step struct {
		after  time.Duration // time that passes before this poll
		report *report.Report
		err    error
		panics bool
		// What the store must hold afterwards.
		received time.Duration // when the stored report arrived, counted from the start
		version  string        // the OS version in it: shows whose data was kept
		kind     string
		problems []string
		findings []string
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{
			name: "a connector that answers",
			steps: []step{
				{report: firewall("26.10.1"), version: "26.10.1", kind: "opnsense",
					problems: []string{"plugins: the plugin list was empty"},
					findings: []string{"warn collector plugins failed"}},
				{after: 15 * time.Minute, report: firewall("26.10.2"), received: 15 * time.Minute, version: "26.10.2", kind: "opnsense",
					problems: []string{"plugins: the plugin list was empty"},
					findings: []string{"warn collector plugins failed"}},
			},
		},
		{
			name: "a connector that never worked is on the dashboard with its problem",
			steps: []step{
				{err: denied, kind: "opnsense",
					problems: []string{"connector: asking for the firmware status: 401 Unauthorized"},
					findings: []string{"warn connector failed"}},
				// It keeps failing: still one problem, and the time of the first try stays,
				// so after two hours it is a silent source as well.
				{after: 15 * time.Minute, err: denied, kind: "opnsense",
					problems: []string{"connector: asking for the firmware status: 401 Unauthorized"},
					findings: []string{"warn connector failed"}},
				{after: 2 * time.Hour, err: errors.New("dial tcp: connection refused"), kind: "opnsense",
					problems: []string{"connector: dial tcp: connection refused"},
					findings: []string{"crit no report since 2026-11-19 06:00 UTC", "warn connector failed"}},
			},
		},
		{
			name: "a connector that stops working keeps what it knew, and recovers",
			steps: []step{
				{report: firewall("26.10.1"), version: "26.10.1", kind: "opnsense",
					problems: []string{"plugins: the plugin list was empty"},
					findings: []string{"warn collector plugins failed"}},
				{after: 15 * time.Minute, err: denied, version: "26.10.1", kind: "opnsense",
					problems: []string{"plugins: the plugin list was empty", "connector: asking for the firmware status: 401 Unauthorized"},
					findings: []string{"warn collector plugins failed", "warn connector failed"}},
				{after: 15 * time.Minute, err: denied, version: "26.10.1", kind: "opnsense",
					problems: []string{"plugins: the plugin list was empty", "connector: asking for the firmware status: 401 Unauthorized"},
					findings: []string{"warn collector plugins failed", "warn connector failed"}},
				{after: 3 * time.Hour, report: firewall("26.10.2"), received: 3*time.Hour + 30*time.Minute, version: "26.10.2", kind: "opnsense",
					problems: []string{"plugins: the plugin list was empty"},
					findings: []string{"warn collector plugins failed"}},
			},
		},
		{
			name: "a connector that returns nothing, crashes or returns nonsense is a failed one",
			steps: []step{
				{kind: "opnsense", problems: []string{"connector: the connector returned nothing"}, findings: []string{"warn connector failed"}},
				{panics: true, kind: "opnsense", problems: []string{"connector: the connector crashed: index out of range"}, findings: []string{"warn connector failed"}},
				{report: &report.Report{Schema: 99}, kind: "opnsense",
					problems: []string{"connector: the connector's report is not usable: unknown schema"}, findings: []string{"warn connector failed"}},
			},
		},
		{
			name: "a report that leaves out what the server knows is completed",
			steps: []step{
				{report: &report.Report{}, kind: "opnsense", problems: []string{}, findings: []string{}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			mem := store.NewMemory()
			now := &clock{t: start}
			var next step
			src := &source{name: "opnsense01", answer: func(ctx context.Context) (*report.Report, error) {
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Minute {
					t.Errorf("the connector was asked without a time limit, or one beyond the next round: %v", deadline)
				}
				if next.panics {
					panic("index out of range")
				}
				return next.report, next.err
			}}
			s := &Scheduler{Store: mem, Connectors: []Connector{{Source: src, Kind: "opnsense"}}, Policy: model.DefaultPolicy(), Now: now.Now, Log: quiet,
				ConnectorInterval: time.Minute}
			for i, st := range tt.steps {
				next = st
				now.advance(st.after)
				s.PollConnectors(ctx)

				got, err := mem.System(ctx, "opnsense01")
				if err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
				r := got.Report
				if r.System.Name != "opnsense01" || r.System.Source != "connector" || r.Schema != report.Schema || r.Sent.IsZero() {
					t.Errorf("step %d: stored as %+v, schema %d, sent %v", i, r.System, r.Schema, r.Sent)
				}
				if r.System.Kind != st.kind || r.System.OSVersion != st.version {
					t.Errorf("step %d: kind %q, version %q; want %q, %q", i, r.System.Kind, r.System.OSVersion, st.kind, st.version)
				}
				if want := start.Add(st.received); !got.ReceivedAt.Equal(want) {
					t.Errorf("step %d: arrival time %v, want %v", i, got.ReceivedAt, want)
				}
				if !slices.Equal(problems(r), st.problems) {
					t.Errorf("step %d: problems %q, want %q", i, problems(r), st.problems)
				}
				if f := titles(model.Findings([]model.SystemState{got}, nil, now.Now(), s.Policy)); !slices.Equal(f, st.findings) {
					t.Errorf("step %d: findings %q, want %q", i, f, st.findings)
				}
			}
			if n := int(src.calls.Load()); n != len(tt.steps) {
				t.Errorf("the connector was asked %d times in %d polls", n, len(tt.steps))
			}
		})
	}
}

func TestPollConnectorsTogether(t *testing.T) {
	mem := store.NewMemory()
	var running, most atomic.Int32
	var sources []Connector
	for i := range 11 {
		name := fmt.Sprintf("fw%02d", i)
		sources = append(sources, Connector{Kind: "opnsense", Source: &source{name: name, answer: func(context.Context) (*report.Report, error) {
			n := running.Add(1)
			defer running.Add(-1)
			for {
				old := most.Load()
				if n <= old || most.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			if name == "fw03" {
				return nil, errors.New("no route to host")
			}
			return firewall("26.10.1"), nil
		}}})
	}
	s := &Scheduler{Store: mem, Connectors: sources, Log: quiet}
	s.PollConnectors(t.Context())

	systems, _ := mem.Systems(t.Context())
	if len(systems) != 11 {
		t.Fatalf("%d systems stored, want all 11: one that fails must not stop the others", len(systems))
	}
	if got := problems(systems[3].Report); !slices.Equal(got, []string{"connector: no route to host"}) {
		t.Errorf("fw03: %q", got)
	}
	if most.Load() > parallel {
		t.Errorf("%d connectors were asked at once, want at most %d", most.Load(), parallel)
	}
}

func TestPollConnectorsWhileStopping(t *testing.T) {
	mem := store.NewMemory()
	ctx, cancel := context.WithCancel(t.Context())
	src := &source{name: "opnsense01", answer: func(ctx context.Context) (*report.Report, error) {
		cancel() // the server is told to stop while the connector is out asking
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	s := &Scheduler{Store: mem, Connectors: []Connector{{Source: src}}, Log: quiet}
	s.PollConnectors(ctx)
	if systems, _ := mem.Systems(t.Context()); len(systems) != 0 {
		t.Errorf("stopping was stored as the connector's failure: %q", problems(systems[0].Report))
	}
}

// registryFake answers from a table and remembers what it was asked.
type registryFake struct {
	answers map[string]model.ImageCheck
	now     func() time.Time

	mu      sync.Mutex
	asked   []string
	running int
	most    int
	slow    time.Duration
}

func (r *registryFake) Check(ctx context.Context, image string) model.ImageCheck {
	r.mu.Lock()
	r.asked = append(r.asked, image)
	r.running++
	r.most = max(r.most, r.running)
	_, limited := ctx.Deadline()
	r.mu.Unlock()
	if r.slow > 0 {
		time.Sleep(r.slow)
	}
	r.mu.Lock()
	r.running--
	r.mu.Unlock()
	if !limited {
		return model.ImageCheck{Image: image, Error: "asked without a time limit"}
	}
	c, ok := r.answers[image]
	if !ok {
		c = model.ImageCheck{Tag: "from the registry"}
	}
	c.Image = image
	if c.CheckedAt.IsZero() && r.now != nil {
		c.CheckedAt = r.now()
	}
	return c
}

func (r *registryFake) askedSorted() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := slices.Clone(r.asked)
	slices.Sort(out)
	return out
}

func withContainers(name string, images ...string) *report.Report {
	r := &report.Report{Schema: report.Schema, System: report.System{Name: name, Source: "agent"}}
	for i, image := range images {
		r.Containers = append(r.Containers, report.Container{Name: fmt.Sprintf("c%d", i), Image: image})
	}
	return r
}

func TestCheckImages(t *testing.T) {
	start := time.Date(2026, 11, 19, 6, 0, 0, 0, time.UTC)
	const (
		gitea   = "docker.io/gitea/gitea:1.23.6"
		mariadb = "docker.io/library/mariadb:11.4.13"
		adguard = "docker.io/adguard/adguardhome:latest"
		beszel  = "docker.io/henrygd/beszel:0.21.2"
		unifi   = "lscr.io/linuxserver/unifi-network-application:10.0.162-ls114"
		materia = "ghcr.io/stryan/materia@sha256:9a8b7c6d5e4f30211a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a8b"
		local   = "localhost/medimorec-server:current"
		pinned  = "docker.io/library/mongo:7.0.48@sha256:1f3c5a7e9b2d4f6081a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7"
	)
	ago := func(d time.Duration) time.Time { return start.Add(-d) }
	tests := []struct {
		name    string
		reports []*report.Report
		before  []model.ImageCheck          // what the store holds already
		answers map[string]model.ImageCheck // what the registry says now
		asked   []string                    // sorted
		after   map[string]model.ImageCheck // checks to find in the store afterwards
	}{
		{
			name:    "every image once, however many containers and systems run it",
			reports: []*report.Report{withContainers("server", gitea, mariadb, mariadb), withContainers("ops01", adguard, gitea)},
			answers: map[string]model.ImageCheck{gitea: {Tag: "1.23.6", TagDigest: "sha256:aa", NewerPatch: "1.23.8"}},
			asked:   []string{adguard, gitea, mariadb},
			after: map[string]model.ImageCheck{
				gitea:   {Image: gitea, Tag: "1.23.6", TagDigest: "sha256:aa", NewerPatch: "1.23.8", CheckedAt: start},
				mariadb: {Image: mariadb, Tag: "from the registry", CheckedAt: start},
				adguard: {Image: adguard, Tag: "from the registry", CheckedAt: start},
			},
		},
		{
			name:    "local images, images pinned by digest and bare IDs are not asked about",
			reports: []*report.Report{withContainers("server", local, materia, "localhost:5000/app:1", "sha256:0c1d2e3f4a5b6c7d8e9f", "0c1d2e3f4a5b", "", pinned, unifi)},
			asked:   []string{pinned, unifi},
		},
		{
			name:    "an answer stays good for the interval",
			reports: []*report.Report{withContainers("server", gitea, mariadb, adguard)},
			before: []model.ImageCheck{
				{Image: gitea, Tag: "1.23.6", NewerPatch: "1.23.7", CheckedAt: ago(5*time.Hour + 59*time.Minute)},
				{Image: mariadb, Tag: "11.4.13", CheckedAt: ago(6 * time.Hour)},
				{Image: adguard, Tag: "latest", CheckedAt: ago(-time.Hour)}, // from before the clock was set back
			},
			asked: []string{adguard, mariadb},
			after: map[string]model.ImageCheck{
				gitea:   {Image: gitea, Tag: "1.23.6", NewerPatch: "1.23.7", CheckedAt: ago(5*time.Hour + 59*time.Minute)},
				mariadb: {Image: mariadb, Tag: "from the registry", CheckedAt: start},
			},
		},
		{
			name:    "a failed check is tried again after half an hour, not before",
			reports: []*report.Report{withContainers("server", gitea, mariadb)},
			before: []model.ImageCheck{
				{Image: gitea, Error: "429 Too Many Requests", CheckedAt: ago(29 * time.Minute)},
				{Image: mariadb, Error: "429 Too Many Requests", CheckedAt: ago(30 * time.Minute)},
			},
			asked: []string{mariadb},
			after: map[string]model.ImageCheck{
				gitea:   {Image: gitea, Error: "429 Too Many Requests", CheckedAt: ago(29 * time.Minute)},
				mariadb: {Image: mariadb, Tag: "from the registry", CheckedAt: start},
			},
		},
		{
			name:    "a check that fails keeps what the last one knew",
			reports: []*report.Report{withContainers("server", gitea, beszel)},
			before: []model.ImageCheck{
				{Image: gitea, Tag: "1.23.6", TagDigest: "sha256:aa", NewerPatch: "1.23.8", NewerMinor: "1.25.2", CheckedAt: ago(7 * time.Hour)},
				{Image: beszel, Tag: "0.21.2", TagDigest: "sha256:bb", NewerPatch: "0.21.3", CheckedAt: ago(7 * time.Hour)},
			},
			answers: map[string]model.ImageCheck{
				gitea: {Error: "asking what gitea/gitea:1.23.6 points at: 503"},
				// The digest was read, the list of tags was not: what is new is kept.
				beszel: {Tag: "0.21.2", TagDigest: "sha256:cc", Error: "listing the tags of henrygd/beszel: timeout"},
			},
			asked: []string{gitea, beszel},
			after: map[string]model.ImageCheck{
				gitea:  {Image: gitea, Tag: "1.23.6", TagDigest: "sha256:aa", NewerPatch: "1.23.8", NewerMinor: "1.25.2", CheckedAt: start, Error: "asking what gitea/gitea:1.23.6 points at: 503"},
				beszel: {Image: beszel, Tag: "0.21.2", TagDigest: "sha256:cc", NewerPatch: "0.21.3", CheckedAt: start, Error: "listing the tags of henrygd/beszel: timeout"},
			},
		},
		{
			name:    "a good answer replaces everything, also what is no longer true",
			reports: []*report.Report{withContainers("server", gitea)},
			before:  []model.ImageCheck{{Image: gitea, Tag: "1.23.6", NewerPatch: "1.23.8", Error: "503", CheckedAt: ago(time.Hour)}},
			answers: map[string]model.ImageCheck{gitea: {Tag: "1.23.6", TagDigest: "sha256:aa"}},
			asked:   []string{gitea},
			after:   map[string]model.ImageCheck{gitea: {Image: gitea, Tag: "1.23.6", TagDigest: "sha256:aa", CheckedAt: start}},
		},
		{
			name:  "no containers, no questions",
			asked: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			mem := store.NewMemory()
			for _, r := range tt.reports {
				if err := mem.SaveReport(ctx, r, start); err != nil {
					t.Fatal(err)
				}
			}
			for _, c := range tt.before {
				if err := mem.SaveImageCheck(ctx, c); err != nil {
					t.Fatal(err)
				}
			}
			reg := &registryFake{answers: tt.answers}
			s := &Scheduler{Store: mem, Registry: reg, RegistryInterval: 6 * time.Hour, Now: func() time.Time { return start }, Log: quiet}
			s.CheckImages(ctx)

			if got := reg.askedSorted(); !slices.Equal(got, tt.asked) {
				t.Errorf("asked about %q, want %q", got, tt.asked)
			}
			checks, err := mem.ImageChecks(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for image, want := range tt.after {
				got := checks[image]
				if !got.CheckedAt.Equal(want.CheckedAt) {
					t.Errorf("%s: checked at %v, want %v", image, got.CheckedAt, want.CheckedAt)
				}
				got.CheckedAt, want.CheckedAt = time.Time{}, time.Time{}
				if got != want {
					t.Errorf("%s:\n got %+v\nwant %+v", image, got, want)
				}
			}
			for image := range checks {
				if !slices.Contains(tt.asked, image) && !slices.ContainsFunc(tt.before, func(c model.ImageCheck) bool { return c.Image == image }) {
					t.Errorf("a check of %s was stored although nobody asked", image)
				}
			}
		})
	}
}

func TestCheckImagesTogether(t *testing.T) {
	ctx := t.Context()
	mem := store.NewMemory()
	var images []string
	for i := range 14 {
		images = append(images, fmt.Sprintf("docker.io/library/mariadb:11.4.%d", i))
	}
	if err := mem.SaveReport(ctx, withContainers("server", images...), time.Now()); err != nil {
		t.Fatal(err)
	}
	reg := &registryFake{slow: 2 * time.Millisecond}
	s := &Scheduler{Store: mem, Registry: reg, RegistryInterval: 6 * time.Hour, Log: quiet}
	s.CheckImages(ctx)
	if len(reg.asked) != 14 || reg.most > parallel {
		t.Errorf("asked %d times, %d at once; want 14 and at most %d at once", len(reg.asked), reg.most, parallel)
	}
	checks, _ := mem.ImageChecks(ctx)
	for _, c := range checks {
		if c.Error != "" || c.CheckedAt.IsZero() {
			t.Fatalf("stored check: %+v", c)
		}
	}
	// A second look right away finds nothing to do.
	s.CheckImages(ctx)
	if len(reg.asked) != 14 {
		t.Errorf("asked again about images just checked: %d questions", len(reg.asked))
	}
}

func TestCheckImagesWhileStopping(t *testing.T) {
	mem := store.NewMemory()
	if err := mem.SaveReport(t.Context(), withContainers("server", "docker.io/gitea/gitea:1.23.6"), time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	reg := checkerFunc(func(ctx context.Context, image string) model.ImageCheck {
		cancel()
		return model.ImageCheck{Image: image, Error: "context canceled"}
	})
	s := &Scheduler{Store: mem, Registry: reg, RegistryInterval: 6 * time.Hour, Log: quiet}
	s.CheckImages(ctx)
	if checks, _ := mem.ImageChecks(t.Context()); len(checks) != 0 {
		t.Errorf("stopping was stored as a registry's failure: %+v", checks)
	}
}

type checkerFunc func(ctx context.Context, image string) model.ImageCheck

func (f checkerFunc) Check(ctx context.Context, image string) model.ImageCheck { return f(ctx, image) }

func TestCheckable(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"docker.io/gitea/gitea:1.23.6", true},
		{"docker.io/library/mariadb:11.8.9", true},
		{"docker.io/photoprism/photoprism:251130", true},
		{"lscr.io/linuxserver/unifi-network-application:10.0.162-ls114", true},
		{"docker.io/adguard/adguardhome:latest", true},
		{"docker.io/louislam/uptime-kuma:2", true},
		{"docker.io/library/alpine", true}, // no tag means "latest"
		{"nginx:1.27", true},
		{"registry.example.net:5000/app:1.0", true},
		{"docker.io/library/mongo:7.0.48@sha256:1f3c5a7e9b2d", true},
		{"ghcr.io/stryan/materia@sha256:9a8b7c6d5e4f", false},
		{"registry.example.net:5000/app@sha256:9a8b7c6d5e4f", false},
		{"localhost/medimorec-server:current", false},
		{"localhost:5000/app:1.0", false},
		{"sha256:0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f", false},
		{"0c1d2e3f4a5b", false},
		{"", false},
		{"@sha256:9a8b7c6d5e4f", false},
	}
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			if got := checkable(tt.image); got != tt.want {
				t.Errorf("checkable = %v, want %v", got, tt.want)
			}
		})
	}
}

// outbox is where the digests of a test end up instead of at a relay.
type outbox struct {
	mu    sync.Mutex
	mails []string // subjects
	texts []string
	fail  error
}

func (o *outbox) send(_ context.Context, cfg notify.Config, subject, text, html string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail != nil {
		return o.fail
	}
	if !strings.Contains(html, "<html") || len(cfg.To) == 0 {
		return errors.New("the digest came without its HTML or its recipients")
	}
	o.mails = append(o.mails, subject)
	o.texts = append(o.texts, text)
	return nil
}

func (o *outbox) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.mails)
}

const (
	allGood    = "upkeep: nothing needs attention"
	oneWarning = "upkeep: 1 warning"
)

func TestMailDigest(t *testing.T) {
	// 2026-11-19 is a Thursday. The schedule is in the clock's own time zone.
	zone := time.FixedZone("CET", 3600)
	at := func(day, hour, minute int) time.Time { return time.Date(2026, 11, day, hour, minute, 0, 0, zone) }
	rebootNeeded := func(name string) *report.Report {
		return &report.Report{Schema: 1, System: report.System{Name: name, Source: "agent"},
			Packages: &report.Packages{Manager: "apt", RebootRequired: true}}
	}
	healthy := func(name string) *report.Report {
		return &report.Report{Schema: 1, System: report.System{Name: name, Source: "agent"}}
	}
	type step struct {
		at       time.Time
		report   *report.Report // arrives just before the scheduler looks
		sendErr  error          // the relay is down
		mails    int            // digests sent so far, after this look
		lastMail string         // subject of the latest one, when mails > 0
	}
	tests := []struct {
		name     string
		schedule string
		sentAt   time.Time // what the store remembers from before, if anything
		steps    []step
	}{
		{
			name:     "daily: the first start waits for the next time on the schedule",
			schedule: "daily 07:00",
			steps: []step{
				{at: at(19, 9, 30), mails: 0},
				{at: at(19, 23, 59), mails: 0},
				{at: at(20, 6, 59), mails: 0},
				{at: at(20, 7, 0), mails: 1, lastMail: allGood},
				{at: at(20, 7, 1), mails: 1},
				{at: at(20, 18, 0), report: healthy("server"), mails: 1},
				{at: at(21, 6, 30), report: rebootNeeded("server"), mails: 1},
				{at: at(21, 7, 0), mails: 2, lastMail: oneWarning},
			},
		},
		{
			name:     "daily: a time missed while the server was down is made up for once",
			schedule: "daily 07:00",
			sentAt:   at(18, 7, 0),
			steps: []step{
				{at: at(19, 9, 30), mails: 1, lastMail: allGood},
				{at: at(19, 9, 31), mails: 1},
				{at: at(20, 7, 0), mails: 2},
			},
		},
		{
			name:     "daily: a relay that is down is tried again five minutes later, not every minute",
			schedule: "daily 07:00",
			sentAt:   at(18, 7, 0),
			steps: []step{
				{at: at(19, 7, 0), sendErr: errors.New("connection refused"), mails: 0},
				{at: at(19, 7, 1), mails: 0}, // the relay is back, but it is not time to try yet
				{at: at(19, 7, 4), mails: 0},
				{at: at(19, 7, 5), mails: 1, lastMail: allGood},
				{at: at(19, 7, 6), mails: 1},
			},
		},
		{
			name:     "weekly: only on its day",
			schedule: "weekly fri 07:00",
			sentAt:   at(13, 7, 0),
			steps: []step{
				{at: at(19, 7, 0), mails: 0},
				{at: at(20, 6, 59), mails: 0},
				{at: at(20, 7, 0), mails: 1},
				{at: at(21, 7, 0), mails: 1},
				{at: at(27, 7, 0), mails: 2},
			},
		},
		{
			name:     "the default schedule is daily at seven",
			schedule: "",
			sentAt:   at(18, 7, 0),
			steps: []step{
				{at: at(19, 6, 59), mails: 0},
				{at: at(19, 7, 0), mails: 1},
			},
		},
		{
			name:     "on change: a new server with nothing to say stays quiet",
			schedule: "on change",
			steps: []step{
				{at: at(19, 9, 0), mails: 0},
				{at: at(19, 9, 1), report: healthy("server"), mails: 0},
				{at: at(19, 10, 0), mails: 0},
			},
		},
		{
			name:     "on change: a mail when the findings change, and only then",
			schedule: "on change",
			steps: []step{
				{at: at(19, 9, 0), report: rebootNeeded("server"), mails: 1, lastMail: oneWarning},
				{at: at(19, 9, 1), mails: 1},
				{at: at(19, 10, 0), report: rebootNeeded("server"), mails: 1}, // it reports the same again
				// Then nothing for two and a half hours: a silent system is a change.
				{at: at(19, 12, 30), mails: 2, lastMail: "upkeep: 1 critical, 1 warning"},
				{at: at(19, 13, 30), mails: 2}, // still silent, an hour longer: the same findings
				{at: at(19, 14, 0), report: healthy("server"), mails: 3, lastMail: allGood},
				{at: at(19, 14, 1), mails: 3},
			},
		},
		{
			name:     "on change: changes within ten minutes of a mail wait and go out together",
			schedule: "on change",
			steps: []step{
				{at: at(19, 9, 0), report: rebootNeeded("server"), mails: 1, lastMail: oneWarning},
				{at: at(19, 9, 2), report: rebootNeeded("pi"), mails: 1},
				{at: at(19, 9, 5), report: rebootNeeded("ops01"), mails: 1},
				{at: at(19, 9, 9), mails: 1},
				{at: at(19, 9, 10), mails: 2, lastMail: "upkeep: 3 warnings"},
				{at: at(19, 9, 11), mails: 2},
			},
		},
		{
			name:     "daily: a last mail in the future, from a clock that was wrong, does not keep the digest away",
			schedule: "daily 07:00",
			sentAt:   at(25, 7, 0),
			steps: []step{
				{at: at(19, 9, 0), mails: 0},
				{at: at(20, 6, 59), mails: 0},
				{at: at(20, 7, 0), mails: 1},
			},
		},
		{
			name:     "on change: the same with a clock that was wrong",
			schedule: "on change",
			sentAt:   at(25, 7, 0),
			steps: []step{
				{at: at(19, 9, 0), report: rebootNeeded("server"), mails: 0},
				{at: at(19, 9, 9), mails: 0},
				{at: at(19, 9, 10), mails: 1, lastMail: oneWarning},
			},
		},
		{
			name:     "on change: a mail that could not be sent is not counted as sent",
			schedule: "on change",
			steps: []step{
				{at: at(19, 9, 0), report: rebootNeeded("server"), sendErr: errors.New("connection refused"), mails: 0},
				{at: at(19, 9, 1), mails: 0},
				{at: at(19, 9, 5), mails: 1, lastMail: oneWarning},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			mem, values, out := store.NewMemory(), store.NewMemoryValues(), &outbox{}
			now := &clock{}
			if !tt.sentAt.IsZero() {
				values.SetValue(ctx, keyMailSent, tt.sentAt.Format(time.RFC3339))
			}
			s := &Scheduler{
				Store: mem, Values: values, Policy: model.DefaultPolicy(), Now: now.Now, Log: quiet, Send: out.send,
				Mail: notify.Config{SMTP: "relay:25", From: "upkeep@example.net", To: []string{"owner@example.net"}, Schedule: tt.schedule},
			}
			for i, st := range tt.steps {
				now.mu.Lock()
				now.t = st.at
				now.mu.Unlock()
				if st.report != nil {
					if err := mem.SaveReport(ctx, st.report, st.at); err != nil {
						t.Fatal(err)
					}
				}
				out.fail = st.sendErr
				s.MailDigest(ctx)
				if out.count() != st.mails {
					t.Fatalf("step %d (%s): %d mails sent so far, want %d: %q", i, st.at.Format("Mon 15:04"), out.count(), st.mails, out.mails)
				}
				if st.lastMail != "" && out.mails[len(out.mails)-1] != st.lastMail {
					t.Errorf("step %d: the mail says %q, want %q", i, out.mails[len(out.mails)-1], st.lastMail)
				}
			}
		})
	}
}

// What was mailed is remembered in the store, so a restart neither repeats nor forgets it.
func TestMailDigestRemembers(t *testing.T) {
	ctx := t.Context()
	zone := time.FixedZone("CET", 3600)
	mem, values := store.NewMemory(), store.NewMemoryValues()
	if err := mem.SaveReport(ctx, &report.Report{Schema: 1, System: report.System{Name: "server", Source: "agent"},
		Packages: &report.Packages{Manager: "apt", RebootRequired: true}}, time.Date(2026, 11, 19, 9, 0, 0, 0, zone)); err != nil {
		t.Fatal(err)
	}
	mail := notify.Config{SMTP: "relay:25", From: "upkeep@example.net", To: []string{"owner@example.net"}, Schedule: "on change"}
	out := &outbox{}
	look := func(at time.Time) {
		// A new Scheduler each time: nothing but the store carries over, as after a restart.
		s := &Scheduler{Store: mem, Values: values, Policy: model.DefaultPolicy(), Log: quiet, Send: out.send, Mail: mail,
			Now: func() time.Time { return at }}
		s.MailDigest(ctx)
	}
	look(time.Date(2026, 11, 19, 9, 0, 0, 0, zone))
	look(time.Date(2026, 11, 19, 9, 30, 0, 0, zone))
	if out.count() != 1 {
		t.Fatalf("%d mails after a restart with unchanged findings, want 1", out.count())
	}
	sent, _ := values.Value(ctx, keyMailSent)
	print, _ := values.Value(ctx, keyMailFingerprint)
	if sent != "2026-11-19T09:00:00+01:00" || len(print) != 64 {
		t.Errorf("remembered %q and %q", sent, print)
	}
	if !strings.Contains(out.texts[0], "reboot required") {
		t.Errorf("the digest does not carry the finding:\n%s", out.texts[0])
	}
}

// forgetful keeps values but cannot write them, like a database on a full disk.
type forgetful struct{ store.KeyValue }

func (forgetful) SetValue(context.Context, string, string) error { return errDisk }

func TestMailDigestThatCannotBeRecorded(t *testing.T) {
	ctx := t.Context()
	mem, values, out := store.NewMemory(), store.NewMemoryValues(), &outbox{}
	start := time.Date(2026, 11, 19, 7, 0, 0, 0, time.UTC)
	values.SetValue(ctx, keyMailSent, start.Add(-24*time.Hour).Format(time.RFC3339))
	now := &clock{t: start}
	s := &Scheduler{Store: mem, Values: forgetful{values}, Policy: model.DefaultPolicy(), Now: now.Now, Log: quiet, Send: out.send,
		Mail: notify.Config{SMTP: "relay:25", From: "upkeep@example.net", To: []string{"owner@example.net"}, Schedule: "daily 07:00"}}
	for range 30 {
		s.MailDigest(ctx)
		now.advance(time.Minute)
	}
	if out.count() != 1 {
		t.Errorf("%d mails in half an hour, want 1: a digest must not repeat every minute", out.count())
	}
}

// Run in a bubble of made-up time: a day and a half of the scheduler's life in a moment.
func TestRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mem, values, out := store.NewMemory(), store.NewMemoryValues(), &outbox{}
		fw := &source{name: "opnsense01", answer: func(context.Context) (*report.Report, error) {
			r := firewall("26.10.1")
			r.Errors = nil
			r.Containers = []report.Container{{Name: "adguardhome", Image: "docker.io/adguard/adguardhome:latest"}}
			return r, nil
		}}
		reg := &registryFake{now: time.Now}
		s := &Scheduler{
			Store: mem, Values: values, Connectors: []Connector{{Source: fw, Kind: "opnsense"}}, Registry: reg,
			Policy: model.DefaultPolicy(), Log: quiet, Send: out.send,
			ConnectorInterval: 15 * time.Minute, RegistryInterval: 6 * time.Hour,
			Mail: notify.Config{SMTP: "relay:25", From: "upkeep@example.net", To: []string{"owner@example.net"}, Schedule: "daily 07:00"},
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			s.Run(ctx)
			close(done)
		}()

		synctest.Wait()
		if n := fw.calls.Load(); n != 1 {
			t.Errorf("%d polls right after the start, want 1", n)
		}
		time.Sleep(time.Hour + time.Second)
		synctest.Wait()
		if n := fw.calls.Load(); n != 5 {
			t.Errorf("%d polls in the first hour, want 5: at the start and every 15 minutes", n)
		}
		if got := reg.askedSorted(); len(got) != 1 {
			t.Errorf("the registry was asked %d times in the first hour, want once: %q", len(got), got)
		}
		time.Sleep(35 * time.Hour)
		synctest.Wait()
		if n := fw.calls.Load(); n != 5+35*4 {
			t.Errorf("%d polls in 36 hours, want %d", n, 5+35*4)
		}
		if got := reg.askedSorted(); len(got) != 6 {
			t.Errorf("the registry was asked %d times in 36 hours, want 6: once every 6 hours", len(got))
		}
		// 36 hours hold one or two seven o'clocks, whatever the time zone of this machine.
		if n := out.count(); n < 1 || n > 2 {
			t.Errorf("%d digests in 36 hours, want 1 or 2", n)
		}
		st, err := mem.System(t.Context(), "opnsense01")
		if err != nil || st.Report.System.Source != "connector" || time.Since(st.ReceivedAt) > 15*time.Minute {
			t.Errorf("the connector's report: %+v, %v", st, err)
		}

		cancel()
		<-done // Run returns once everything it started has stopped
	})
}

var _ connect.Source = (*source)(nil)

// The answer about an image nobody runs any more is removed after a week, not at once: a
// machine that is down for a few days comes back to what was known.
func TestCheckImagesForgetsUnusedImages(t *testing.T) {
	ctx := t.Context()
	start := time.Date(2026, 11, 19, 6, 0, 0, 0, time.UTC)
	const (
		inUse   = "docker.io/gitea/gitea:1.23.6"
		local   = "localhost/app:current" // in use, never asked about: its (demo) check stays too
		gone    = "docker.io/library/mongo:6.0.1"
		justNow = "docker.io/library/mongo:7.0.48"
	)
	st := store.NewMemory()
	if err := st.SaveReport(ctx, withContainers("server", inUse, local), start); err != nil {
		t.Fatal(err)
	}
	for image, checked := range map[string]time.Time{
		inUse: start.Add(-time.Hour), local: start.Add(-30 * 24 * time.Hour),
		gone: start.Add(-checkKept - time.Minute), justNow: start.Add(-checkKept + time.Minute),
	} {
		if err := st.SaveImageCheck(ctx, model.ImageCheck{Image: image, CheckedAt: checked}); err != nil {
			t.Fatal(err)
		}
	}
	clk := &clock{t: start}
	s := &Scheduler{Store: st, Values: store.NewMemoryValues(), Registry: &registryFake{now: clk.Now}, Now: clk.Now, Log: quiet}
	s.CheckImages(ctx)

	checks, err := st.ImageChecks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for image := range checks {
		left = append(left, image)
	}
	slices.Sort(left)
	if want := []string{inUse, justNow, local}; !slices.Equal(left, want) {
		t.Errorf("checks left: %v, want %v", left, want)
	}
}
