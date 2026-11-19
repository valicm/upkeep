package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/collect"
	"github.com/valicm/upkeep/internal/connect"
	"github.com/valicm/upkeep/internal/report"
)

// fake is a collector made of a function.
type fake struct {
	name string
	fn   func(ctx context.Context, r *report.Report) error
}

func (f fake) Name() string                                        { return f.name }
func (f fake) Collect(ctx context.Context, r *report.Report) error { return f.fn(ctx, r) }

// logs collects what the agent logs.
type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// testAgent is an agent with short timeouts and a clock that stands still.
func testAgent(l *logs, cs ...collect.Collector) *agent {
	return &agent{
		name:       "testbox",
		collectors: cs,
		timeout:    150 * time.Millisecond,
		grace:      50 * time.Millisecond,
		interval:   15 * time.Minute,
		logf:       l.logf,
		now:        func() time.Time { return time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC) },
		sleep:      func(ctx context.Context, d time.Duration) bool { return ctx.Err() == nil },
		jitter:     func(d time.Duration) time.Duration { return d },
	}
}

func problems(r *report.Report) string {
	var out []string
	for _, p := range r.Errors {
		out = append(out, p.Collector+": "+p.Message)
	}
	return strings.Join(out, " | ")
}

func TestBuild(t *testing.T) {
	packages := func(manager string) fake {
		return fake{"ospkg", func(_ context.Context, r *report.Report) error {
			r.Packages = &report.Packages{Manager: manager, Pending: 3}
			return nil
		}}
	}
	container := fake{"containers", func(_ context.Context, r *report.Report) error {
		r.Containers = append(r.Containers, report.Container{Name: "gitea", Image: "docker.io/gitea/gitea:1.23.6"})
		return nil
	}}
	hostFake := fake{"host", func(_ context.Context, r *report.Report) error {
		r.System.Kind, r.System.OS = "linux", "Debian GNU/Linux 13 (trixie)"
		return nil
	}}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	tests := []struct {
		name       string
		collectors []collect.Collector
		check      func(t *testing.T, r *report.Report)
		problems   string // all of them, as "collector: message | ..."
	}{
		{
			name:       "everything works",
			collectors: []collect.Collector{hostFake, packages("apt"), container},
			check: func(t *testing.T, r *report.Report) {
				if r.System.Kind != "linux" || r.Packages == nil || r.Packages.Pending != 3 || len(r.Containers) != 1 {
					t.Errorf("%+v", r)
				}
			},
		},
		{
			name: "one fails, the others still count",
			collectors: []collect.Collector{
				hostFake,
				fake{"ospkg", func(context.Context, *report.Report) error {
					return errors.New("apt: exit status 100: Unmet dependencies")
				}},
				container,
			},
			check: func(t *testing.T, r *report.Report) {
				if r.Packages != nil || len(r.Containers) != 1 {
					t.Errorf("%+v", r)
				}
			},
			problems: "ospkg: apt: exit status 100: Unmet dependencies",
		},
		{
			name: "a failure leaves nothing half done behind",
			collectors: []collect.Collector{fake{"containers", func(_ context.Context, r *report.Report) error {
				r.Containers = append(r.Containers, report.Container{Name: "first of five"})
				r.Packages = &report.Packages{Manager: "apt"}
				return errors.New("the socket closed")
			}}},
			check: func(t *testing.T, r *report.Report) {
				if len(r.Containers) != 0 || r.Packages != nil {
					t.Errorf("%+v", r)
				}
			},
			problems: "containers: the socket closed",
		},
		{
			name: "a panic is a problem, not the end of the agent",
			collectors: []collect.Collector{
				fake{"backup", func(context.Context, *report.Report) error {
					var jobs []string
					_ = jobs[3]
					return nil
				}},
				container,
			},
			check: func(t *testing.T, r *report.Report) {
				if len(r.Containers) != 1 {
					t.Errorf("the collector after the panic did not run: %+v", r)
				}
			},
			problems: "backup: panic: runtime error: index out of range [3] with length 0",
		},
		{
			name: "a collector that honours its deadline says what it was doing",
			collectors: []collect.Collector{fake{"ospkg", func(ctx context.Context, _ *report.Report) error {
				<-ctx.Done()
				return fmt.Errorf("run apt-get -s dist-upgrade: %w", ctx.Err())
			}}},
			problems: "ospkg: stopped after 150ms: run apt-get -s dist-upgrade: context deadline exceeded",
		},
		{
			name: "a collector that ignores its deadline is left behind",
			collectors: []collect.Collector{
				fake{"containers", func(_ context.Context, r *report.Report) error {
					<-release // long after the report has gone
					r.Containers = append(r.Containers, report.Container{Name: "too late"})
					return nil
				}},
				packages("apt"),
			},
			check: func(t *testing.T, r *report.Report) {
				if len(r.Containers) != 0 || r.Packages == nil {
					t.Errorf("%+v", r)
				}
			},
			problems: "containers: gave no answer within 150ms and was left behind",
		},
		{
			name: "a collector reports its own problem and still delivers",
			collectors: []collect.Collector{fake{"ospkg", func(_ context.Context, r *report.Report) error {
				r.Packages = &report.Packages{Manager: "apt"}
				r.Errors = append(r.Errors, report.Problem{Collector: "ospkg", Message: "apt: there are no package lists"})
				return nil
			}}},
			check: func(t *testing.T, r *report.Report) {
				if r.Packages == nil {
					t.Error("packages are missing")
				}
			},
			problems: "ospkg: apt: there are no package lists",
		},
		{
			name:       "the first answer about packages counts",
			collectors: []collect.Collector{packages("apt"), packages("pkg")},
			check: func(t *testing.T, r *report.Report) {
				if r.Packages.Manager != "apt" {
					t.Errorf("got %s", r.Packages.Manager)
				}
			},
		},
		{
			name: "who the report is about is not a collector's to change",
			collectors: []collect.Collector{
				fake{"rude", func(_ context.Context, r *report.Report) error {
					r.System.Name, r.System.Source, r.System.Kind = "somebody-else", "connector", "linux"
					return nil
				}},
				fake{"second", func(_ context.Context, r *report.Report) error {
					if r.System.Name != "testbox" || r.System.Kind != "linux" {
						return fmt.Errorf("saw %+v", r.System)
					}
					return nil
				}},
			},
			check: func(t *testing.T, r *report.Report) {
				if r.System.Kind != "linux" {
					t.Errorf("%+v", r.System)
				}
			},
		},
		{
			name: "a collector sees nothing of the others",
			collectors: []collect.Collector{
				container,
				fake{"nosy", func(_ context.Context, r *report.Report) error {
					if len(r.Containers) != 0 || r.Schema != report.Schema {
						return fmt.Errorf("saw %d containers", len(r.Containers))
					}
					return nil
				}},
			},
		},
		{name: "no collectors at all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &logs{}
			a := testAgent(l, tt.collectors...)
			r := a.build(t.Context())
			if r.System.Name != "testbox" || r.System.Source != "agent" || r.Schema != report.Schema || !r.Sent.Equal(a.now()) {
				t.Errorf("header: %+v sent %s", r.System, r.Sent)
			}
			if err := r.Validate(); err != nil {
				t.Errorf("not a valid report: %v", err)
			}
			if got := problems(r); got != tt.problems {
				t.Errorf("problems\n got  %s\n want %s", got, tt.problems)
			}
			// Every problem is in the log as well, where the machine's owner looks first.
			for _, p := range r.Errors {
				if !strings.Contains(l.String(), p.Message) {
					t.Errorf("not logged: %s", p.Message)
				}
			}
			if tt.check != nil {
				tt.check(t, r)
			}
		})
	}
}

// When the agent is told to stop, the collectors are cut off and nothing is reported as
// their failure.
func TestBuildStopsWithTheAgent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	ran := 0
	slow := fake{"slow", func(ctx context.Context, _ *report.Report) error {
		ran++
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}}
	a := testAgent(&logs{}, slow, slow, slow)
	r := a.build(ctx)
	if ran != 1 || len(r.Errors) != 0 {
		t.Errorf("ran %d collectors, errors %+v", ran, r.Errors)
	}
}

// A collector that hangs is not started a second time while the first run is still out.
func TestCollectorLeftBehindIsNotStartedAgain(t *testing.T) {
	release := make(chan struct{})
	started := 0
	hung := fake{"containers", func(context.Context, *report.Report) error {
		started++
		<-release
		return nil
	}}
	a := testAgent(&logs{}, hung)

	want := []string{
		"containers: gave no answer within 150ms and was left behind",
		"containers: is still busy with an earlier report and was not started again",
		"containers: is still busy with an earlier report and was not started again",
	}
	for i, w := range want {
		if got := problems(a.build(t.Context())); got != w {
			t.Errorf("report %d: got %q, want %q", i+1, got, w)
		}
	}

	close(release) // it comes back at last
	deadline := time.Now().Add(5 * time.Second)
	for len(a.behind[0]) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := problems(a.build(t.Context())); got != "" || started != 2 {
		t.Errorf("after it came back: problems %q, started %d times", got, started)
	}
}

// source is a connect.Source made of a function.
type source struct {
	name  string
	fetch func(context.Context) (*report.Report, error)
}

func (s source) Name() string                                      { return s.name }
func (s source) Fetch(ctx context.Context) (*report.Report, error) { return s.fetch(ctx) }

func TestLocalSources(t *testing.T) {
	firmware := source{"opnsense02", func(context.Context) (*report.Report, error) {
		return &report.Report{
			System:   report.System{Name: "opnsense02", Kind: "opnsense", Source: "connector"},
			Packages: &report.Packages{Manager: "pkg", Pending: 9},
			Software: []report.Software{{Name: "OPNsense", Kind: "firmware", Installed: "26.10", Latest: "26.10.1", UpdateAvailable: true}},
		}, nil
	}}
	tests := []struct {
		name      string
		collector collect.Collector
		software  int
		problems  string
	}{
		{name: "what the source found is merged in", collector: local("opnsense", firmware, nil, false), software: 1},
		{
			name: "a source that cannot be reached",
			collector: local("homeassistant", source{"ha", func(context.Context) (*report.Report, error) {
				return nil, errors.New("ask http://127.0.0.1:8123/api/config: connection refused")
			}}, nil, false),
			problems: "homeassistant: ask http://127.0.0.1:8123/api/config: connection refused",
		},
		{
			name:      "a source that could not be set up fails in every report",
			collector: local("opnsense", nil, errors.New("read the key file: open /etc/upkeep/opnsense.key: no such file or directory"), true),
			problems:  "opnsense: set up from the [opnsense] table: read the key file: open /etc/upkeep/opnsense.key: no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			own := fake{"ospkg", func(_ context.Context, r *report.Report) error {
				r.Packages = &report.Packages{Manager: "apt", Pending: 1}
				return nil
			}}
			a := testAgent(&logs{}, own, tt.collector)
			r := a.build(t.Context())
			if r.System.Name != "testbox" || r.System.Source != "agent" || r.System.Kind == "opnsense" {
				t.Errorf("the agent's identity changed: %+v", r.System)
			}
			if r.Packages == nil || r.Packages.Manager != "apt" {
				t.Errorf("the machine's own packages must win: %+v", r.Packages)
			}
			if len(r.Software) != tt.software || problems(r) != tt.problems {
				t.Errorf("software %d, problems %q", len(r.Software), problems(r))
			}
		})
	}
}

// An agent that runs on the appliance itself reports as that appliance: its kind, the name
// and the version of what runs there. The name on the dashboard, and that this is an agent,
// are still the agent's to say.
func TestLocalSourceOnTheApplianceItself(t *testing.T) {
	ha := source{"whatever", func(context.Context) (*report.Report, error) {
		return &report.Report{
			System:   report.System{Name: "whatever", Kind: "homeassistant", OS: "Home Assistant OS", OSVersion: "18.4", Kernel: "from the source", Source: "connector"},
			Software: []report.Software{{Name: "Home Assistant Core", Kind: "core", Installed: "2026.11.2"}},
		}, nil
	}}
	inContainer := fake{"host", func(_ context.Context, r *report.Report) error {
		r.System.Kind, r.System.OS, r.System.OSVersion, r.System.Kernel, r.System.Arch = "linux", "Alpine Linux v3.22", "3.22.1", "6.12.47-haos", "arm64"
		return nil
	}}
	tests := []struct {
		name string
		self bool
		want report.System
	}{
		{name: "on the appliance", self: true,
			want: report.System{Name: "testbox", Kind: "homeassistant", OS: "Home Assistant OS", OSVersion: "18.4", Kernel: "6.12.47-haos", Arch: "arm64", Source: "agent"}},
		{name: "on a machine next to it", self: false,
			want: report.System{Name: "testbox", Kind: "linux", OS: "Alpine Linux v3.22", OSVersion: "3.22.1", Kernel: "6.12.47-haos", Arch: "arm64", Source: "agent"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testAgent(&logs{}, inContainer, local("homeassistant", ha, nil, tt.self)).build(t.Context())
			if r.System != tt.want {
				t.Errorf("system: got %+v, want %+v", r.System, tt.want)
			}
			if len(r.Software) != 1 || problems(r) != "" {
				t.Errorf("software %d, problems %q", len(r.Software), problems(r))
			}
		})
	}
}

var _ connect.Source = source{}
