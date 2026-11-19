package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// quiet switches off the collectors that would look at the machine the tests run on. The
// host collector stays: it only reads a few files.
const quiet = `
[packages]
enabled = false
[containers]
enabled = false
[backups]
enabled = false
`

func configFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// receiver is a server that takes reports and hands them to the test.
func receiver(t *testing.T, status int) (*httptest.Server, chan report.Report) {
	t.Helper()
	got := make(chan report.Report, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep report.Report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			t.Errorf("the server got something that is not a report: %v", err)
		}
		if r.Header.Get("Authorization") != "Bearer "+secret || r.URL.Path != "/api/v1/report" {
			t.Errorf("request %s with Authorization %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.WriteHeader(status)
		got <- rep
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestPrint(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Neither a server nor a token: -print must work on a machine nobody has set up.
	err := run(t.Context(), []string{"-print", "-config", configFile(t, quiet)}, env("UPKEEP_NAME", "pi"), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("stdout is not a report: %v\n%s", err, stdout.String())
	}
	if err := r.Validate(); err != nil {
		t.Errorf("not a valid report: %v", err)
	}
	if r.System.Name != "pi" || r.System.Source != "agent" || r.System.Kind == "" || r.System.AgentVersion == "" || r.Sent.IsZero() {
		t.Errorf("%+v", r)
	}
	if !strings.Contains(stdout.String(), "\n  \"system\": {") {
		t.Errorf("the report is not indented for reading:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr: %s", stderr.String())
	}
}

func TestPrintSendsNothing(t *testing.T) {
	srv, got := receiver(t, http.StatusOK)
	var stdout, stderr bytes.Buffer
	cfg := configFile(t, "server = \""+srv.URL+"\"\ntoken_file = \""+tokenFile(t, secret)+"\"\n"+quiet)
	if err := run(t.Context(), []string{"-print", "-once", "-config", cfg}, env(), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Error("-print sent a report")
	}
}

func TestOnce(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		token   string
		wantErr string
		wantLog string
	}{
		{name: "delivered", status: http.StatusOK, token: secret, wantLog: "report sent: nothing to say"},
		{name: "refused", status: http.StatusUnauthorized, token: secret, wantErr: "401 Unauthorized"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, got := receiver(t, tt.status)
			cfg := configFile(t, "server = \""+srv.URL+"\"\nname = \"once-box\"\ntoken_file = \""+tokenFile(t, tt.token)+"\"\n"+quiet)
			var stdout, stderr bytes.Buffer
			err := run(t.Context(), []string{"-once", "-config", cfg}, env(), &stdout, &stderr)
			if (tt.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error %v, want %q", err, tt.wantErr)
			}
			if r := <-got; r.System.Name != "once-box" {
				t.Errorf("the server got %+v", r.System)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), tt.wantLog) {
				t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), secret) || (err != nil && strings.Contains(err.Error(), secret)) {
				t.Error("the token leaked")
			}
			// systemd adds the time itself: a line must start with what it says.
			if tt.wantLog != "" && !strings.HasPrefix(stderr.String(), tt.wantLog) {
				t.Errorf("log line %q", stderr.String())
			}
		})
	}
}

func TestRunRefusesBadSetups(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		config  string
		env     func(string) string
		wantErr string
	}{
		{name: "no server", args: []string{"-once"}, config: quiet, env: env(), wantErr: "no server to report to"},
		{name: "no token file", args: []string{"-once"}, config: "server = \"https://upkeep.example.net\"\n" + quiet, env: env(), wantErr: "no token to report with"},
		{name: "unknown flag", args: []string{"-fast"}, config: quiet, env: env(), wantErr: "flag provided but not defined"},
		{name: "stray argument", args: []string{"-once", "now"}, config: quiet, env: env(), wantErr: `unexpected argument "now"`},
		{name: "broken configuration", args: []string{"-print"}, config: "interval = 15\n", env: env(), wantErr: "read the configuration"},
		{name: "a name the server would refuse", args: []string{"-print"}, config: quiet, env: env("UPKEEP_NAME", "rack/3"), wantErr: `cannot report as "rack/3"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"-config", configFile(t, tt.config)}, tt.args...)
			err := run(t.Context(), args, tt.env, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %v, want one with %q", err, tt.wantErr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout: %s", stdout.String())
			}
		})
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"-h"}, env(), &stdout, &stderr); err != nil {
		t.Error(err)
	}
	for _, flag := range []string{"-config", "-once", "-print"} {
		if !strings.Contains(stderr.String(), flag) {
			t.Errorf("the help does not mention %s:\n%s", flag, stderr.String())
		}
	}
}

// The loop on a clock that only moves when the agent sleeps: a server that is away for the
// first report, back for the second.
func TestLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	c := &clock{t: time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)}
	l := &logs{}
	a := testAgent(l)
	a.now, a.sleep = c.now, c.sleep

	var sent []time.Time  // when a report was taken
	var built []time.Time // the Sent time inside each one
	a.send = func(_ context.Context, body []byte) error {
		var r report.Report
		if err := json.Unmarshal(body, &r); err != nil {
			t.Errorf("body: %v", err)
		}
		if c.t.Before(time.Date(2026, 11, 19, 8, 15, 0, 0, time.UTC)) {
			return errors.New("send the report: connection refused")
		}
		sent, built = append(sent, c.t), append(built, r.Sent)
		if len(sent) == 3 {
			cancel()
		}
		return nil
	}
	a.loop(ctx)

	at := func(h, m int) time.Time { return time.Date(2026, 11, 19, h, m, 0, 0, time.UTC) }
	// 08:00 fails until the next report is due; 08:15, 08:30 and 08:45 are taken at once.
	want := []time.Time{at(8, 15), at(8, 30), at(8, 45)}
	if len(sent) != 3 || !sent[0].Equal(want[0]) || !sent[1].Equal(want[1]) || !sent[2].Equal(want[2]) {
		t.Errorf("reports taken at %v, want %v", sent, want)
	}
	// What is sent at 08:15 is a new report, not the one from 08:00 again.
	if len(built) > 0 && !built[0].Equal(at(8, 15)) {
		t.Errorf("the first report taken was built at %s", built[0])
	}
	if !strings.Contains(l.String(), "report not delivered") || !strings.Contains(l.String(), "the next report is due") {
		t.Errorf("log:\n%s", l.String())
	}
}

// The real thing: Main, a real signal, a real (local) server.
func TestMainStopsOnSIGTERM(t *testing.T) {
	for _, k := range []string{"UPKEEP_SERVER", "UPKEEP_TOKEN_FILE", "UPKEEP_NAME", "UPKEEP_INTERVAL"} {
		t.Setenv(k, "") // Main reads the real environment
	}
	srv, got := receiver(t, http.StatusOK)
	cfg := configFile(t, "server = \""+srv.URL+"\"\nname = \"daemon-box\"\ninterval = \"1h\"\ntoken_file = \""+tokenFile(t, secret)+"\"\n"+quiet)

	done := make(chan error, 1)
	go func() { done <- Main([]string{"-config", cfg}) }()

	select {
	case r := <-got: // the first report comes at once, not after an interval
		if r.System.Name != "daemon-box" {
			t.Errorf("the server got %+v", r.System)
		}
	case err := <-done:
		t.Fatalf("the agent ended by itself: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("no report within 30s")
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a stop on SIGTERM must be clean, got: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent did not stop within 10s of SIGTERM")
	}
}

func TestSystemName(t *testing.T) {
	if got, err := systemName("  opnsense02 "); err != nil || got != "opnsense02" {
		t.Errorf("configured: %q, %v", got, err)
	}
	got, err := systemName("")
	if err != nil || got == "" || strings.Contains(got, ".") {
		t.Errorf("from the host name: %q, %v", got, err)
	}
}

func TestSummary(t *testing.T) {
	tests := []struct {
		r    report.Report
		want string
	}{
		{report.Report{}, "nothing to say"},
		{report.Report{Packages: &report.Packages{}}, "0 package updates"},
		{
			report.Report{
				Packages:   &report.Packages{Pending: 12, Security: 3, RebootRequired: true},
				Containers: make([]report.Container, 9), Backups: make([]report.Backup, 1), Software: make([]report.Software, 2), Errors: make([]report.Problem, 1),
			},
			"12 package updates (3 security), reboot required, 9 containers, 1 backup, 2 software items, 1 problem",
		},
	}
	for _, tt := range tests {
		if got := summary(&tt.r); got != tt.want {
			t.Errorf("got %q, want %q", got, tt.want)
		}
	}
}
