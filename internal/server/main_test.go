package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/store"
)

// logBuffer collects what the server logs while a test talks to it.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// running is a server started by a test, on a port of its own on this machine.
type running struct {
	url  string
	log  *logBuffer
	stop func() error // what SIGTERM does; returns what run returned
}

func start(t *testing.T, args ...string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{log: &logBuffer{}}
	addr := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, append(args, "-listen", "127.0.0.1:0"), surroundings{
			stderr: r.log, listening: func(a net.Addr) { addr <- a }, registry: noRegistry{},
		})
	}()
	var once sync.Once
	var result error
	r.stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case result = <-done:
			case <-time.After(30 * time.Second):
				result = fmt.Errorf("the server did not stop; its log:\n%s", r.log)
			}
		})
		return result
	}
	t.Cleanup(func() { r.stop() })
	select {
	case a := <-addr:
		r.url = "http://" + a.String()
	case err := <-done:
		t.Fatalf("the server did not start: %v\n%s", err, r.log)
	case <-time.After(30 * time.Second):
		t.Fatalf("the server did not start in time:\n%s", r.log)
	}
	return r
}

// noRegistry stands where the real registries would be: a test must not ask the internet.
type noRegistry struct{}

func (noRegistry) Check(_ context.Context, image string) model.ImageCheck {
	return model.ImageCheck{Image: image, Error: "tests do not ask registries"}
}

func (r *running) do(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, r.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRunDemo(t *testing.T) {
	srv := start(t, "-demo")
	tests := []struct {
		name, method, path, token string
		status                    int
		says                      string
	}{
		{"the supervisor's question", "GET", "/healthz", "", 200, "ok"},
		{"the dashboard, without a password", "GET", "/", "", 200, "<html"},
		{"a report: the demo has no token to accept", "POST", "/api/v1/report", sharedToken, 401, "token"},
		{"the state: the same", "GET", "/api/v1/state", sharedToken, 401, "token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := srv.do(t, tt.method, tt.path, tt.token, reportNamed("server"))
			if status != tt.status || !strings.Contains(body, tt.says) {
				t.Errorf("%s %s = %d, want %d with %q in it; got:\n%.300s", tt.method, tt.path, status, tt.status, tt.says, body)
			}
		})
	}
	if err := srv.stop(); err != nil {
		t.Errorf("stopping: %v", err)
	}
	if log := srv.log.String(); !strings.Contains(log, "listening") || !strings.Contains(log, "stopping") {
		t.Errorf("the log does not tell the story:\n%s", log)
	}
}

// A whole life: start from a configuration, take a report, serve it, stop on the signal,
// and find the report in the database afterwards.
func TestRunServer(t *testing.T) {
	config := writeConfig(t, `
data_dir = "/var/lib/upkeep"
token_file = "/etc/upkeep/token"

[tokens]
pi = "/etc/upkeep/tokens/pi"

[dashboard]
user = "valentino"
password_file = "/etc/upkeep/dashboard-password"
`)
	dataDir := filepath.Join(filepath.Dir(config), "data")
	srv := start(t, "-config", config)

	steps := []struct {
		name, method, path, token, body string
		status                          int
		says                            string
	}{
		{"healthy", "GET", "/healthz", "", "", 200, "ok"},
		{"the dashboard wants its password", "GET", "/", "", "", 401, "password"},
		{"a report without a token", "POST", "/api/v1/report", "", reportFixture(t), 401, "token"},
		{"a report", "POST", "/api/v1/report", sharedToken, reportFixture(t), 200, `"system":"server"`},
		{"pi's report with pi's token", "POST", "/api/v1/report", piToken, reportNamed("pi"), 200, `"system":"pi"`},
		{"pi's token for another name", "POST", "/api/v1/report", piToken, reportNamed("server"), 403, "may only report pi"},
		{"the state shows both", "GET", "/api/v1/state", sharedToken, "", 200, `"reboot required"`},
	}
	for _, st := range steps {
		status, body := srv.do(t, st.method, st.path, st.token, st.body)
		if status != st.status || !strings.Contains(body, st.says) {
			t.Fatalf("%s: %s %s = %d, want %d with %q in it; got:\n%.400s", st.name, st.method, st.path, status, st.status, st.says, body)
		}
	}
	// With the password the real dashboard answers, and it knows the systems.
	req, _ := http.NewRequestWithContext(t.Context(), "GET", srv.url+"/", nil)
	req.SetBasicAuth("valentino", dashPass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(page), "server") {
		t.Errorf("the dashboard with its password: %d\n%.300s", resp.StatusCode, page)
	}

	if err := srv.stop(); err != nil {
		t.Fatalf("stopping: %v", err)
	}
	for _, secret := range []string{sharedToken, piToken, dashPass} {
		if strings.Contains(srv.log.String(), secret) {
			t.Errorf("the log contains a secret:\n%s", srv.log)
		}
	}

	st, err := store.OpenSQLite(t.Context(), filepath.Join(dataDir, "upkeep.db"))
	if err != nil {
		t.Fatalf("the database after the server stopped: %v", err)
	}
	defer st.Close()
	systems, err := st.Systems(t.Context())
	if err != nil || len(systems) != 2 || systems[1].Report.System.Name != "server" || len(systems[1].Report.Containers) != 9 {
		t.Errorf("the database holds %d systems, %v; want pi and server as reported", len(systems), err)
	}
}

func TestRunRefuses(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"a flag nobody knows", []string{"-daemon"}, "flag provided but not defined"},
		{"an argument that is not a flag", []string{"-demo", "now"}, `unexpected argument "now"`},
		{"a configuration that is not there", []string{"-config", filepath.Join(t.TempDir(), "server.toml")}, "reading the configuration"},
		{"a configuration with a mistake", []string{"-config", writeConfig(t, "listen = 8484\n")}, "server.toml"},
		{"a port that is taken", []string{"-demo", "-listen", taken.Addr().String()}, "listening on " + taken.Addr().String()},
		{"a connector that lacks what it needs", []string{"-config", writeConfig(t, "[[opnsense]]\nname = \"fw\"\nurl = \"https://fw.example.net\"\n")}, "opnsense fw"},
		{"a data directory that cannot be made", []string{"-config", writeConfig(t, "data_dir = \"/etc/upkeep/token/sub\"\n")}, "data directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			var log logBuffer
			err := run(ctx, tt.args, surroundings{stderr: &log, registry: noRegistry{}})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want one that says %q", err, tt.want)
			}
			if ctx.Err() != nil {
				t.Error("the server ran until the test stopped it")
			}
		})
	}
	t.Run("asking for help is not an error", func(t *testing.T) {
		var log logBuffer
		if err := run(t.Context(), []string{"-h"}, surroundings{stderr: &log}); err != nil {
			t.Errorf("err = %v", err)
		}
		for _, flag := range []string{"-config", "-demo", "-listen"} {
			if !strings.Contains(log.String(), flag) {
				t.Errorf("the help does not name %s:\n%s", flag, &log)
			}
		}
	})
}
