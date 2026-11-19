package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// secret is the token in these tests. No error and no log line may ever contain it.
const secret = "tok_3f9c1e77a2b84d06"

func tokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSend(t *testing.T) {
	var got struct {
		method, path, auth, contentType, agent string
		report                                 report.Report
		valid                                  error
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path = r.Method, r.URL.Path
		got.auth, got.contentType, got.agent = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header.Get("User-Agent")
		got.valid = json.NewDecoder(r.Body).Decode(&got.report)
		if got.valid == nil {
			got.valid = got.report.Validate()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := Config{Server: srv.URL + "/", TokenFile: tokenFile(t, secret+"\n")}
	endpoint, err := cfg.endpoint()
	if err != nil {
		t.Fatal(err)
	}
	l := &logs{}
	a := testAgent(l, fake{"ospkg", func(_ context.Context, r *report.Report) error {
		r.Packages = &report.Packages{Manager: "apt", Pending: 12, Security: 3, RebootRequired: true}
		return nil
	}})
	a.send = newSender(endpoint, cfg.TokenFile).send
	if err := a.report(t.Context(), onceTries, time.Time{}); err != nil {
		t.Fatal(err)
	}

	if got.method != "POST" || got.path != "/api/v1/report" {
		t.Errorf("request %s %s", got.method, got.path)
	}
	if got.auth != "Bearer "+secret {
		t.Errorf("Authorization %q", got.auth)
	}
	if got.contentType != "application/json" || !strings.HasPrefix(got.agent, "upkeep-agent/") {
		t.Errorf("Content-Type %q, User-Agent %q", got.contentType, got.agent)
	}
	if got.valid != nil {
		t.Errorf("the server could not use the report: %v", got.valid)
	}
	if r := got.report; r.System.Name != "testbox" || r.Packages == nil || r.Packages.Pending != 12 || r.Sent.IsZero() {
		t.Errorf("report as the server read it: %+v", r)
	}
	if want := "report sent: 12 package updates (3 security), reboot required"; !strings.Contains(l.String(), want) {
		t.Errorf("log %q, want %q", l.String(), want)
	}
	if strings.Contains(l.String(), secret) {
		t.Errorf("the token is in the log: %s", l.String())
	}
}

func TestSendAnswers(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		header  [2]string
		ok      bool
		refused bool // sending again is pointless
		want    string
	}{
		{name: "200", status: 200, ok: true},
		{name: "202", status: 202, ok: true},
		{name: "wrong token", status: 401, body: "unknown token\n", refused: true, want: "the server answered 401 Unauthorized: unknown token"},
		{name: "report not accepted", status: 400, body: `{"error":"system name is missing or not usable"}`, refused: true, want: `400 Bad Request: {"error":"system name is missing or not usable"}`},
		{name: "wrong address", status: 404, body: "404 page not found\n", refused: true, want: "404 Not Found"},
		{
			// A redirect is not followed: its target would be asked with GET and answer 200.
			name: "redirect", status: 301, header: [2]string{"Location", "https://upkeep.example.net/api/v1/report"}, refused: true,
			want: "301 Moved Permanently and points to https://upkeep.example.net/api/v1/report",
		},
		{name: "server broken", status: 500, body: "database is locked", want: "500 Internal Server Error: database is locked"},
		{name: "proxy without a server behind it", status: 502, body: "<html>\n<head><title>502 Bad Gateway</title></head>\n</html>", want: "502 Bad Gateway: <html> <head><title>502 Bad Gateway</title></head> </html>"},
		{name: "server busy", status: 429, want: "429 Too Many Requests"},
		{name: "a long answer is cut", status: 500, body: strings.Repeat("x", 5000), want: strings.Repeat("x", 200) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("the agent asked with %s", r.Method)
				}
				if tt.header[0] != "" {
					w.Header().Set(tt.header[0], tt.header[1])
				}
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			err := newSender(srv.URL+"/api/v1/report", tokenFile(t, secret)).send(t.Context(), []byte(`{}`))
			if tt.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var no *refused
			if err == nil || errors.As(err, &no) != tt.refused || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %v (refused %v), want one with %q (refused %v)", err, errors.As(err, &no), tt.want, tt.refused)
			}
			if err != nil && (strings.Contains(err.Error(), secret) || len(err.Error()) > 600) {
				t.Errorf("bad error: %v", err)
			}
		})
	}
}

func TestSendTokenFile(t *testing.T) {
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked++ }))
	defer srv.Close()

	tests := []struct {
		name    string
		content *string // nil: the file does not exist
		want    string
	}{
		{name: "missing", want: "read the token file"},
		{name: "empty", content: new(string), want: "is empty"},
		{name: "two lines", content: ptr(secret + "\nsecond-line\n"), want: "must hold a single token on one line"},
		{name: "not a token", content: ptr("tok\x00" + secret), want: "must hold a single token on one line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if tt.content != nil {
				path = tokenFile(t, *tt.content)
			}
			err := newSender(srv.URL, path).send(t.Context(), []byte(`{}`))
			var no *refused
			if !errors.As(err, &no) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %v, want a refusal with %q", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Errorf("the error shows the token: %v", err)
			}
		})
	}
	if asked != 0 {
		t.Errorf("the server was asked %d times without a usable token", asked)
	}
}

func ptr(s string) *string { return &s }

// A new token only needs a new file: it is read for every attempt.
func TestSendReadsTheTokenEveryTime(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
	}))
	defer srv.Close()
	path := tokenFile(t, "first")
	s := newSender(srv.URL, path)
	if err := s.send(t.Context(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.send(t.Context(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "Bearer first,Bearer second" {
		t.Errorf("got %q", seen)
	}
}

func TestSendServerAway(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens there any more

	err := newSender(url+"/api/v1/report", tokenFile(t, secret)).send(t.Context(), []byte(`{}`))
	var no *refused
	if err == nil || errors.As(err, &no) {
		t.Fatalf("a server that is away must be worth another try: %v", err)
	}
	if !strings.Contains(err.Error(), "send the report") || strings.Contains(err.Error(), secret) {
		t.Errorf("error: %v", err)
	}
}

// clock is a time that only moves when the agent sleeps.
type clock struct {
	t      time.Time
	sleeps []time.Duration
}

func (c *clock) now() time.Time { return c.t }
func (c *clock) sleep(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	c.sleeps = append(c.sleeps, d)
	c.t = c.t.Add(d)
	return true
}

func secs(ds []time.Duration) []int {
	out := make([]int, len(ds))
	for i, d := range ds {
		out[i] = int(d / time.Second)
	}
	return out
}

func TestDeliver(t *testing.T) {
	away := errors.New("send the report: connection refused")
	tests := []struct {
		name     string
		answers  []error // one per attempt; the last repeats
		tries    int
		deadline time.Duration // after the start; 0 for none
		attempts int
		sleeps   []int // seconds
		wantErr  string
	}{
		{name: "taken at once", answers: []error{nil}, attempts: 1},
		{name: "server back after a while", answers: []error{away, away, away, nil}, attempts: 4, sleeps: []int{5, 10, 20}},
		{
			name: "the wait doubles up to five minutes", answers: []error{away, away, away, away, away, away, away, away, away, nil},
			attempts: 10, sleeps: []int{5, 10, 20, 40, 80, 160, 300, 300, 300},
		},
		{name: "refused: no second attempt", answers: []error{&refused{"the server answered 401 Unauthorized"}}, attempts: 1, wantErr: "401 Unauthorized"},
		{name: "-once gives up after three attempts", answers: []error{away}, tries: onceTries, attempts: 3, sleeps: []int{5, 10}, wantErr: "gave up after 3 attempts"},
		{
			// 15 minutes until the next report: 5+10+20+40+80+160+300 = 615 s fit, 300 more do not.
			name: "gives up when the next report is due", answers: []error{away}, deadline: 15 * time.Minute,
			attempts: 8, sleeps: []int{5, 10, 20, 40, 80, 160, 300}, wantErr: "the next report is due",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &clock{t: time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)}
			l := &logs{}
			a := testAgent(l)
			a.now, a.sleep = c.now, c.sleep
			attempts := 0
			a.send = func(context.Context, []byte) error {
				err := tt.answers[min(attempts, len(tt.answers)-1)]
				attempts++
				return err
			}
			var deadline time.Time
			if tt.deadline > 0 {
				deadline = c.t.Add(tt.deadline)
			}
			err := a.deliver(t.Context(), []byte(`{}`), tt.tries, deadline)
			if (tt.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("error %v, want %q", err, tt.wantErr)
			}
			if attempts != tt.attempts {
				t.Errorf("%d attempts, want %d", attempts, tt.attempts)
			}
			if got := secs(c.sleeps); len(got) != len(tt.sleeps) || (len(got) > 0 && !equal(got, tt.sleeps)) {
				t.Errorf("waited %v s, want %v s", got, tt.sleeps)
			}
		})
	}
}

func equal(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDeliverStopsWithTheAgent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	a := testAgent(&logs{})
	attempts := 0
	a.send = func(context.Context, []byte) error {
		attempts++
		cancel() // SIGTERM arrives while the server is away
		return errors.New("send the report: connection refused")
	}
	if err := a.deliver(ctx, []byte(`{}`), 0, time.Time{}); err == nil || attempts != 1 {
		t.Errorf("error %v after %d attempts", err, attempts)
	}
}

func TestJitter(t *testing.T) {
	lo, hi := time.Hour, time.Duration(0)
	for i := 0; i < 2000; i++ {
		d := jitter(15 * time.Minute)
		lo, hi = min(lo, d), max(hi, d)
	}
	if lo < 13*time.Minute+30*time.Second || hi > 16*time.Minute+30*time.Second || hi-lo < time.Minute {
		t.Errorf("15m became %s to %s: want a tenth either way", lo, hi)
	}
}

func TestSleep(t *testing.T) {
	if !sleep(t.Context(), time.Millisecond) || !sleep(t.Context(), -time.Second) {
		t.Error("a full wait must say true")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	if sleep(ctx, time.Minute) || sleep(ctx, 0) || time.Since(start) > 5*time.Second {
		t.Error("a wait that the agent's stop cut short must say false, at once")
	}
}
