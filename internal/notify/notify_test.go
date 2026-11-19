package notify

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // the schedule tests need Europe/Zagreb wherever they run

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata from what Render gives now")

var zagreb = mustLocation("Europe/Zagreb")

func mustLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return loc
}

func system(name string) model.SystemState {
	return model.SystemState{Report: report.Report{Schema: 1, System: report.System{Name: name, Source: "agent"}}}
}

// The findings are written the way model.Findings words them, about the homelab upkeep was
// written for; the golden files are what Render made of them and were read by a person.
func TestRenderGolden(t *testing.T) {
	now := time.Date(2026, 11, 19, 7, 0, 0, 0, zagreb)
	homelab := []model.SystemState{
		system("backup-pi"), system("homeassistant"), system("opnsense01"), system("opnsense02"),
		system("ops01"), system("pi"), system("server"),
	}
	tests := []struct {
		name     string // also the golden files' name
		cfg      Config
		states   []model.SystemState
		findings []model.Finding
		subject  string
	}{
		{
			name:   "findings",
			cfg:    Config{URL: "https://upkeep.example.net/"},
			states: homelab,
			findings: []model.Finding{
				{System: "backup-pi", Category: model.CategorySource, Severity: model.Crit, Title: "no report since 2026-11-18 22:10 UTC", Detail: "silent for 7 hours; the agent should report at least every 2 hours"},
				{System: "server", Category: model.CategoryBackup, Severity: model.Crit, Title: "backup restic-backup failed", Detail: "last run 2026-11-19 02:00 UTC; exit-code 3; last success 2026-11-18 02:14 UTC"},
				{System: "opnsense02", Category: model.CategorySource, Severity: model.Warn, Title: "connector failed", Detail: "asking for the firmware status: 401 Unauthorized"},
				{System: "server", Category: model.CategoryReboot, Severity: model.Warn, Title: "reboot required", Detail: "kernel 6.12.107 running, 6.12.117 installed"},
				{System: "server", Category: model.CategoryOS, Severity: model.Warn, Title: "12 package updates, 3 security", Detail: "security: openssl, libssl3t64, linux-image-amd64; also bash, curl, tzdata and 6 more"},
				{System: "homeassistant", Category: model.CategorySoftware, Severity: model.Info, Title: "Home Assistant Core 2026.11.3 available", Detail: "installed 2026.11.1"},
				{System: "homeassistant", Category: model.CategorySoftware, Severity: model.Info, Title: "Zigbee2MQTT update available"},
				{System: "server", Category: model.CategoryContainer, Severity: model.Info, Title: "gitea: 1.23.8 available", Detail: "patch update of docker.io/gitea/gitea:1.23.6; also 1.25.2 (minor), 2.0.1 (major)"},
			},
			subject: "upkeep: 2 critical, 3 warnings, 3 info",
		},
		{
			name:   "one-finding",
			cfg:    Config{URL: "https://upkeep.example.net/"},
			states: []model.SystemState{system("server")},
			findings: []model.Finding{
				{System: "server", Category: model.CategoryReboot, Severity: model.Warn, Title: "reboot required"},
			},
			subject: "upkeep: 1 warning",
		},
		{
			name:    "all-good",
			cfg:     Config{URL: "https://upkeep.example.net/"},
			states:  homelab,
			subject: "upkeep: nothing needs attention",
		},
		{
			name:    "no-systems",
			subject: "upkeep: nothing needs attention",
		},
		{
			// What reaches the mail comes from other machines. None of it may become markup,
			// and a link that is not a web address must not be clickable.
			name:   "hostile",
			cfg:    Config{URL: "javascript:alert(1)"},
			states: []model.SystemState{system(`<b>pi</b>`), system(`quiet & "calm"`)},
			findings: []model.Finding{
				{System: `<b>pi</b>`, Category: model.CategorySource, Severity: model.Warn, Title: `collector <script>alert(1)</script> failed`, Detail: `exit status 1: "a" < 'b' & c > d`},
			},
			subject: "upkeep: 1 warning",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, text, html := Render(tt.cfg, tt.states, tt.findings, now)
			if subject != tt.subject {
				t.Errorf("subject = %q, want %q", subject, tt.subject)
			}
			golden(t, tt.name+".txt", text)
			golden(t, tt.name+".html", html)
		})
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "digest-"+name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run the test with -update to write it)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from what Render gives now:\n%s", path, got)
	}
}

func TestRenderEscapes(t *testing.T) {
	_, _, html := Render(Config{URL: "javascript:alert(1)"},
		[]model.SystemState{system("<b>pi</b>")},
		[]model.Finding{{System: "<b>pi</b>", Severity: model.Warn, Title: "<script>alert(1)</script>", Detail: `<img src=x onerror="x">`}},
		time.Date(2026, 11, 19, 7, 0, 0, 0, time.UTC))
	for _, bad := range []string{"<script>", "<b>pi", "<img", `href="javascript:`} {
		if strings.Contains(html, bad) {
			t.Errorf("the HTML mail contains %q unescaped", bad)
		}
	}
}

func TestRenderUnknownSeverity(t *testing.T) {
	subject, text, _ := Render(Config{}, nil, []model.Finding{
		{System: "pi", Severity: model.Crit + 1, Title: "worse than critical"},
		{System: "pi", Severity: model.Info - 1, Title: "less than info"},
	}, time.Date(2026, 11, 19, 7, 0, 0, 0, time.UTC))
	if subject != "upkeep: 1 critical, 1 info" || !strings.Contains(text, "crit  worse than critical") || !strings.Contains(text, "info  less than info") {
		t.Errorf("subject %q, text:\n%s", subject, text)
	}
}

func TestFingerprint(t *testing.T) {
	base := []model.Finding{
		{System: "server", Category: model.CategoryOS, Severity: model.Warn, Title: "12 package updates, 3 security", Detail: "security: openssl"},
		{System: "pi", Category: model.CategoryReboot, Severity: model.Warn, Title: "reboot required"},
	}
	change := func(f func(fs []model.Finding) []model.Finding) []model.Finding {
		return f(append([]model.Finding(nil), base...))
	}
	tests := []struct {
		name  string
		other []model.Finding
		same  bool
	}{
		{"the same findings", base, true},
		{"in another order", change(func(fs []model.Finding) []model.Finding { fs[0], fs[1] = fs[1], fs[0]; return fs }), true},
		{"another detail, as when only time passed", change(func(fs []model.Finding) []model.Finding { fs[0].Detail = "5 hours ago"; return fs }), true},
		{"another title", change(func(fs []model.Finding) []model.Finding { fs[0].Title = "14 package updates, 3 security"; return fs }), false},
		{"another severity", change(func(fs []model.Finding) []model.Finding { fs[1].Severity = model.Crit; return fs }), false},
		{"another system", change(func(fs []model.Finding) []model.Finding { fs[1].System = "pi2"; return fs }), false},
		{"another category", change(func(fs []model.Finding) []model.Finding { fs[1].Category = model.CategoryOS; return fs }), false},
		{"one finding gone", base[:1], false},
		{"all gone", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Fingerprint(tt.other) == Fingerprint(base); got != tt.same {
				t.Errorf("same fingerprint = %v, want %v", got, tt.same)
			}
		})
	}
	if Fingerprint(nil) == "" || Fingerprint(nil) != Fingerprint([]model.Finding{}) {
		t.Error("no findings must have a fingerprint of their own: empty means never mailed")
	}
}

func TestParseSchedule(t *testing.T) {
	tests := []struct {
		in   string
		want Schedule
		bad  bool
	}{
		{in: "", want: Schedule{Hour: 7}},
		{in: "daily 07:00", want: Schedule{Hour: 7}},
		{in: "daily 7:05", want: Schedule{Hour: 7, Minute: 5}},
		{in: "  Daily   23:59 ", want: Schedule{Hour: 23, Minute: 59}},
		{in: "weekly mon 06:30", want: Schedule{Weekly: true, Day: time.Monday, Hour: 6, Minute: 30}},
		{in: "weekly Sunday 18:00", want: Schedule{Weekly: true, Day: time.Sunday, Hour: 18}},
		{in: "on change", want: Schedule{OnChange: true}},
		{in: "On  Change", want: Schedule{OnChange: true}},
		{in: "daily", bad: true},
		{in: "daily 24:00", bad: true},
		{in: "daily 07:60", bad: true},
		{in: "daily seven", bad: true},
		{in: "weekly 07:00", bad: true},
		{in: "weekly someday 07:00", bad: true},
		{in: "hourly", bad: true},
		{in: "on change 07:00", bad: true},
		{in: "0 7 * * *", bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseSchedule(tt.in)
			if (err != nil) != tt.bad {
				t.Fatalf("err = %v, want an error: %v", err, tt.bad)
			}
			if err != nil && !strings.Contains(err.Error(), "daily HH:MM") {
				t.Errorf("the error does not say what is allowed: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestScheduleLast(t *testing.T) {
	at := func(y int, m time.Month, d, h, min int) time.Time { return time.Date(y, m, d, h, min, 0, 0, zagreb) }
	tests := []struct {
		name     string
		schedule string
		now      time.Time
		want     time.Time
	}{
		{"daily, before today's time", "daily 07:00", at(2026, 11, 19, 6, 59), at(2026, 11, 18, 7, 0)},
		{"daily, at the minute", "daily 07:00", at(2026, 11, 19, 7, 0), at(2026, 11, 19, 7, 0)},
		{"daily, later that day", "daily 07:00", at(2026, 11, 19, 23, 30), at(2026, 11, 19, 7, 0)},
		{"daily, over the new year", "daily 07:00", at(2027, 1, 1, 0, 5), at(2026, 12, 31, 7, 0)},
		// 2026-11-19 is a Thursday.
		{"weekly, on the day after the time", "weekly thu 07:00", at(2026, 11, 19, 8, 0), at(2026, 11, 19, 7, 0)},
		{"weekly, on the day before the time", "weekly thu 07:00", at(2026, 11, 19, 6, 0), at(2026, 11, 12, 7, 0)},
		{"weekly, days later", "weekly mon 06:30", at(2026, 11, 19, 8, 0), at(2026, 11, 16, 6, 30)},
		{"weekly, the day before", "weekly fri 06:30", at(2026, 11, 19, 8, 0), at(2026, 11, 13, 6, 30)},
		// Clocks go back on 2026-10-25 and forward on 2027-03-28 in Zagreb: the day before is
		// 25 and 23 hours away, the digest still belongs to seven o'clock.
		{"daily, the morning after clocks went back", "daily 07:00", at(2026, 10, 25, 6, 0), at(2026, 10, 24, 7, 0)},
		{"daily, the morning after clocks went forward", "daily 07:00", at(2027, 3, 28, 6, 0), at(2027, 3, 27, 7, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := ParseSchedule(tt.schedule)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Last(tt.now); !got.Equal(tt.want) {
				t.Errorf("Last(%v) = %v, want %v", tt.now, got, tt.want)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{SMTP: "192.0.2.25:1025", From: "upkeep@example.net", To: []string{"owner@example.net"}}
	with := func(change func(*Config)) Config {
		c := good
		c.To = append([]string(nil), good.To...)
		change(&c)
		return c
	}
	tests := []struct {
		name string
		cfg  Config
		want string // part of the error; empty when the configuration is fine
	}{
		{"no mail wanted", Config{}, ""},
		{"a relay on the LAN", good, ""},
		{"names in addresses", with(func(c *Config) { c.From = "Upkeep <upkeep@example.net>"; c.To = []string{"Owner <owner@example.net>"} }), ""},
		{"a relay with a login", with(func(c *Config) { c.StartTLS, c.User, c.PasswordFile = true, "upkeep", "/etc/upkeep/smtp-password" }), ""},
		{"smtp without a port", with(func(c *Config) { c.SMTP = "192.0.2.25" }), "host:port"},
		{"no sender", with(func(c *Config) { c.From = "" }), "from"},
		{"a sender that is no address", with(func(c *Config) { c.From = "upkeep" }), "from"},
		{"nobody to send to", with(func(c *Config) { c.To = nil }), "to needs"},
		{"a recipient that is no address", with(func(c *Config) { c.To = append(c.To, "owner@") }), `to "owner@"`},
		{"a schedule nobody understands", with(func(c *Config) { c.Schedule = "hourly" }), "schedule"},
		{"a user without a password", with(func(c *Config) { c.StartTLS, c.User = true, "upkeep" }), "password_file"},
		{"a password without a user", with(func(c *Config) { c.StartTLS, c.PasswordFile = true, "/x" }), "needs user"},
		{"a login in the clear", with(func(c *Config) { c.User, c.PasswordFile = "upkeep", "/x" }), "starttls"},
		{"a CA without TLS", with(func(c *Config) { c.CAFile = "/x" }), "starttls"},
		{"a dashboard address", with(func(c *Config) { c.URL = "https://upkeep.example.net/" }), ""},
		{"a link that is no web address", with(func(c *Config) { c.URL = "javascript:alert(1)" }), "http"},
		{"a link without a host", with(func(c *Config) { c.URL = "upkeep.example.net" }), "http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("err = %v, want one that says %q", err, tt.want)
			}
		})
	}
}
