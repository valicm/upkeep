package agent

import (
	"github.com/valicm/upkeep/internal/connect/homeassistant"
	"strings"
	"testing"
	"time"
)

func env(pairs ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return func(k string) string { return m[k] }
}

// basics are the agent's own settings, the part of a Config that can be compared.
type basics struct {
	Server, TokenFile, Name string
	Interval, Timeout       Duration
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		explicit bool
		env      func(string) string
		want     basics
		wantErr  string
	}{
		{
			name: "the example file", path: "testdata/agent.toml", explicit: true, env: env(),
			want: basics{Server: "https://upkeep.example.net", TokenFile: "/etc/upkeep/token", Name: "server", Interval: Duration{15 * time.Minute}, Timeout: Duration{3 * time.Minute}},
		},
		{
			name: "defaults", path: "testdata/empty.toml", explicit: true, env: env(),
			want: basics{Interval: Duration{15 * time.Minute}, Timeout: Duration{3 * time.Minute}},
		},
		{
			name: "the environment wins over the file", path: "testdata/agent.toml", explicit: true,
			env:  env("UPKEEP_SERVER", "http://127.0.0.1:8080", "UPKEEP_TOKEN_FILE", "/run/secrets/upkeep", "UPKEEP_NAME", "pi", "UPKEEP_INTERVAL", "1h"),
			want: basics{Server: "http://127.0.0.1:8080", TokenFile: "/run/secrets/upkeep", Name: "pi", Interval: Duration{time.Hour}, Timeout: Duration{3 * time.Minute}},
		},
		{
			// No file at the default place: the environment alone is a complete setup.
			name: "no file, not asked for", path: "testdata/does-not-exist.toml", env: env("UPKEEP_SERVER", "https://u.example.net", "UPKEEP_TOKEN_FILE", "/t"),
			want: basics{Server: "https://u.example.net", TokenFile: "/t", Interval: Duration{15 * time.Minute}, Timeout: Duration{3 * time.Minute}},
		},
		{name: "no file, but -config named it", path: "testdata/does-not-exist.toml", explicit: true, env: env(), wantErr: "does-not-exist.toml"},
		{name: "a directory", path: "testdata", explicit: true, env: env(), wantErr: "read the configuration"},
		{name: "misspelled settings", path: "testdata/unknown-key.toml", explicit: true, env: env(), wantErr: "unknown setting intervall (line 2), packages.manger (line 5)"},
		{name: "not a duration", path: "testdata/bad-duration.toml", explicit: true, env: env(), wantErr: `"soon" is not a duration`},
		{name: "a number instead of a duration", path: "testdata/number-interval.toml", explicit: true, env: env(), wantErr: `"15" is not a duration`},
		{name: "not TOML", path: "testdata/bad-syntax.toml", explicit: true, env: env(), wantErr: "bad-syntax.toml: line 1"},
		{name: "interval too short", path: "testdata/short-interval.toml", explicit: true, env: env(), wantErr: "interval 15s is too short"},
		{name: "interval from the environment is checked too", path: "testdata/empty.toml", explicit: true, env: env("UPKEEP_INTERVAL", "often"), wantErr: "UPKEEP_INTERVAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadConfig(tt.path, tt.explicit, tt.env)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v, want one with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if b := (basics{got.Server, got.TokenFile, got.Name, got.Interval, got.Timeout}); b != tt.want {
				t.Errorf("got  %+v\nwant %+v", b, tt.want)
			}
		})
	}
}

// The tables of the collectors arrive in their own types.
func TestLoadConfigTables(t *testing.T) {
	cfg, err := LoadConfig("testdata/agent.toml", true, env())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Packages.Manager != "apt" || cfg.Packages.Enabled == nil || !*cfg.Packages.Enabled {
		t.Errorf("packages: %+v", cfg.Packages)
	}
	if cfg.Containers.Enabled == nil || *cfg.Containers.Enabled {
		t.Errorf("containers: %+v", cfg.Containers)
	}
	if cfg.HomeAssistant == nil || cfg.HomeAssistant.URL != "http://127.0.0.1:8123" {
		t.Errorf("homeassistant: %+v", cfg.HomeAssistant)
	}
	if cfg.OPNsense == nil || cfg.OPNsense.URL != "https://127.0.0.1" {
		t.Errorf("opnsense: %+v", cfg.OPNsense)
	}

	// Without their tables the local sources are off.
	cfg, err = LoadConfig("testdata/empty.toml", true, env())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HomeAssistant != nil || cfg.OPNsense != nil {
		t.Errorf("sources without tables: %+v %+v", cfg.HomeAssistant, cfg.OPNsense)
	}
}

func TestCollectorsFromConfig(t *testing.T) {
	names := func(cfg Config) string {
		var out []string
		for _, c := range collectors(cfg, "testbox") {
			out = append(out, c.Name())
		}
		return strings.Join(out, " ")
	}
	full, err := LoadConfig("testdata/agent.toml", true, env())
	if err != nil {
		t.Fatal(err)
	}
	// The local sources are named after their tables, whatever name their own table gives.
	if got, want := names(full), "host network ospkg containers backup homeassistant opnsense"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := names(Config{}), "host network ospkg containers backup"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// The example's tables are complete: none of its sources fails to be set up. They need no
	// name of their own, the agent's is theirs.
	for _, c := range collectors(full, "testbox") {
		if n, ok := c.(named); ok {
			if f, broken := n.Collector.(failing); broken {
				t.Errorf("the example's [%s] table does not work: %v", n.name, f.err)
			}
		}
	}
	// A table with a mistake still gives a collector, one that says what is wrong.
	broken := full
	broken.HomeAssistant = &homeassistant.Config{URL: "http://127.0.0.1:8123"}
	found := false
	for _, c := range collectors(broken, "testbox") {
		if n, ok := c.(named); ok && n.name == "homeassistant" {
			f, isFailing := n.Collector.(failing)
			found = isFailing && strings.Contains(f.err.Error(), "token_file is missing")
		}
	}
	if !found {
		t.Error("a [homeassistant] table without a token gives no failing collector")
	}
}

func TestEndpoint(t *testing.T) {
	tests := []struct {
		server  string
		token   string
		want    string
		wantErr string
	}{
		{server: "https://upkeep.example.net", token: "/t", want: "https://upkeep.example.net/api/v1/report"},
		{server: "https://upkeep.example.net/", token: "/t", want: "https://upkeep.example.net/api/v1/report"},
		{server: "http://127.0.0.1:8080", token: "/t", want: "http://127.0.0.1:8080/api/v1/report"},
		// Behind a reverse proxy that serves it under a path.
		{server: "https://ops.example.net/upkeep/", token: "/t", want: "https://ops.example.net/upkeep/api/v1/report"},
		{server: "https://upkeep.example.net?x=1#top", token: "/t", want: "https://upkeep.example.net/api/v1/report"},
		{server: "", token: "/t", wantErr: "no server to report to"},
		{server: "upkeep.example.net", token: "/t", wantErr: "server must be a URL"},
		{server: "ftp://upkeep.example.net", token: "/t", wantErr: "server must be a URL"},
		{server: "https://", token: "/t", wantErr: "server must be a URL"},
		{server: "https://me:hunter2@upkeep.example.net", token: "/t", wantErr: "must not carry a user or password"},
		{server: "https://upkeep.example.net", token: "", wantErr: "no token to report with"},
	}
	for _, tt := range tests {
		cfg := Config{Server: tt.server, TokenFile: tt.token}
		got, err := cfg.endpoint()
		switch {
		case tt.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("%q: error %v, want one with %q", tt.server, err, tt.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "hunter2") {
				t.Errorf("%q: the error shows the password: %v", tt.server, err)
			}
		case err != nil:
			t.Errorf("%q: %v", tt.server, err)
		case got != tt.want:
			t.Errorf("%q: got %q, want %q", tt.server, got, tt.want)
		}
	}
}

func TestRedact(t *testing.T) {
	for _, raw := range []string{"ftp://me:hunter2@example.net/x", "://me:hunter2@example.net"} {
		if got := redact(raw); strings.Contains(got, "hunter2") {
			t.Errorf("redact(%q) = %q", raw, got)
		}
	}
}

func TestPlainHTTP(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://upkeep.example.net/api/v1/report", false},
		{"http://upkeep.example.net/api/v1/report", true},
		{"http://192.0.2.10:8080/api/v1/report", true},
		{"http://127.0.0.1:8080/api/v1/report", false},
		{"http://[::1]:8080/api/v1/report", false},
		{"http://localhost:8080/api/v1/report", false},
	}
	for _, tt := range tests {
		if got := plainHTTP(tt.url); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.url, got, tt.want)
		}
	}
}
