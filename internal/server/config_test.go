package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
)

const (
	sharedToken = "5f2c8a1e9b7d4c3a6e0f1b2d3c4a5e6f" // what "openssl rand -hex 16" gives
	piToken     = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	backupToken = "ffeeddccbbaa99887766554433221100"
	dashPass    = "tajna lozinka"
)

// writeConfig puts a configuration into a temporary directory. "/etc/upkeep" in it becomes
// that directory, and the secret files the example names are created there.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"token":              sharedToken + "\n",
		"tokens/backup-pi":   backupToken + "\n",
		"tokens/pi":          "  " + piToken + "\r\n",
		"dashboard-password": dashPass + "\n",
		"short":              "hunter2\n",
		"empty":              "\n",
		"two-lines":          sharedToken + "\n" + piToken + "\n",
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "server.toml")
	content = strings.ReplaceAll(content, "/etc/upkeep", dir)
	content = strings.ReplaceAll(content, "/var/lib/upkeep", filepath.Join(dir, "data"))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The example in testdata is what a person copies: it must load, and mean what it says.
func TestLoadExample(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("testdata", "server.toml"))
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, string(example))
	dir := filepath.Dir(path)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		what      string
		got, want any
	}{
		{"listen", cfg.Listen, "0.0.0.0:8484"},
		{"data_dir", cfg.DataDir, filepath.Join(dir, "data")},
		{"registry_interval", time.Duration(cfg.RegistryInterval), 6 * time.Hour},
		{"connector_interval", time.Duration(cfg.ConnectorInterval), 15 * time.Minute},
		{"policy", cfg.policy(), model.Policy{SilentAfter: 2 * time.Hour, BackupMaxAge: 26 * time.Hour, RebootWarnAge: 72 * time.Hour}},
		{"dashboard user", cfg.Dashboard.User, "valentino"},
		{"mail smtp", cfg.Mail.SMTP, "192.0.2.25:1025"},
		{"mail from", cfg.Mail.From, "Upkeep <upkeep@example.net>"},
		{"mail to", fmt.Sprint(cfg.Mail.To), "[owner@example.net]"},
		{"mail url", cfg.Mail.URL, "https://upkeep.example.net/"},
		{"mail schedule", cfg.Mail.Schedule, "daily 07:00"},
		{"opnsense tables", len(cfg.OPNsense), 2},
		{"opnsense name", cfg.OPNsense[1].Name, "opnsense02"},
		{"opnsense url", cfg.OPNsense[1].URL, "https://opnsense02.example.net"},
		{"homeassistant tables", len(cfg.HomeAssistant), 1},
		{"homeassistant name", cfg.HomeAssistant[0].Name, "homeassistant"},
		{"connector names", fmt.Sprint(cfg.connectorNames()), "[{opnsense opnsense01} {opnsense opnsense02} {homeassistant homeassistant}]"},
		{"shared token read", cfg.agentToken.matches(sharedToken), true},
		{"shared token is not another", cfg.agentToken.matches(piToken), false},
		{"system tokens", len(cfg.systemTokens), 2},
		{"dashboard password read", cfg.dashboardPassword.matches(dashPass), true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.what, c.got, c.want)
		}
	}
	// The tables become the sources the scheduler polls, each with its kind. Their key files
	// are read when they are first asked, not here.
	connectors, err := cfg.connectors()
	if err != nil {
		t.Fatal(err)
	}
	var polled []string
	for _, c := range connectors {
		polled = append(polled, c.Kind+" "+c.Source.Name())
	}
	if got := strings.Join(polled, ", "); got != "opnsense opnsense01, opnsense opnsense02, homeassistant homeassistant" {
		t.Errorf("connectors = %s", got)
	}
	// Spaces and line ends around a token are the editor's, not the token's.
	if h := cfg.systemTokens["pi.lan"]; !h.matches(piToken) {
		t.Error("the token of pi.lan was not read without its surrounding white space")
	}
	if h := cfg.systemTokens["backup-pi"]; !h.matches(backupToken) || h.matches(sharedToken) {
		t.Error("the token of backup-pi is not the one in its file")
	}
	// A configuration that is printed, by a log line or a panic, must not show a secret.
	printed := fmt.Sprintf("%+v %#v", *cfg, *cfg)
	for _, secret := range []string{sharedToken, piToken, backupToken, dashPass} {
		if strings.Contains(printed, secret) {
			t.Errorf("a printed configuration contains a secret")
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	def := model.DefaultPolicy()
	checks := []struct {
		what      string
		got, want any
	}{
		{"listen", cfg.Listen, "127.0.0.1:8484"},
		{"data_dir", cfg.DataDir, "/var/lib/upkeep"},
		{"registry_interval", time.Duration(cfg.RegistryInterval), 6 * time.Hour},
		{"connector_interval", time.Duration(cfg.ConnectorInterval), 15 * time.Minute},
		{"policy", cfg.policy(), def},
		{"mail", cfg.Mail.Enabled(), false},
		{"shared token", cfg.agentToken == nil, true},
		{"system tokens", len(cfg.systemTokens), 0},
		{"dashboard password", cfg.dashboardPassword == nil, true},
		{"connectors", len(cfg.connectorNames()), 0},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.what, c.got, c.want)
		}
	}
}

func TestLoadRefuses(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   []string // parts of the error
	}{
		{"a key upkeep does not know", "listn = \":8484\"\n", []string{"keys upkeep does not know", "listn (line 1)"}},
		{"a key of a table upkeep does not know", "[mail]\nsmtp = \"relay:25\"\nfrom = \"a@example.net\"\nto = [\"b@example.net\"]\nsmpt_user = \"x\"\n", []string{"smpt_user"}},
		{"what is not TOML", "listen = \n", []string{"server.toml, line 1"}},
		// Somebody typed the token into the file instead of naming its file. The error says
		// where, and does not repeat what was typed.
		{"a secret typed into the file under a key upkeep does not know", "listen = \":8484\"\ntoken = \"hunter2-hunter2-hunter2\"\n", []string{"token (line 2)"}},
		{"a secret typed into a line that is not TOML", "token_file = hunter2-hunter2\n", []string{"line 1"}},
		{"listen without a port", "listen = \"0.0.0.0\"\n", []string{"listen must be host:port"}},
		{"a time span nobody understands", "registry_interval = \"often\"\n", []string{"often", "time span"}},
		{"a negative time span", "connector_interval = \"-5m\"\n", []string{"time span"}},
		{"registries asked too often", "registry_interval = \"1m\"\n", []string{"registry_interval must be at least 10m"}},
		{"connectors polled too often", "connector_interval = \"10s\"\n", []string{"connector_interval must be at least 1m"}},
		{"a dashboard user without a password", "[dashboard]\nuser = \"valentino\"\n", []string{"[dashboard] needs both"}},
		{"a dashboard password without a user", "[dashboard]\npassword_file = \"/etc/upkeep/dashboard-password\"\n", []string{"[dashboard] needs both"}},
		{"a dashboard user with a colon", "[dashboard]\nuser = \"a:b\"\npassword_file = \"/etc/upkeep/dashboard-password\"\n", []string{"colon"}},
		{"a token file that is not there", "token_file = \"/etc/upkeep/nothing\"\n", []string{"token_file", "nothing"}},
		{"an empty token file", "token_file = \"/etc/upkeep/empty\"\n", []string{"token_file", "is empty"}},
		{"a token that is too short", "token_file = \"/etc/upkeep/short\"\n", []string{"token_file", "fewer than 16 characters"}},
		{"a token file with two tokens", "token_file = \"/etc/upkeep/two-lines\"\n", []string{"more than one line"}},
		{"a system token that is too short", "[tokens]\npi = \"/etc/upkeep/short\"\n", []string{"[tokens] pi", "fewer than 16"}},
		{"a system without a token file", "[tokens]\npi = \"\"\n", []string{"[tokens]", "pi"}},
		{"two systems with one token", "[tokens]\npi = \"/etc/upkeep/tokens/pi\"\nother = \"/etc/upkeep/tokens/pi\"\n", []string{"[tokens] pi has the same token as [tokens] other"}},
		{"a system with the shared token", "token_file = \"/etc/upkeep/token\"\n[tokens]\npi = \"/etc/upkeep/token\"\n", []string{"[tokens] pi has the same token as token_file"}},
		{"a dashboard password file that is not there", "[dashboard]\nuser = \"v\"\npassword_file = \"/etc/upkeep/nothing\"\n", []string{"[dashboard] password_file"}},
		{"mail without a recipient", "[mail]\nsmtp = \"relay:25\"\nfrom = \"a@example.net\"\n", []string{"[mail]", "to needs"}},
		{"a mail schedule nobody understands", "[mail]\nsmtp = \"relay:25\"\nfrom = \"a@example.net\"\nto = [\"b@example.net\"]\nschedule = \"hourly\"\n", []string{"[mail]", "schedule"}},
		{"a connector without a name", "[[opnsense]]\nurl = \"https://fw.example.net\"\n", []string{"[[opnsense]] needs a name"}},
		{"two connectors with one name", "[[opnsense]]\nname = \"fw\"\n[[homeassistant]]\nname = \"fw\"\n", []string{`"fw" is used by two connectors`}},
		{"a connector that also has an agent's token", "[tokens]\nfw = \"/etc/upkeep/tokens/pi\"\n[[opnsense]]\nname = \"fw\"\n", []string{`"fw" is polled by [[opnsense]]`}},
		{"a map name that is no URL", "[[map.names]]\nurl = \"photos.example.net\"\nsystem = \"server\"\n", []string{"[[map.names]] 1", "url must be like"}},
		{"a map name with a password in it", "[[map.names]]\nurl = \"https://u:p@photos.example.net/\"\nsystem = \"server\"\n", []string{"[[map.names]] 1", "user or password"}},
		{"a map name without a system", "[[map.names]]\nurl = \"https://photos.example.net/\"\n", []string{"system is missing"}},
		{"a map name with no port", "[[map.names]]\nurl = \"https://photos.example.net/\"\nsystem = \"server\"\nport = 70000\n", []string{"port 70000"}},
		{"a map ssh user that is not a user", "[map]\nssh_user = \"admin@server\"\n", []string{"[map] ssh_user"}},
		{"a map key upkeep does not know", "[map]\nssh_port = 22\n", []string{"ssh_port"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, tt.config))
			if err == nil {
				t.Fatalf("loaded: %+v", cfg)
			}
			for _, part := range tt.want {
				if !strings.Contains(err.Error(), part) {
					t.Errorf("error %q does not say %q", err, part)
				}
			}
			for _, secret := range []string{sharedToken, piToken, "hunter2"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error contains a secret: %q", err)
				}
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "server.toml")); err == nil || !strings.Contains(err.Error(), "reading the configuration") {
		t.Errorf("a configuration that is not there: %v", err)
	}
}

func TestDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		bad  bool
	}{
		{in: "15m", want: 15 * time.Minute},
		{in: "6h", want: 6 * time.Hour},
		{in: "1h30m", want: 90 * time.Minute},
		{in: "3d", want: 72 * time.Hour},
		{in: " 26h ", want: 26 * time.Hour},
		{in: "0", want: 0},
		{in: "", bad: true},
		{in: "6", bad: true},
		{in: "1.5d", bad: true},
		{in: "-2h", bad: true},
		{in: "-1d", bad: true},
		{in: "soon", bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalText([]byte(tt.in))
			if (err != nil) != tt.bad || time.Duration(d) != tt.want {
				t.Errorf("got %v, %v; want %v, an error: %v", time.Duration(d), err, tt.want, tt.bad)
			}
		})
	}
}

func TestSecretHash(t *testing.T) {
	h := hashSecret(sharedToken)
	var none *secretHash
	tests := []struct {
		name      string
		hash      *secretHash
		candidate string
		want      bool
	}{
		{"the secret", &h, sharedToken, true},
		{"another secret", &h, piToken, false},
		{"a prefix", &h, sharedToken[:10], false},
		{"nothing", &h, "", false},
		{"no secret configured, nothing sent", none, "", false},
		{"no secret configured, something sent", none, sharedToken, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hash.matches(tt.candidate); got != tt.want {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapView(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
[map]
ssh_user = "admin"
[[map.names]]
url = "https://photos.example.net/"
system = " server "
port = 2342
[[opnsense]]
name = "fw"
url = "https://fw.example.net:10000"
[[homeassistant]]
name = "ha"
url = "http://10.10.10.20:8123"
`))
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.mapView()
	if m.SSHUser != "admin" || len(m.Names) != 1 || m.Names[0].System != "server" || m.Names[0].Port != 2342 {
		t.Errorf("names: %+v", m)
	}
	if len(m.Appliances) != 2 || m.Appliances[0].Name != "fw" || m.Appliances[1].URL != "http://10.10.10.20:8123" {
		t.Errorf("appliances: %+v", m.Appliances)
	}
}
