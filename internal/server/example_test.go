package server

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/valicm/upkeep/internal/configtest"
)

// deploy/server.toml is what an owner copies to the server. It has to be a valid
// configuration as it is, every setting it shows has to exist, and it has to show every
// setting there is.
func TestDeployExample(t *testing.T) {
	const path = "../../deploy/server.toml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(text string) *Config {
		t.Helper()
		var cfg Config
		if err := toml.NewDecoder(strings.NewReader(text)).DisallowUnknownFields().Decode(&cfg); err != nil {
			var strict *toml.StrictMissingError
			if ok := asStrict(err, &strict); ok {
				t.Fatalf("unknown settings:\n%s", strict.String())
			}
			t.Fatal(err)
		}
		cfg.setDefaults()
		if err := cfg.validate(); err != nil {
			t.Fatalf("not a valid configuration: %v", err)
		}
		return &cfg
	}

	// As it is: reachable by agents, with a token, and nothing else switched on.
	plain := decode(string(raw))
	if plain.Listen != "0.0.0.0:8484" || plain.TokenFile == "" || plain.DataDir != "/var/lib/upkeep" {
		t.Errorf("the example as it is: %+v", plain)
	}
	if plain.Mail.Enabled() || len(plain.OPNsense)+len(plain.HomeAssistant)+len(plain.Tokens) != 0 || plain.Dashboard.User != "" {
		t.Errorf("the example as it is switches on more than the basics: %+v", plain)
	}

	// With everything switched on.
	all := configtest.Uncomment(string(raw))
	full := decode(all)
	doc, err := configtest.Document(all)
	if err != nil {
		t.Fatal(err)
	}
	if missing := configtest.Missing(doc, reflect.TypeFor[Config]()); len(missing) > 0 {
		t.Errorf("the example does not show these settings: %s", strings.Join(missing, ", "))
	}
	if time.Duration(full.Policy.RebootWarnAge) != 72*time.Hour || !full.Mail.Enabled() || len(full.OPNsense) != 1 || full.OPNsense[0].Timezone == "" {
		t.Errorf("the settings did not arrive where they belong: %+v", full)
	}
	// The connectors can be built from what the example shows, apart from the one setting
	// that is only for an agent inside Home Assistant, and the certificate files, which are
	// read at once and are not on this machine.
	full.HomeAssistant[0].Supervisor = false
	full.HomeAssistant[0].CAFile, full.OPNsense[0].CAFile = "", ""
	if _, err := full.connectors(); err != nil {
		t.Errorf("the example's appliances cannot be set up: %v", err)
	}
}

func asStrict(err error, target **toml.StrictMissingError) bool {
	s, ok := err.(*toml.StrictMissingError)
	if ok {
		*target = s
	}
	return ok
}
