package agent

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/valicm/upkeep/internal/configtest"
)

// deploy/agent.toml is what an owner copies to a machine. It has to load as it is, every
// setting it shows has to exist, and it has to show every setting there is.
func TestDeployExample(t *testing.T) {
	const path = "../../deploy/agent.toml"
	cfg, err := LoadConfig(path, true, func(string) string { return "" })
	if err != nil {
		t.Fatalf("the example does not load as it is: %v", err)
	}
	if _, err := cfg.endpoint(); err != nil {
		t.Errorf("the example as it is cannot send: %v", err)
	}
	if cfg.HomeAssistant != nil || cfg.OPNsense != nil || len(cfg.Backups.Restic)+len(cfg.Backups.File)+len(cfg.Backups.Systemd) != 0 {
		t.Errorf("the example as it is switches on more than the basics: %+v", cfg)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	all := configtest.Uncomment(string(raw))
	var full Config
	if err := toml.NewDecoder(strings.NewReader(all)).DisallowUnknownFields().Decode(&full); err != nil {
		t.Fatalf("with every setting switched on: %s", tomlError(err))
	}
	doc, err := configtest.Document(all)
	if err != nil {
		t.Fatal(err)
	}
	if missing := configtest.Missing(doc, reflect.TypeFor[Config]()); len(missing) > 0 {
		t.Errorf("the example does not show these settings: %s", strings.Join(missing, ", "))
	}
	if full.OPNsense == nil || full.OPNsense.CheckEvery != "12h" || full.HomeAssistant == nil || len(full.Backups.Restic) != 1 || full.Interval.String() != "15m0s" {
		t.Errorf("the settings did not arrive where they belong: %+v", full)
	}
}

// The example for a firewall loads as it is and asks what it says it asks.
func TestDeployExampleForOPNsense(t *testing.T) {
	cfg, err := LoadConfig("../../deploy/opnsense/agent.toml", true, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	off := func(b *bool) bool { return b != nil && !*b }
	if !off(cfg.Packages.Enabled) || !off(cfg.Containers.Enabled) || !off(cfg.Backups.Enabled) {
		t.Errorf("packages, containers and backups are not all switched off: %+v", cfg)
	}
	if cfg.OPNsense == nil || cfg.OPNsense.KeyFile == "" || !cfg.OPNsense.TLSSkipVerify || cfg.OPNsense.Check {
		t.Errorf("the [opnsense] table: %+v", cfg.OPNsense)
	}
	for _, c := range collectors(cfg, "opnsense") {
		if n, ok := c.(named); ok {
			if f, broken := n.Collector.(failing); broken {
				t.Errorf("the [%s] table does not work: %v", n.name, f.err)
			}
		}
	}
}
