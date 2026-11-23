package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/valicm/upkeep/internal/collect/backup"
	"github.com/valicm/upkeep/internal/collect/containers"
	"github.com/valicm/upkeep/internal/collect/network"
	"github.com/valicm/upkeep/internal/collect/ospkg"
	"github.com/valicm/upkeep/internal/connect/homeassistant"
	"github.com/valicm/upkeep/internal/connect/opnsense"
)

// DefaultConfigPath is where the agent looks for its configuration unless -config says otherwise.
const DefaultConfigPath = "/etc/upkeep/agent.toml"

const (
	defaultInterval = 15 * time.Minute
	defaultTimeout  = 3 * time.Minute
	// minInterval keeps a typo ("15s" for "15m") from running apt every few seconds.
	minInterval = time.Minute
)

// Config is the agent's configuration file. Each collector owns its own table, by its own
// type, so its owner can add settings without this package changing.
type Config struct {
	Server    string   `toml:"server"`     // the upkeep server, "https://upkeep.example.net"
	TokenFile string   `toml:"token_file"` // a file holding the token this machine reports with
	Name      string   `toml:"name"`       // this system's name on the dashboard; the host name when empty
	Interval  Duration `toml:"interval"`   // time between two reports, "15m"
	Timeout   Duration `toml:"timeout"`    // how long one collector may take, "3m"

	// These four always run unless their table says enabled = false.
	Packages   ospkg.Config      `toml:"packages"`
	Containers containers.Config `toml:"containers"`
	Backups    backup.Config     `toml:"backups"`
	Network    network.Config    `toml:"network"`
	// Sources the server would otherwise ask over the network, for a machine that can reach
	// them better itself. Each only runs when its table is there.
	HomeAssistant *homeassistant.Config `toml:"homeassistant"`
	OPNsense      *opnsense.Config      `toml:"opnsense"`
}

// Duration is a time.Duration that a configuration file writes as "15m" or "1h30m". It is a
// struct so that a bare number is an error instead of that many nanoseconds.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(text)))
	if err != nil {
		return fmt.Errorf("%q is not a duration like \"15m\" or \"1h30m\"", text)
	}
	d.Duration = v
	return nil
}

// LoadConfig reads the file at path, then lets the environment override the basics, then
// fills in defaults. A missing file is only an error when the user named it (explicit): an
// agent can be set up by environment alone, and "-print" needs no setup at all.
func LoadConfig(path string, explicit bool, getenv func(string) string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	switch {
	case err == nil:
		defer f.Close()
		// Unknown keys are errors: a misspelled setting must not be silently ignored.
		if err := toml.NewDecoder(f).DisallowUnknownFields().Decode(&cfg); err != nil {
			return cfg, fmt.Errorf("read the configuration %s: %s", path, tomlError(err))
		}
	case errors.Is(err, fs.ErrNotExist) && !explicit:
		// Defaults and the environment are all there is.
	default:
		return cfg, fmt.Errorf("read the configuration: %w", err)
	}

	if v := getenv("UPKEEP_SERVER"); v != "" {
		cfg.Server = v
	}
	if v := getenv("UPKEEP_TOKEN_FILE"); v != "" {
		cfg.TokenFile = v
	}
	if v := getenv("UPKEEP_NAME"); v != "" {
		cfg.Name = v
	}
	if v := getenv("UPKEEP_INTERVAL"); v != "" {
		if err := cfg.Interval.UnmarshalText([]byte(v)); err != nil {
			return cfg, fmt.Errorf("UPKEEP_INTERVAL: %w", err)
		}
	}

	if cfg.Interval.Duration == 0 {
		cfg.Interval.Duration = defaultInterval
	}
	if cfg.Timeout.Duration == 0 {
		cfg.Timeout.Duration = defaultTimeout
	}
	return cfg, cfg.check()
}

// tomlError adds the line and the key to what the decoder says, where it knows them.
func tomlError(err error) string {
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		var keys []string
		for _, e := range strict.Errors {
			line, _ := e.Position()
			keys = append(keys, fmt.Sprintf("%s (line %d)", strings.Join(e.Key(), "."), line))
		}
		return "unknown setting " + strings.Join(keys, ", ")
	}
	var decode *toml.DecodeError
	if errors.As(err, &decode) {
		line, _ := decode.Position()
		return fmt.Sprintf("line %d: %s", line, decode.Error())
	}
	return err.Error()
}

// check finds what is wrong whatever the agent is asked to do.
func (c *Config) check() error {
	if c.Interval.Duration < minInterval {
		return fmt.Errorf("interval %s is too short: the least is %s", c.Interval, minInterval)
	}
	if c.Timeout.Duration <= 0 {
		return fmt.Errorf("timeout %s must be more than nothing", c.Timeout)
	}
	return nil
}

// endpoint returns the URL reports go to. It is only needed, and only checked, when the
// agent is going to send.
func (c *Config) endpoint() (string, error) {
	if c.Server == "" {
		return "", errors.New("no server to report to: set \"server\" in the configuration or UPKEEP_SERVER")
	}
	u, err := url.Parse(c.Server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("server must be a URL like https://upkeep.example.net, not %q", redact(c.Server))
	}
	if u.User != nil {
		return "", errors.New("server must not carry a user or password: the token file is what the agent logs in with")
	}
	if c.TokenFile == "" {
		return "", errors.New("no token to report with: set \"token_file\" in the configuration or UPKEEP_TOKEN_FILE")
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/report"
	return u.String(), nil
}

// redact shows a URL without a password somebody may have put in it.
func redact(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Redacted()
	}
	if i := strings.Index(raw, "@"); i >= 0 {
		return "..." + raw[i:]
	}
	return raw
}
