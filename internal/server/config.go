package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/valicm/upkeep/internal/connect/homeassistant"
	"github.com/valicm/upkeep/internal/connect/opnsense"
	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/notify"
)

// DefaultConfigPath is where "upkeep server" looks for its configuration.
const DefaultConfigPath = "/etc/upkeep/server.toml"

// Config is the server's configuration file. Secrets are never in it: it names the files
// that hold them, so the file itself can be kept in a repository.
type Config struct {
	Listen  string `toml:"listen"`   // "127.0.0.1:8484" unless set; agents on other machines need more than loopback
	DataDir string `toml:"data_dir"` // where the database lives; "/var/lib/upkeep" unless set

	// TokenFile holds the token agents send with a report. A system named in Tokens has a
	// token of its own instead and can only report under that name.
	TokenFile string            `toml:"token_file"`
	Tokens    map[string]string `toml:"tokens"` // system name = token file

	RegistryInterval  Duration `toml:"registry_interval"`  // how often registries are asked about one image; "6h" unless set
	ConnectorInterval Duration `toml:"connector_interval"` // how often appliances are polled; "15m" unless set

	Dashboard     DashboardConfig        `toml:"dashboard"`
	Policy        PolicyConfig           `toml:"policy"`
	Mail          notify.Config          `toml:"mail"`
	OPNsense      []opnsense.Config      `toml:"opnsense"`
	HomeAssistant []homeassistant.Config `toml:"homeassistant"`

	// What Load read from the files above. Only hashes are kept, so nothing that prints a
	// Config can print a secret.
	agentToken        *secretHash
	systemTokens      map[string]secretHash
	dashboardPassword *secretHash
}

// DashboardConfig is the optional [dashboard] table: a password for the pages. Without it
// the dashboard is open to whoever can reach the port.
type DashboardConfig struct {
	User         string `toml:"user"`
	PasswordFile string `toml:"password_file"`
}

// PolicyConfig is the optional [policy] table: the thresholds of model.Policy.
type PolicyConfig struct {
	SilentAfter   Duration `toml:"silent_after"`    // "2h" unless set
	BackupMaxAge  Duration `toml:"backup_max_age"`  // "26h" unless set
	RebootWarnAge Duration `toml:"reboot_warn_age"` // "3d" unless set
}

// Duration is a time span in the configuration: "15m", "6h", "90s", or whole days as "3d".
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 || n > 3650 {
			return fmt.Errorf("%q is not a time span like \"15m\", \"6h\" or \"3d\"", s)
		}
		*d = Duration(time.Duration(n) * 24 * time.Hour)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return fmt.Errorf("%q is not a time span like \"15m\", \"6h\" or \"3d\"", s)
	}
	*d = Duration(v)
	return nil
}

// secretHash is the SHA-256 of a secret. Comparing hashes in constant time hides the
// secret's length as well as its content.
type secretHash [sha256.Size]byte

func hashSecret(s string) secretHash { return sha256.Sum256([]byte(s)) }

func (h *secretHash) matches(candidate string) bool {
	if h == nil {
		return false
	}
	sum := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(h[:], sum[:]) == 1
}

// minTokenLength refuses a token that could be guessed. "openssl rand -hex 32" gives 64.
const minTokenLength = 16

// Load reads and checks the configuration file and the secret files it names.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading the configuration: %w", err)
	}
	defer f.Close()
	var cfg Config
	// A misspelled key must not silently fall back to a default.
	if err := toml.NewDecoder(f).DisallowUnknownFields().Decode(&cfg); err != nil {
		var strict *toml.StrictMissingError
		var syntax *toml.DecodeError
		// The key and its line, never the line itself: whoever typed a secret into this file
		// by mistake must not find it in the journal as well.
		switch {
		case errors.As(err, &strict):
			var keys []string
			for _, e := range strict.Errors {
				line, _ := e.Position()
				keys = append(keys, fmt.Sprintf("%s (line %d)", strings.Join(e.Key(), "."), line))
			}
			return nil, fmt.Errorf("configuration %s has keys upkeep does not know: %s", path, strings.Join(keys, ", "))
		case errors.As(err, &syntax):
			line, _ := syntax.Position()
			return nil, fmt.Errorf("configuration %s, line %d: %s", path, line, syntax.Error())
		}
		return nil, fmt.Errorf("configuration %s: %w", path, err)
	}
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("configuration %s: %w", path, err)
	}
	if err := cfg.readSecrets(); err != nil {
		return nil, fmt.Errorf("configuration %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) setDefaults() {
	def := model.DefaultPolicy()
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8484"
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/upkeep"
	}
	if c.RegistryInterval == 0 {
		c.RegistryInterval = Duration(6 * time.Hour)
	}
	if c.ConnectorInterval == 0 {
		c.ConnectorInterval = Duration(15 * time.Minute)
	}
	// Zero is "not set", never "off": the dashboard reads it the same way, and the mail must
	// say what the dashboard shows.
	if c.Policy.SilentAfter == 0 {
		c.Policy.SilentAfter = Duration(def.SilentAfter)
	}
	if c.Policy.BackupMaxAge == 0 {
		c.Policy.BackupMaxAge = Duration(def.BackupMaxAge)
	}
	if c.Policy.RebootWarnAge == 0 {
		c.Policy.RebootWarnAge = Duration(def.RebootWarnAge)
	}
}

func (c *Config) validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen must be host:port, like \"0.0.0.0:8484\": %w", err)
	}
	// Registries limit how often they may be asked; an appliance's API is one's own.
	if time.Duration(c.RegistryInterval) < 10*time.Minute {
		return errors.New("registry_interval must be at least 10m")
	}
	if time.Duration(c.ConnectorInterval) < time.Minute {
		return errors.New("connector_interval must be at least 1m")
	}
	if (c.Dashboard.User == "") != (c.Dashboard.PasswordFile == "") {
		return errors.New("[dashboard] needs both user and password_file, or neither")
	}
	if strings.Contains(c.Dashboard.User, ":") {
		return errors.New("[dashboard] user must not contain a colon") // basic auth cannot carry one
	}
	for name, file := range c.Tokens {
		if strings.TrimSpace(name) != name || name == "" || file == "" {
			return fmt.Errorf("[tokens] %q: a system name and its token file are needed", name)
		}
	}
	if err := c.Mail.Validate(); err != nil {
		return fmt.Errorf("[mail] %w", err)
	}
	seen := map[string]string{}
	for _, name := range c.connectorNames() {
		switch {
		case name.name == "":
			return fmt.Errorf("[[%s]] needs a name", name.table)
		case seen[name.name] != "":
			return fmt.Errorf("the name %q is used by two connectors ([[%s]] and [[%s]])", name.name, seen[name.name], name.table)
		case c.Tokens[name.name] != "":
			return fmt.Errorf("%q is polled by [[%s]] and cannot have an agent's token as well", name.name, name.table)
		}
		seen[name.name] = name.table
	}
	return nil
}

type connectorName struct{ table, name string }

func (c *Config) connectorNames() []connectorName {
	var out []connectorName
	for _, o := range c.OPNsense {
		out = append(out, connectorName{"opnsense", o.Name})
	}
	for _, h := range c.HomeAssistant {
		out = append(out, connectorName{"homeassistant", h.Name})
	}
	return out
}

// readSecrets reads the token and password files. Errors name the file, never its content.
func (c *Config) readSecrets() error {
	byHash := map[secretHash]string{} // whose token it is, to catch one token given to two
	if c.TokenFile != "" {
		token, err := readSecret(c.TokenFile, minTokenLength)
		if err != nil {
			return fmt.Errorf("token_file: %w", err)
		}
		h := hashSecret(token)
		c.agentToken = &h
		byHash[h] = "token_file"
	}
	names := make([]string, 0, len(c.Tokens))
	for name := range c.Tokens {
		names = append(names, name)
	}
	sort.Strings(names) // so that the same mistake gives the same error every time
	c.systemTokens = map[string]secretHash{}
	for _, name := range names {
		token, err := readSecret(c.Tokens[name], minTokenLength)
		if err != nil {
			return fmt.Errorf("[tokens] %s: %w", name, err)
		}
		h := hashSecret(token)
		if other, dup := byHash[h]; dup {
			// The token is all that says who is reporting: it cannot belong to two.
			return fmt.Errorf("[tokens] %s has the same token as %s", name, other)
		}
		byHash[h] = "[tokens] " + name
		c.systemTokens[name] = h
	}
	if c.Dashboard.PasswordFile != "" {
		password, err := readSecret(c.Dashboard.PasswordFile, 1)
		if err != nil {
			return fmt.Errorf("[dashboard] password_file: %w", err)
		}
		h := hashSecret(password)
		c.dashboardPassword = &h
	}
	return nil
}

// readSecret returns the content of a secret file without the line end an editor leaves.
func readSecret(path string, minLength int) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(raw))
	switch {
	case secret == "":
		return "", fmt.Errorf("%s is empty", path)
	case len(secret) < minLength:
		return "", fmt.Errorf("%s holds fewer than %d characters, which is too easy to guess", path, minLength)
	case strings.ContainsAny(secret, "\r\n"):
		return "", fmt.Errorf("%s holds more than one line", path)
	}
	return secret, nil
}

// policy is the configured thresholds as the rest of upkeep wants them.
func (c *Config) policy() model.Policy {
	return model.Policy{
		SilentAfter:   time.Duration(c.Policy.SilentAfter),
		BackupMaxAge:  time.Duration(c.Policy.BackupMaxAge),
		RebootWarnAge: time.Duration(c.Policy.RebootWarnAge),
	}
}

// connectors builds the sources of the [[opnsense]] and [[homeassistant]] tables.
func (c *Config) connectors() ([]Connector, error) {
	var out []Connector
	for _, o := range c.OPNsense {
		src, err := opnsense.New(o)
		if err != nil {
			return nil, err // it names the kind and the system itself
		}
		out = append(out, Connector{Source: src, Kind: "opnsense"})
	}
	for _, h := range c.HomeAssistant {
		src, err := homeassistant.New(h)
		if err != nil {
			return nil, err
		}
		out = append(out, Connector{Source: src, Kind: "homeassistant"})
	}
	return out, nil
}
