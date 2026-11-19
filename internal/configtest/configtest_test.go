package configtest

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

type span struct{ time.Duration }

func (s *span) UnmarshalText(b []byte) (err error) {
	s.Duration, err = time.ParseDuration(string(b))
	return err
}

type job struct {
	Name string `toml:"name"`
	Path string `toml:"path"`
}

type config struct {
	Server   string            `toml:"server"`
	Interval span              `toml:"interval"`
	Tokens   map[string]string `toml:"tokens"`
	Backups  struct {
		Enabled *bool `toml:"enabled"`
		File    []job `toml:"file"`
	} `toml:"backups"`
	Source *struct {
		URL string `toml:"url"`
	} `toml:"source"`
	hidden string
}

func TestUncommentAndMissing(t *testing.T) {
	example := `# An example. Prose keeps its "#".
server = "http://upkeep.example.net"
#interval = "15m"   # with a remark

#[tokens]
#"pi.lan" = "/etc/upkeep/pi"

[backups]
#enabled = true
#[[backups.file]]
#name = "config"

#[source]
# url is left out on purpose.
`
	all := Uncomment(example)
	if strings.Contains(all, "\n#interval") || !strings.Contains(all, "# An example.") || !strings.Contains(all, "\n[[backups.file]]\nname = ") {
		t.Fatalf("Uncomment:\n%s", all)
	}
	doc, err := Document(all)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(Missing(doc, reflect.TypeFor[config]()), ", ")
	if want := "backups.file.path, source.url"; got != want {
		t.Errorf("Missing = %q, want %q", got, want)
	}
	// As it is, most of it is switched off.
	doc, err = Document(example)
	if err != nil {
		t.Fatal(err)
	}
	got = strings.Join(Missing(doc, reflect.TypeFor[*config]()), ", ")
	if want := "backups.enabled, backups.file, interval, source, tokens"; got != want {
		t.Errorf("Missing = %q, want %q", got, want)
	}
}
