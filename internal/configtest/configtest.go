// Package configtest keeps the example configuration files under deploy/ true: the tests of
// the agent and of the server use it to prove that an example loads, that every setting it
// shows exists, and that it shows every setting there is.
package configtest

import (
	"encoding"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// off matches a setting that an example shows switched off: "#" directly followed by a key or
// a table. Prose has a space after the "#".
var off = regexp.MustCompile(`(?m)^#([A-Za-z_"\[])`)

// Uncomment returns an example with every setting it shows switched on.
func Uncomment(example string) string { return off.ReplaceAllString(example, "$1") }

// Document reads TOML into plain maps, as the file says it and not as a struct takes it.
func Document(text string) (map[string]any, error) {
	var doc map[string]any
	err := toml.Unmarshal([]byte(text), &doc)
	return doc, err
}

var textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()

// Missing lists the settings of a configuration struct that a document does not set, as
// paths like "backups.restic.env_file". A table that may come several times is checked by
// its first one; a map of free names only has to be there.
func Missing(doc map[string]any, config reflect.Type) []string {
	var out []string
	missing(doc, config, "", &out)
	sort.Strings(out)
	return out
}

func missing(doc map[string]any, t reflect.Type, prefix string, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	for i := range t.NumField() {
		f := t.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
		if key == "" || key == "-" || !f.IsExported() {
			continue
		}
		value, ok := doc[key]
		if !ok {
			*out = append(*out, prefix+key)
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct {
			if list, isList := value.([]any); isList && len(list) > 0 {
				value, ft = list[0], ft.Elem()
			}
		}
		if ft.Kind() != reflect.Struct || reflect.PointerTo(ft).Implements(textUnmarshaler) {
			continue // a plain value, or one written as text such as a duration
		}
		if table, isTable := value.(map[string]any); isTable {
			missing(table, ft, prefix+key+".", out)
		} else {
			*out = append(*out, prefix+key+" (not a table)")
		}
	}
}
