package report

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := func(name string) *Report {
		return &Report{Schema: Schema, System: System{Name: name, Source: "agent"}}
	}
	tests := []struct {
		name  string
		r     *Report
		wrong string // part of the error; empty means the report is usable
	}{
		{name: "an agent's report", r: ok("server")},
		{name: "a connector's report", r: &Report{Schema: 1, System: System{Name: "opnsense02", Source: "connector"}}},
		{name: "a name with a dot and a dash", r: ok("pi-4.lan")},
		{name: "a name with spaces and letters beyond ASCII", r: ok("žaba 2")},
		{name: "a name of dots that is no path", r: ok("...")},
		{name: "no schema", r: &Report{System: System{Name: "server", Source: "agent"}}, wrong: "schema"},
		{name: "a schema from the future", r: &Report{Schema: Schema + 1, System: System{Name: "server", Source: "agent"}}, wrong: "schema"},
		{name: "no name", r: ok(""), wrong: "name"},
		{name: "only spaces", r: ok("   "), wrong: "name"},
		{name: "a slash", r: ok("a/b"), wrong: "name"},
		{name: "a backslash", r: ok(`a\b`), wrong: "name"},
		{name: "a line break", r: ok("a\nb"), wrong: "name"},
		{name: "a zero byte", r: ok("a\x00b"), wrong: "name"},
		{name: "too long", r: ok(strings.Repeat("x", 101)), wrong: "name"},
		// The name is part of an address on the dashboard: a browser never asks for these.
		{name: "one dot", r: ok("."), wrong: "name"},
		{name: "two dots", r: ok(".."), wrong: "name"},
		{name: "two dots with spaces around", r: ok(" .. "), wrong: "name"},
		{name: "no source", r: &Report{Schema: 1, System: System{Name: "server"}}, wrong: "source"},
		{name: "another source", r: &Report{Schema: 1, System: System{Name: "server", Source: "cron"}}, wrong: "source"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.r.Validate()
			switch {
			case tc.wrong == "" && err != nil:
				t.Errorf("Validate: %v, want no error", err)
			case tc.wrong != "" && (err == nil || !strings.Contains(err.Error(), tc.wrong)):
				t.Errorf("Validate: %v, want an error about the %s", err, tc.wrong)
			}
		})
	}
}
