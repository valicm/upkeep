package backup

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// systemctlTimeout is generous for a question to the local service manager.
const systemctlTimeout = 15 * time.Second

// shown are the properties of a service that tell how its latest run went.
const shown = "Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus," +
	"ExecMainStartTimestamp,ExecMainExitTimestamp,InactiveExitTimestamp,SuccessExitStatus"

// How a unit's main command ended, as ExecMainCode says it (CLD_EXITED and so on in signal.h).
const (
	mainExited = 1
	mainKilled = 2
	mainDumped = 3
)

// unit is what "systemctl show" says about a service.
type unit struct {
	load        string       // "loaded", "not-found", "masked"
	active      string       // "inactive", "activating", "active", "failed", ...
	sub         string       // "dead", "start-pre", "start", "running", "exited", ...
	result      string       // "success", "exit-code", "signal", "timeout", "oom-kill", ...
	started     time.Time    // when it last left "inactive": the start of its latest run
	mainStart   time.Time    // start and end of that run's main command;
	mainExit    time.Time    // systemd clears both, and the next two, at every start
	mainCode    int          // 0 when the main command has not ended
	mainStatus  int          // its exit status, or the signal that ended it
	alsoSuccess map[int]bool // exit statuses the unit counts as success
}

// serviceName completes a unit name the way systemctl does and refuses what cannot be watched.
func serviceName(name string) (service, problem string) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return name, "it has no unit"
	case strings.ContainsAny(name, "/ \t\n") || strings.HasPrefix(name, "-"):
		return name, "its unit is not a unit name"
	case strings.HasSuffix(name, ".service"):
		return name, ""
	}
	for _, kind := range []string{".timer", ".socket", ".target", ".path", ".mount", ".automount", ".swap", ".slice", ".scope", ".device"} {
		if strings.HasSuffix(name, kind) {
			return name, "its unit must be the service that does the backup, not the " + kind[1:] + " around it"
		}
	}
	return name + ".service", ""
}

// showUnit asks systemd about a service. TZ makes systemctl print times in UTC: its usual
// form names the time zone by an abbreviation ("CET") that cannot be read back reliably.
func (c *collector) showUnit(ctx context.Context, name string) (unit, error) {
	env := append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	out, err := c.run(ctx, systemctlTimeout, env, "systemctl", "show", "--no-pager", "--property="+shown, "--", name)
	if err != nil {
		return unit{}, fmt.Errorf("asking systemd about %s: %w", name, err)
	}
	if out.exit != 0 {
		return unit{}, fmt.Errorf("asking systemd about %s: systemctl ended with status %d: %s", name, out.exit, lastLine(out.stderr))
	}
	u, err := parseUnit(string(out.stdout))
	if err != nil {
		return unit{}, fmt.Errorf("asking systemd about %s: %w", name, err)
	}
	return u, nil
}

func parseUnit(out string) (unit, error) {
	var u unit
	for line := range strings.Lines(out) {
		key, value, _ := strings.Cut(strings.TrimRight(line, "\r\n"), "=")
		var err error
		switch key {
		case "LoadState":
			u.load = value
		case "ActiveState":
			u.active = value
		case "SubState":
			u.sub = value
		case "Result":
			u.result = value
		case "InactiveExitTimestamp":
			u.started, err = systemdTime(value)
		case "ExecMainStartTimestamp":
			u.mainStart, err = systemdTime(value)
		case "ExecMainExitTimestamp":
			u.mainExit, err = systemdTime(value)
		case "ExecMainCode":
			u.mainCode, err = strconv.Atoi(value)
		case "ExecMainStatus":
			u.mainStatus, err = strconv.Atoi(value)
		case "SuccessExitStatus":
			// "3 USR1": exit statuses and signals. Only the statuses matter here: a backup
			// that a signal ended did not finish, whatever the unit calls it.
			for _, f := range strings.Fields(value) {
				if n, err := strconv.Atoi(f); err == nil {
					if u.alsoSuccess == nil {
						u.alsoSuccess = map[int]bool{}
					}
					u.alsoSuccess[n] = true
				}
			}
		}
		if err != nil {
			return unit{}, fmt.Errorf("reading %s: %w", key, err)
		}
	}
	if u.load == "" || u.active == "" {
		return unit{}, fmt.Errorf("systemctl did not say what state the unit is in")
	}
	return u, nil
}

// systemdTime reads a time as systemctl prints it under TZ=UTC: "Wed 2026-11-18 23:19:02 UTC".
// A time that was never set is empty.
func systemdTime(s string) (time.Time, error) {
	if s == "" || s == "n/a" {
		return time.Time{}, nil
	}
	// Go would accept any abbreviation and silently take it for UTC.
	if !strings.HasSuffix(s, " UTC") {
		return time.Time{}, fmt.Errorf("time %q is not in UTC", s)
	}
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("time %q is not in the form systemctl prints", s)
	}
	return t.UTC(), nil
}

// verdict is how a unit's latest run went.
type verdict struct {
	result  string    // "ok", "failed", "running"; empty when systemd remembers no run
	started time.Time // when that run began
	detail  string
}

func (u unit) verdict() verdict {
	switch u.active {
	case "failed":
		return verdict{result: "failed", started: u.started, detail: u.failure()}
	case "inactive":
	case "active":
		// A oneshot with RemainAfterExit= stays "active (exited)" when it is done. Any other
		// active service is still at work.
		if u.sub != "exited" {
			return verdict{result: "running", started: u.started}
		}
	default:
		// "activating" is a oneshot at work, in its main command or a step before it.
		return verdict{result: "running", started: u.started}
	}
	switch {
	case u.started.IsZero():
		return verdict{} // not run since the machine started
	case !u.succeeded():
		return verdict{result: "failed", started: u.started, detail: u.failure()}
	}
	v := verdict{result: "ok", started: u.started}
	if took := u.mainExit.Sub(u.mainStart); !u.mainStart.IsZero() && took >= 0 {
		v.detail = "took " + took.String()
	}
	return v
}

// succeeded reports whether the latest run finished well. "Result=success" alone does not say
// so: "systemctl reset-failed" puts it back on a unit that failed, and a unit that was stopped
// by hand has it too. The main command must have run and ended with a status that counts.
func (u unit) succeeded() bool {
	return u.result == "success" && u.mainCode == mainExited && (u.mainStatus == 0 || u.alsoSuccess[u.mainStatus])
}

// failure says in a few words why a run counts as failed: "exit-code 3", "timeout".
func (u unit) failure() string {
	var how string // how the main command ended, when it ran and ended badly
	switch {
	case u.mainCode == mainExited && u.mainStatus != 0 && !u.alsoSuccess[u.mainStatus]:
		how = fmt.Sprintf("exit-code %d", u.mainStatus)
	case u.mainCode == mainKilled || u.mainCode == mainDumped:
		how = "signal " + signalName(u.mainStatus)
	}
	switch u.result {
	case "exit-code", "signal":
		if how != "" {
			return how
		}
		// The unit's own word is all there is when a step before the main command failed.
		return u.result + " in a step before the main command"
	case "core-dump":
		if how != "" {
			return "core-dump, " + how
		}
	case "success":
		if how != "" {
			return how
		}
		return "ended before the main command ran"
	}
	return u.result // "timeout", "oom-kill", "start-limit-hit", ...
}

// signalName adds the name to the signals a backup is likely to meet. Their numbers are the
// same on every architecture Linux runs on.
func signalName(n int) string {
	names := map[int]string{1: "HUP", 2: "INT", 6: "ABRT", 9: "KILL", 11: "SEGV", 13: "PIPE", 15: "TERM"}
	if name, ok := names[n]; ok {
		return fmt.Sprintf("%d (%s)", n, name)
	}
	return strconv.Itoa(n)
}

// judge reports the backup a service runs from what systemd says about the service. known is
// what was remembered of it; the second result is what to remember from now on.
//
// LastRun and LastSuccess are when a run began, as a restic snapshot's time is: the backup
// holds the data as it was then.
func judge(j SystemdJob, u unit, known jobState) (report.Backup, jobState) {
	b := report.Backup{Name: j.Name, Kind: "systemd", MaxAgeHours: j.MaxAgeHours}
	switch seen := u.verdict(); seen.result {
	case "ok":
		known = jobState{LastSuccess: seen.started, LastRun: seen.started, LastResult: "ok", Detail: seen.detail}
	case "failed":
		// systemd has forgotten the run before this one. The memory has not.
		known.LastRun, known.LastResult, known.Detail = seen.started, "failed", seen.detail
	case "running":
		// Not remembered: the run has no result yet.
		b.LastSuccess, b.LastRun, b.LastResult = known.LastSuccess, seen.started, "running"
		return b, known
	default:
		if known.LastResult == "" {
			b.LastResult, b.Detail = "unknown", "no run since the machine started, and none seen before that"
			return b, known
		}
		// A restart of the machine wiped systemd's record; what was seen before still holds.
	}
	b.LastSuccess, b.LastRun, b.LastResult, b.Detail = known.LastSuccess, known.LastRun, known.LastResult, known.Detail
	return b, known
}

// unasked reports a backup whose unit systemd did not tell about: what is remembered of it, so
// that it stays on the dashboard, and why the rest is not known.
func unasked(j SystemdJob, known jobState, why string) report.Backup {
	return report.Backup{
		Name: j.Name, Kind: "systemd", MaxAgeHours: j.MaxAgeHours,
		LastSuccess: known.LastSuccess, LastRun: known.LastRun, LastResult: "unknown",
		Detail: why,
	}
}

// lastLine is the last thing a command said, which is where its error is.
func lastLine(text []byte) string {
	lines := strings.Split(strings.TrimSpace(string(text)), "\n")
	return clip(strings.TrimSpace(lines[len(lines)-1]), 200)
}

// clip keeps a message from outside to one short line.
func clip(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	for i := range s {
		if i >= max {
			return s[:i] + "..."
		}
	}
	return s
}
