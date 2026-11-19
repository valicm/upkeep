package backup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// resticTimeout bounds one look into a repository. restic retries a server that does not
// answer for many minutes; the agent's report must not wait that long.
const resticTimeout = 2 * time.Minute

// problem says what is wrong with the job as configured, or nothing.
func (j ResticJob) problem() string {
	switch {
	case j.Repository != "" && j.RepositoryFile != "":
		return "it has both repository and repository_file"
	case j.EnvFile != "":
		return ""
	case j.Repository == "" && j.RepositoryFile == "":
		return "it needs env_file, or repository_file (or repository) with password_file"
	case j.PasswordFile == "":
		return "it needs password_file (or env_file)"
	}
	return ""
}

// snapshot is one entry of "restic snapshots --json".
type snapshot struct {
	Time    time.Time `json:"time"` // when the backup began
	ShortID string    `json:"short_id"`
	Summary *struct {
		TotalBytesProcessed int64 `json:"total_bytes_processed"`
	} `json:"summary"` // restic 0.17 and later
}

// resticBackup reports a restic repository by its newest snapshot: restic writes a snapshot
// only when a backup ran to its end. known is what was remembered of the repository; the
// second result is what to remember from now on.
func (c *collector) resticBackup(ctx context.Context, j ResticJob, known jobState) (report.Backup, jobState, error) {
	b := report.Backup{Name: j.Name, Kind: "restic", MaxAgeHours: j.MaxAgeHours}
	snapshots, err := c.snapshots(ctx, j)
	if err != nil {
		// A repository that cannot be reached right now still has the backups it had.
		b.LastSuccess, b.LastRun, b.LastResult = known.LastSuccess, known.LastRun, "unknown"
		b.Detail = "the repository could not be read"
		return b, known, fmt.Errorf("backup %s: %w", j.Name, err)
	}
	var newest *snapshot
	for i := range snapshots {
		if newest == nil || snapshots[i].Time.After(newest.Time) {
			newest = &snapshots[i]
		}
	}
	if newest == nil {
		b.LastResult, b.Detail = "unknown", "the repository has no snapshot"
		for _, f := range []struct{ what, value string }{{"of host", j.Host}, {"with tag", j.Tag}} {
			if f.value != "" {
				b.Detail += " " + f.what + " " + f.value
			}
		}
		return b, jobState{}, nil
	}

	b.LastSuccess, b.LastRun, b.LastResult = newest.Time.UTC(), newest.Time.UTC(), "ok"
	b.Detail = "snapshot " + newest.ShortID
	if newest.Summary != nil {
		b.Detail += ", " + size(newest.Summary.TotalBytesProcessed)
	}
	return b, jobState{LastSuccess: b.LastSuccess, LastRun: b.LastRun, LastResult: "ok", Detail: b.Detail}, nil
}

// snapshots asks restic for the newest snapshot of every host and set of paths. It takes no
// lock: looking must never get in a running backup's way, and must work on a repository that
// this user may only read.
func (c *collector) snapshots(ctx context.Context, j ResticJob) ([]snapshot, error) {
	env, secrets, err := j.environment()
	if err != nil {
		return nil, err
	}
	args := []string{"snapshots", "--json", "--no-lock", "--latest", "1"}
	if j.Host != "" {
		args = append(args, "--host", j.Host)
	}
	if j.Tag != "" {
		args = append(args, "--tag", j.Tag)
	}
	out, err := c.run(ctx, resticTimeout, env, "restic", args...)
	said := resticMessage(out.stderr, secrets, err == nil)
	switch {
	case err != nil && said != "":
		return nil, fmt.Errorf("asking restic for the snapshots: %w: %s", err, said)
	case err != nil:
		return nil, fmt.Errorf("asking restic for the snapshots: %w", err)
	case out.exit != 0:
		return nil, fmt.Errorf("asking restic for the snapshots: restic ended with status %d: %s", out.exit, said)
	}
	var list []snapshot
	if err := json.Unmarshal(out.stdout, &list); err != nil {
		return nil, errors.New("asking restic for the snapshots: its answer is not the list expected")
	}
	return list, nil
}

// environment is what restic runs with: the agent's own environment, the variables of the
// job's file, and the job's settings on top. The repository and the password travel in the
// environment and not on the command line, where every user of the machine could read them.
// The second result lists the values that must not show up in anything reported.
func (j ResticJob) environment() (env, secrets []string, err error) {
	env = os.Environ()
	if j.EnvFile != "" {
		file, err := os.Open(j.EnvFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading restic's settings: %w", err)
		}
		defer file.Close()
		vars, err := parseEnv(file)
		if err != nil {
			return nil, nil, fmt.Errorf("reading restic's settings from %s: %w", j.EnvFile, err)
		}
		for _, v := range vars {
			env = append(env, v.name+"="+v.value)
			secrets = append(secrets, v.value)
		}
	}
	for _, v := range []struct{ name, value string }{
		{"RESTIC_REPOSITORY", j.Repository},
		{"RESTIC_REPOSITORY_FILE", j.RepositoryFile},
		{"RESTIC_PASSWORD_FILE", j.PasswordFile},
	} {
		if v.value != "" {
			env = append(env, v.name+"="+v.value)
		}
	}
	return env, append(secrets, j.Repository), nil
}

type variable struct{ name, value string }

var variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// parseEnv reads a systemd EnvironmentFile (systemd.exec(5)): NAME=value lines, values bare
// or in single or double quotes, comments after "#" or ";" at the start of a line. Errors name
// the line by its number only: its text may be a password.
func parseEnv(r io.Reader) ([]variable, error) {
	var out []variable
	lines := bufio.NewScanner(r)
	for n := 1; lines.Scan(); n++ {
		line := strings.TrimSpace(lines.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		line = strings.TrimPrefix(line, "export ") // not systemd's, but common in files a shell also reads
		name, value, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found || !variableName.MatchString(name) {
			return nil, fmt.Errorf("line %d is not NAME=value", n)
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			quote := value[0]
			value = value[1 : len(value)-1]
			if quote == '"' {
				value = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`").Replace(value)
			}
		}
		out = append(out, variable{name, value})
	}
	if err := lines.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

var (
	// credentials matches the user and password in front of a host: "//user:secret@".
	credentials = regexp.MustCompile(`//[^/@\s"']*@`)
	// retry is how restic reports a storage operation it will try again; what failed follows.
	retry = regexp.MustCompile(`returned error, retrying after [^:]*: `)
	// escapes are the terminal codes restic clears its status line with.
	escapes = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")
)

// resticMessage picks what restic said went wrong out of what it printed, and takes out
// everything that could be a secret. With --json restic's last word is a JSON object
// ({"message_type":"exit_error",...}). When restic was stopped because the repository's server
// never answered, that last word is only "context canceled", and the reason is in the lines
// before it, one per attempt.
func resticMessage(stderr []byte, secrets []string, finished bool) string {
	lines := strings.Split(strings.TrimSpace(escapes.ReplaceAllString(string(stderr), "")), "\n")
	said := strings.TrimSpace(lines[len(lines)-1])
	var last struct {
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(said), &last) == nil && last.Message != "" {
		said, _, _ = strings.Cut(last.Message, "\n") // the lines after the first repeat the repository's address
	}
	if !finished {
		for _, line := range lines {
			if at := retry.FindStringIndex(line); at != nil {
				said = line[at[1]:]
			}
		}
	}
	// restic stars out the password in an address itself; this does not rely on it.
	for _, secret := range secrets {
		// A value this short would star out half the message. A password in an address is
		// covered below whatever its length.
		if len(secret) < 4 {
			continue
		}
		said = strings.ReplaceAll(said, secret, "***")
		if _, password, found := strings.Cut(userinfo(secret), ":"); found && len(password) >= 4 {
			said = strings.ReplaceAll(said, password, "***")
		}
	}
	said = credentials.ReplaceAllString(said, "//***@")
	return clip(said, 300)
}

// userinfo is the "user:password" inside an address like "rest:http://user:password@host/".
func userinfo(address string) string {
	_, rest, found := strings.Cut(address, "//")
	if !found {
		return ""
	}
	rest, _, _ = strings.Cut(rest, "/")
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return ""
	}
	return rest[:at]
}
