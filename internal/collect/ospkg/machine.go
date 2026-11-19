package ospkg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// machine is how the collector reaches the system: files under a root, and commands. Tests
// replace both, so no test runs a package manager or reads the real /var.
type machine struct {
	root   string // "" on a real machine, a directory of fixtures in tests
	goos   string
	goarch string
	tmp    string // where short-lived directories go; "" is the system's place for them
	run    func(ctx context.Context, c command) (output, error)
	have   func(name string) bool                // is this command installed
	uname  func(context.Context) (string, error) // "uname -r", for a kernel without /proc
}

// command is one program to run. It gets a small fixed environment, never the agent's own.
type command struct {
	name    string
	args    []string
	env     []string // added to the fixed environment
	timeout time.Duration
}

func (c command) String() string { return strings.Join(append([]string{c.name}, c.args...), " ") }

// output is what a command that ran to its end left behind. A non-zero exit code is not an
// error here: several package managers use it to say "there are updates".
type output struct {
	stdout, stderr string
	code           int
}

func (m *machine) path(p string) string { return filepath.Join(m.root, p) }

func (m *machine) exists(p string) bool {
	_, err := os.Stat(m.path(p))
	return err == nil
}

// newestMtime returns the newest modification time among the files the patterns match, and
// the zero time when they match nothing.
func (m *machine) newestMtime(patterns ...string) time.Time {
	var newest time.Time
	for _, pattern := range patterns {
		names, _ := filepath.Glob(m.path(pattern))
		for _, name := range names {
			if st, err := os.Stat(name); err == nil && st.ModTime().After(newest) {
				newest = st.ModTime()
			}
		}
	}
	return newest
}

// searchPath is where commands are looked for, after the agent's own PATH. A service started
// by FreeBSD's rc has neither /usr/local/sbin, where pkg lives, nor Debian's sbin directories.
var searchPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

func lookPath(name string) (string, bool) {
	dirs := append(filepath.SplitList(os.Getenv("PATH")), searchPath...)
	for _, dir := range dirs {
		if !filepath.IsAbs(dir) {
			continue // a relative PATH entry would run whatever sits in the working directory
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

func haveCommand(name string) bool {
	_, ok := lookPath(name)
	return ok
}

// maxOutput is far above anything a package manager prints; it only stops a command that
// went wrong from filling the memory of a small machine.
const maxOutput = 16 << 20

// runCommand runs c to its end, at most for c.timeout. The environment is fixed: the C locale,
// because the output is parsed, and nothing inherited that could change what a tool does
// (ASSUME_ALWAYS_YES, for one, would let FreeBSD's pkg install itself).
func runCommand(ctx context.Context, c command) (output, error) {
	path, ok := lookPath(c.name)
	if !ok {
		return output{}, fmt.Errorf("run %s: command not found", c.name)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, c.args...)
	cmd.Env = append([]string{
		"PATH=" + strings.Join(searchPath, string(os.PathListSeparator)),
		"LC_ALL=C",
		"LANG=C",
	}, c.env...)
	if home := os.Getenv("HOME"); home != "" {
		cmd.Env = append(cmd.Env, "HOME="+home)
	}
	stdout, stderr := &capped{left: maxOutput}, &capped{left: maxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 2 * time.Second // do not wait for a pipe that a killed command left open

	err := cmd.Run()
	out := output{stdout: stdout.buf.String(), stderr: stderr.buf.String()}
	var exit *exec.ExitError
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return out, fmt.Errorf("run %s: no answer within %s", c, c.timeout)
	case ctx.Err() != nil:
		return out, fmt.Errorf("run %s: %w", c, ctx.Err())
	case errors.As(err, &exit) && exit.ExitCode() >= 0:
		out.code = exit.ExitCode()
		return out, nil
	case err != nil:
		return out, fmt.Errorf("run %s: %w", c, err)
	}
	return out, nil
}

// capped is a buffer that silently drops what does not fit.
type capped struct {
	buf  bytes.Buffer
	left int
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	if n > c.left {
		p = p[:c.left]
	}
	c.buf.Write(p)
	c.left -= len(p)
	return n, nil
}

// failure describes a command that ended badly, with the tool's own words: the lines it
// marked as errors, or else the end of what it wrote.
func failure(c command, out output) error {
	msg := errorLines(out.stderr)
	if msg == "" {
		msg = errorLines(out.stdout)
	}
	if msg == "" {
		msg = tail(strings.TrimSpace(out.stderr + "\n" + out.stdout))
	}
	if msg == "" {
		return fmt.Errorf("%s: exit status %d", c, out.code)
	}
	return fmt.Errorf("%s: exit status %d: %s", c, out.code, msg)
}

// errorLines joins the lines apt marks with "E:"; other tools have no such mark.
func errorLines(text string) string {
	var errs []string
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "E: "); ok {
			errs = append(errs, rest)
		}
	}
	return clip(strings.Join(errs, "; "))
}

// tail returns the last lines of text on one line.
func tail(text string) string {
	lines := strings.Split(text, "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return clip(strings.Join(lines, "; "))
}

// clip keeps a message short enough for a line on a dashboard.
func clip(s string) string {
	const max = 400
	if len(s) > max {
		s = s[:max] + "..."
	}
	return strings.ToValidUTF8(s, "?") // the cut, or the tool, may have left half a character
}
