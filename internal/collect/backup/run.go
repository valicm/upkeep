package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// output is what a command left behind.
type output struct {
	stdout, stderr []byte
	exit           int // the command's exit status
}

// runner runs a command with the given environment (nil: this process's own) and waits for
// it, for at most timeout. An error means the command could not be run or did not finish; a
// command that ran and failed has a nil error and its exit status in the output. It is a field
// of the collector so that tests can answer with captured output.
type runner func(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (output, error)

const (
	maxStdout = 32 << 20 // restic's snapshot list is a few kilobytes; this is a runaway's limit
	maxStderr = 64 << 10
)

// errNotInstalled is a command that is not on this machine.
var errNotInstalled = errors.New("not installed")

func execute(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (output, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	stdout, stderr := capped{max: maxStdout}, capped{max: maxStderr}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// Ask first, so that restic can close its connections; kill if it does not listen. The
	// wait is shorter than the three seconds the agent gives a collector whose time is up.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 2 * time.Second

	err := cmd.Run()
	out := output{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	var exited *exec.ExitError
	switch {
	case err == nil:
	case errors.Is(err, exec.ErrNotFound):
		return out, fmt.Errorf("%s is %w", name, errNotInstalled)
	case ctx.Err() != nil:
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return out, fmt.Errorf("%s did not finish within %s", name, timeout)
		}
		return out, ctx.Err()
	case errors.As(err, &exited) && exited.Exited():
		out.exit = exited.ExitCode()
	default:
		return out, err // killed by a signal, or could not be started
	}
	if stdout.dropped {
		return out, fmt.Errorf("%s printed more than %d MiB", name, maxStdout>>20)
	}
	return out, nil
}

// capped keeps the first max bytes written to it and drops the rest.
type capped struct {
	bytes.Buffer
	max     int
	dropped bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); len(p) > room {
		c.dropped = true
		c.Buffer.Write(p[:max(room, 0)])
		return len(p), nil // the command must not block or fail on a full buffer
	}
	return c.Buffer.Write(p)
}
