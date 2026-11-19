package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"time"
)

// stateFile is the collector's memory inside the agent's state directory. It exists because
// the evidence forgets: systemd knows only a unit's latest run, and nothing at all after a
// reboot, so the last run that worked has to be written down when it is seen.
const stateFile = "backup.json"

// state is the file's content.
type state struct {
	Jobs map[string]jobState `json:"jobs"` // by "systemd:<unit>" or "restic:<name>"
}

// jobState is what was last seen of one backup.
type jobState struct {
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastRun     time.Time `json:"last_run,omitzero"`
	LastResult  string    `json:"last_result,omitempty"`
	Detail      string    `json:"detail,omitempty"`
}

// same compares moments, not how they are written: a time read back from the file and the
// same time fresh from restic can differ in their time zone.
func (a jobState) same(b jobState) bool {
	return a.LastSuccess.Equal(b.LastSuccess) && a.LastRun.Equal(b.LastRun) && a.LastResult == b.LastResult && a.Detail == b.Detail
}

// keep remembers js under key, or forgets the key when there is nothing to remember.
func (s state) keep(key string, js jobState) {
	if js.same(jobState{}) {
		delete(s.Jobs, key)
		return
	}
	s.Jobs[key] = js
}

func (c *collector) loadState() (state, error) {
	if c.stateDir == "" {
		return c.memory, nil
	}
	path := filepath.Join(c.stateDir, stateFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return state{}, nil // the first run
	}
	if err != nil {
		return state{}, fmt.Errorf("reading what is remembered of earlier backups: %w", err)
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return state{}, fmt.Errorf("reading what is remembered of earlier backups: %s is damaged and will be replaced: %w", path, err)
	}
	return s, nil
}

// saveState writes after down when it differs from before. Most runs change nothing, and the
// state directory of a Raspberry Pi is an SD card that is better not written every few minutes.
func (c *collector) saveState(before, after state) error {
	if c.stateDir == "" {
		c.memory = after
		return nil
	}
	if maps.EqualFunc(before.Jobs, after.Jobs, jobState.same) {
		return nil
	}
	raw, err := json.MarshalIndent(after, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return fmt.Errorf("remembering the backups seen: %w", err)
	}
	// Written beside the file and moved over it, so a crash leaves the old file or the new one.
	tmp, err := os.CreateTemp(c.stateDir, stateFile+".*")
	if err != nil {
		return fmt.Errorf("remembering the backups seen: %w", err)
	}
	_, err = tmp.Write(append(raw, '\n'))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(c.stateDir, stateFile))
	}
	if err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("remembering the backups seen: %w", err)
	}
	return nil
}
