// Package store keeps the server's state: the latest report of every system and the registry
// checks. Memory is for tests and the demo; the SQLite store is what a server runs on.
package store

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
)

// ErrNotFound is returned for a system nobody reported.
var ErrNotFound = errors.New("not found")

// Store is everything the rest of the server needs from storage.
type Store interface {
	// SaveReport replaces the stored report of r.System.Name.
	SaveReport(ctx context.Context, r *report.Report, receivedAt time.Time) error
	// Systems returns the latest state of every system, sorted by name.
	Systems(ctx context.Context) ([]model.SystemState, error)
	// System returns one system, or ErrNotFound.
	System(ctx context.Context, name string) (model.SystemState, error)
	// DeleteSystem forgets a system that no longer exists.
	DeleteSystem(ctx context.Context, name string) error
	// SaveImageCheck replaces the check stored for c.Image.
	SaveImageCheck(ctx context.Context, c model.ImageCheck) error
	// DeleteImageCheck forgets the check of an image no system runs any more.
	DeleteImageCheck(ctx context.Context, image string) error
	// ImageChecks returns every stored check, keyed by image reference.
	ImageChecks(ctx context.Context) (map[string]model.ImageCheck, error)
	Close() error
}

// Memory is a Store that lives in the process.
type Memory struct {
	mu      sync.RWMutex
	systems map[string]model.SystemState
	checks  map[string]model.ImageCheck
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{systems: map[string]model.SystemState{}, checks: map[string]model.ImageCheck{}}
}

func (m *Memory) SaveReport(_ context.Context, r *report.Report, receivedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.systems[r.System.Name] = model.SystemState{Report: *r, ReceivedAt: receivedAt}
	return nil
}

func (m *Memory) Systems(context.Context) ([]model.SystemState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SystemState, 0, len(m.systems))
	for _, s := range m.systems {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Report.System.Name < out[j].Report.System.Name })
	return out, nil
}

func (m *Memory) System(_ context.Context, name string) (model.SystemState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.systems[name]
	if !ok {
		return model.SystemState{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) DeleteSystem(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.systems, name)
	return nil
}

func (m *Memory) SaveImageCheck(_ context.Context, c model.ImageCheck) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks[c.Image] = c
	return nil
}

func (m *Memory) DeleteImageCheck(_ context.Context, image string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.checks, image)
	return nil
}

func (m *Memory) ImageChecks(context.Context) (map[string]model.ImageCheck, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]model.ImageCheck, len(m.checks))
	for k, v := range m.checks {
		out[k] = v
	}
	return out, nil
}

func (m *Memory) Close() error { return nil }
