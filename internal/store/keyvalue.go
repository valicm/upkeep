package store

import (
	"context"
	"sync"
)

// KeyValue is the small table the server keeps its own state in between restarts: when the
// last mail went out and what it said. It is apart from Store so that Store stays what the
// dashboard needs and nothing more.
type KeyValue interface {
	// Value returns what is stored under key, or "" when nothing is.
	Value(ctx context.Context, key string) (string, error)
	// SetValue stores value under key, replacing what was there.
	SetValue(ctx context.Context, key, value string) error
}

// MemoryValues is a KeyValue that lives in the process, for tests and the demo.
type MemoryValues struct {
	mu     sync.RWMutex
	values map[string]string
}

// NewMemoryValues returns an empty MemoryValues.
func NewMemoryValues() *MemoryValues { return &MemoryValues{values: map[string]string{}} }

func (m *MemoryValues) Value(_ context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.values[key], nil
}

func (m *MemoryValues) SetValue(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = value
	return nil
}

// ValuesOf returns s itself when it also keeps values, as the SQLite store does, and else a
// MemoryValues that forgets when the process ends.
func ValuesOf(s Store) KeyValue {
	if kv, ok := s.(KeyValue); ok {
		return kv
	}
	return NewMemoryValues()
}
