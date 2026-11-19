package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // the driver, pure Go so that the binary stays static

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
)

// migrations bring a database from schema version i to i+1. Only ever append: a database in
// the field is at whatever version its last server left it.
var migrations = []string{
	// 1: the latest report per system, the registry checks, and the server's own values.
	`CREATE TABLE systems (
		name        TEXT PRIMARY KEY,
		received_at TEXT NOT NULL, -- RFC 3339, UTC
		report      TEXT NOT NULL  -- the report as the agent's JSON
	) STRICT;
	CREATE TABLE image_checks (
		image       TEXT PRIMARY KEY,
		tag         TEXT NOT NULL,
		tag_digest  TEXT NOT NULL,
		newer_patch TEXT NOT NULL,
		newer_minor TEXT NOT NULL,
		newer_major TEXT NOT NULL,
		checked_at  TEXT NOT NULL, -- RFC 3339, UTC; empty when never
		error       TEXT NOT NULL
	) STRICT;
	CREATE TABLE key_values (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	) STRICT;`,
	// 2: a remark on a registry check that worked but may be incomplete.
	`ALTER TABLE image_checks ADD COLUMN note TEXT NOT NULL DEFAULT '';`,
}

// SQLite is the Store a server runs on: one file, no other process needed. It also is the
// server's KeyValue.
type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens the database file at path, creating it or bringing its schema up to date
// when needed. The directory must exist.
func OpenSQLite(ctx context.Context, path string) (*SQLite, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("opening the database %s: %w", path, err)
	}
	// A file: URI, so that a path with "?" or "#" in it stays a path. WAL lets a backup tool
	// read the file while the server writes; the busy timeout makes two writers wait for each
	// other instead of failing.
	q := url.Values{"_pragma": {"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(NORMAL)"}}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: q.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening the database %s: %w", path, err)
	}
	db.SetMaxOpenConns(4) // a homelab's worth of reports does not need more
	s := &SQLite{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("opening the database %s: %w", path, err)
	}
	return s, nil
}

// migrate applies the migrations the file has not seen. The version lives in SQLite's own
// user_version, which is part of the transaction that changes the schema.
func (s *SQLite) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("reading the schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("schema version %d is newer than this upkeep knows (%d): it was written by a newer upkeep", version, len(migrations))
	}
	for v := version; v < len(migrations); v++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("upgrading the schema to version %d: %w", v+1, err)
		}
		if _, err = tx.ExecContext(ctx, migrations[v]); err == nil {
			// PRAGMA takes no placeholders; v is our own counter.
			_, err = tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, v+1))
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("upgrading the schema to version %d: %w", v+1, err)
		}
	}
	return nil
}

func (s *SQLite) SaveReport(ctx context.Context, r *report.Report, receivedAt time.Time) error {
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("saving the report of %s: %w", r.System.Name, err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO systems (name, received_at, report) VALUES (?, ?, ?)
		 ON CONFLICT (name) DO UPDATE SET received_at = excluded.received_at, report = excluded.report`,
		r.System.Name, formatTime(receivedAt), string(body))
	if err != nil {
		return fmt.Errorf("saving the report of %s: %w", r.System.Name, err)
	}
	return nil
}

func (s *SQLite) Systems(ctx context.Context) ([]model.SystemState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, received_at, report FROM systems ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("reading the systems: %w", err)
	}
	defer rows.Close()
	out := []model.SystemState{}
	for rows.Next() {
		st, err := scanSystem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading the systems: %w", err)
	}
	return out, nil
}

func (s *SQLite) System(ctx context.Context, name string) (model.SystemState, error) {
	row := s.db.QueryRowContext(ctx, `SELECT name, received_at, report FROM systems WHERE name = ?`, name)
	st, err := scanSystem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SystemState{}, ErrNotFound
	}
	return st, err
}

// scanSystem reads one row of systems; both *sql.Row and *sql.Rows can do that.
func scanSystem(row interface{ Scan(...any) error }) (model.SystemState, error) {
	var name, received, body string
	if err := row.Scan(&name, &received, &body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.SystemState{}, err
		}
		return model.SystemState{}, fmt.Errorf("reading a system: %w", err)
	}
	var st model.SystemState
	if err := json.Unmarshal([]byte(body), &st.Report); err != nil {
		return model.SystemState{}, fmt.Errorf("reading the stored report of %s: %w", name, err)
	}
	var err error
	if st.ReceivedAt, err = parseTime(received); err != nil {
		return model.SystemState{}, fmt.Errorf("reading the arrival time of %s: %w", name, err)
	}
	return st, nil
}

func (s *SQLite) DeleteSystem(ctx context.Context, name string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM systems WHERE name = ?`, name); err != nil {
		return fmt.Errorf("deleting the system %s: %w", name, err)
	}
	return nil
}

func (s *SQLite) SaveImageCheck(ctx context.Context, c model.ImageCheck) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO image_checks (image, tag, tag_digest, newer_patch, newer_minor, newer_major, checked_at, error, note)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (image) DO UPDATE SET tag = excluded.tag, tag_digest = excluded.tag_digest,
			newer_patch = excluded.newer_patch, newer_minor = excluded.newer_minor, newer_major = excluded.newer_major,
			checked_at = excluded.checked_at, error = excluded.error, note = excluded.note`,
		c.Image, c.Tag, c.TagDigest, c.NewerPatch, c.NewerMinor, c.NewerMajor, formatTime(c.CheckedAt), c.Error, c.Note)
	if err != nil {
		return fmt.Errorf("saving the registry check of %s: %w", c.Image, err)
	}
	return nil
}

func (s *SQLite) DeleteImageCheck(ctx context.Context, image string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM image_checks WHERE image = ?`, image); err != nil {
		return fmt.Errorf("deleting the registry check of %s: %w", image, err)
	}
	return nil
}

func (s *SQLite) ImageChecks(ctx context.Context) (map[string]model.ImageCheck, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT image, tag, tag_digest, newer_patch, newer_minor, newer_major, checked_at, error, note FROM image_checks`)
	if err != nil {
		return nil, fmt.Errorf("reading the registry checks: %w", err)
	}
	defer rows.Close()
	out := map[string]model.ImageCheck{}
	for rows.Next() {
		var c model.ImageCheck
		var checked string
		if err := rows.Scan(&c.Image, &c.Tag, &c.TagDigest, &c.NewerPatch, &c.NewerMinor, &c.NewerMajor, &checked, &c.Error, &c.Note); err != nil {
			return nil, fmt.Errorf("reading the registry checks: %w", err)
		}
		if c.CheckedAt, err = parseTime(checked); err != nil {
			return nil, fmt.Errorf("reading the registry check of %s: %w", c.Image, err)
		}
		out[c.Image] = c
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading the registry checks: %w", err)
	}
	return out, nil
}

func (s *SQLite) Value(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM key_values WHERE key = ?`, key).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("reading the value %s: %w", key, err)
	}
	return value, nil
}

func (s *SQLite) SetValue(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO key_values (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("saving the value %s: %w", key, err)
	}
	return nil
}

func (s *SQLite) Close() error { return s.db.Close() }

// Times are stored as text a person can read when looking into the file. The zero time is
// stored empty: it means "never", not year 1.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}
