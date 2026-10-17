// Package store is conductor-provisioner's local state in SQLite (pure Go
// driver, CGO off, WAL, synchronous=FULL): the one-time tokens (hashes
// only) and the hash-chained audit log. Passwords are never stored.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store wraps the database.
type Store struct {
	db       *sql.DB
	auditMu  sync.Mutex
	auditKey []byte
	now      func() time.Time
}

// Open opens (creating if needed) the database and applies migrations.
// auditKey keys the audit chain (derived from the state key, see
// AuditKey); with a nil key the audit log can be read but neither
// extended nor verified (status without the state key). The files are
// made private to the process user.
func Open(ctx context.Context, p string, auditKey []byte) (*Store, error) {
	if p == "" {
		return nil, errors.New("store: empty path")
	}
	if auditKey != nil && len(auditKey) < 32 {
		return nil, errors.New("store: the audit key must be at least 32 bytes")
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + p + "?" + q.Encode()
	if p == ":memory:" {
		dsn = "file::memory:?" + q.Encode()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, auditKey: append([]byte(nil), auditKey...), now: func() time.Time { return time.Now().UTC() }}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if p != ":memory:" {
		for _, f := range []string{p, p + "-wal", p + "-shm"} {
			if _, err := os.Stat(f); err == nil {
				_ = os.Chmod(f, 0o600)
			}
		}
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error {
	clear(s.auditKey)
	return s.db.Close()
}

// SetClock replaces the clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = func() time.Time { return now().UTC() } }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	latest := 0
	for _, name := range names {
		v, err := strconv.Atoi(strings.SplitN(path.Base(name), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("store: migration %s: bad name", name)
		}
		latest = max(latest, v)
	}
	var newest sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&newest); err != nil {
		return err
	}
	if newest.Valid && int(newest.Int64) > latest {
		return fmt.Errorf("store: the database schema (version %d) is newer than this binary (%d); downgrades are not supported", newest.Int64, latest)
	}
	for _, name := range names {
		v, _ := strconv.Atoi(strings.SplitN(path.Base(name), "_", 2)[0])
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, v).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, v, ts(s.now())); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// tsLayout is fixed-width, so stored times compare correctly as text.
const tsLayout = "2006-01-02T15:04:05.000000Z"

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(tsLayout)
}

func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// clip shortens s to at most n bytes.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
