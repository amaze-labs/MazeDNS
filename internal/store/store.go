// Package store is the SQLite-backed datastore for MazeDNS config and query logs.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (registers "sqlite")
)

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Rule is an allow/deny entry for a domain.
type Rule struct {
	ID        int64  `json:"id"`
	Action    string `json:"action"` // "allow" | "deny"
	Domain    string `json:"domain"`
	Enabled   bool   `json:"enabled"`
	UpdatedAt int64  `json:"updated_at"`
}

// Rewrite is a local DNS record override.
type Rewrite struct {
	ID        int64  `json:"id"`
	Domain    string `json:"domain"`
	RRType    string `json:"rrtype"` // "A" | "AAAA" | "CNAME"
	Value     string `json:"value"`
	Enabled   bool   `json:"enabled"`
	UpdatedAt int64  `json:"updated_at"`
}

// Open opens (creating if needed) the SQLite database at path and runs migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // serialize access — simplest correct behavior for SQLite
	s := &Store{db: db}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			return nil, fmt.Errorf("pragma %q: %w", pragma, err)
		}
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	action TEXT NOT NULL,
	domain TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1,
	updated_at INTEGER NOT NULL,
	UNIQUE(action, domain)
);
CREATE TABLE IF NOT EXISTS rewrites (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT NOT NULL,
	rrtype TEXT NOT NULL,
	value TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1,
	updated_at INTEGER NOT NULL,
	UNIQUE(domain, rrtype)
);
CREATE TABLE IF NOT EXISTS query_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts INTEGER NOT NULL,
	client TEXT NOT NULL,
	name TEXT NOT NULL,
	qtype TEXT NOT NULL,
	action TEXT NOT NULL,
	rcode TEXT NOT NULL,
	elapsed_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(ts);
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	role TEXT NOT NULL DEFAULT 'readonly',
	source TEXT NOT NULL DEFAULT 'local',
	subject TEXT NOT NULL DEFAULT '',
	password_hash TEXT NOT NULL DEFAULT '',
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	username TEXT NOT NULL,
	role TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
	key TEXT PRIMARY KEY,
	value INTEGER NOT NULL
);
INSERT OR IGNORE INTO meta(key, value) VALUES('config_version', 0);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// ListRules returns all rules ordered by domain.
func (s *Store) ListRules() ([]Rule, error) {
	rows, err := s.db.Query(`SELECT id, action, domain, enabled, updated_at FROM rules ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Action, &r.Domain, &r.Enabled, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRule inserts or re-enables a rule and returns its id.
func (s *Store) AddRule(action, domain string) (int64, error) {
	now := time.Now().Unix()
	if _, err := s.db.Exec(
		`INSERT INTO rules(action, domain, enabled, updated_at) VALUES(?,?,1,?)
		 ON CONFLICT(action, domain) DO UPDATE SET enabled=1, updated_at=?`,
		action, domain, now, now,
	); err != nil {
		return 0, err
	}
	var id int64
	err := s.db.QueryRow(`SELECT id FROM rules WHERE action=? AND domain=?`, action, domain).Scan(&id)
	return id, err
}

// DeleteRule removes a rule by id.
func (s *Store) DeleteRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM rules WHERE id=?`, id)
	return err
}

// ListRewrites returns all rewrites ordered by domain.
func (s *Store) ListRewrites() ([]Rewrite, error) {
	rows, err := s.db.Query(`SELECT id, domain, rrtype, value, enabled, updated_at FROM rewrites ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rewrite
	for rows.Next() {
		var r Rewrite
		if err := rows.Scan(&r.ID, &r.Domain, &r.RRType, &r.Value, &r.Enabled, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRewrite inserts or updates a rewrite and returns its id.
func (s *Store) AddRewrite(domain, rrtype, value string) (int64, error) {
	now := time.Now().Unix()
	if _, err := s.db.Exec(
		`INSERT INTO rewrites(domain, rrtype, value, enabled, updated_at) VALUES(?,?,?,1,?)
		 ON CONFLICT(domain, rrtype) DO UPDATE SET value=excluded.value, enabled=1, updated_at=?`,
		domain, rrtype, value, now, now,
	); err != nil {
		return 0, err
	}
	var id int64
	err := s.db.QueryRow(`SELECT id FROM rewrites WHERE domain=? AND rrtype=?`, domain, rrtype).Scan(&id)
	return id, err
}

// DeleteRewrite removes a rewrite by id.
func (s *Store) DeleteRewrite(id int64) error {
	_, err := s.db.Exec(`DELETE FROM rewrites WHERE id=?`, id)
	return err
}
