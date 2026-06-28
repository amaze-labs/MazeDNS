// Package store is the SQLite-backed datastore for MazeDNS config and query logs.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (registers "sqlite")
)

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Rule is an allow/deny entry for a domain, tagged with a category.
type Rule struct {
	ID        int64  `json:"id"`
	Action    string `json:"action"` // "allow" | "deny"
	Domain    string `json:"domain"`
	Category  string `json:"category"` // "ads" | "trackers" | "malware" | "custom"
	Enabled   bool   `json:"enabled"`
	ListID    int64  `json:"list_id"` // 0 = manual rule; otherwise the owning list
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
	category TEXT NOT NULL DEFAULT 'custom',
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
	category TEXT NOT NULL DEFAULT '',
	rcode TEXT NOT NULL,
	elapsed_ms INTEGER NOT NULL,
	node TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(ts);
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	role TEXT NOT NULL DEFAULT 'readonly',
	source TEXT NOT NULL DEFAULT 'local',
	subject TEXT NOT NULL DEFAULT '',
	avatar_url TEXT NOT NULL DEFAULT '',
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
INSERT OR IGNORE INTO meta(key, value) VALUES('block_paused_until', 0);
CREATE TABLE IF NOT EXISTS lists (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	source TEXT NOT NULL DEFAULT 'file',
	url TEXT NOT NULL DEFAULT '',
	category TEXT NOT NULL DEFAULT 'custom',
	enabled INTEGER NOT NULL DEFAULT 1,
	interval_sec INTEGER NOT NULL DEFAULT 0,
	last_fetch INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '',
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
	name TEXT PRIMARY KEY,
	key_hash TEXT NOT NULL DEFAULT '',
	key_prefix TEXT NOT NULL DEFAULT '',
	address TEXT NOT NULL DEFAULT '',
	version INTEGER NOT NULL DEFAULT 0,
	last_seen INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL DEFAULT 0,
	q_total INTEGER NOT NULL DEFAULT 0,
	q_blocked INTEGER NOT NULL DEFAULT 0,
	q_cached INTEGER NOT NULL DEFAULT 0,
	q_forwarded INTEGER NOT NULL DEFAULT 0,
	q_rewritten INTEGER NOT NULL DEFAULT 0,
	q_errors INTEGER NOT NULL DEFAULT 0,
	insights TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS classifications (
	domain TEXT PRIMARY KEY,                    -- registered domain (eTLD+1), normalized
	category TEXT NOT NULL DEFAULT 'clean',     -- ads|trackers|malware|phishing|clean|other
	block INTEGER NOT NULL DEFAULT 0,           -- model recommends blocking
	status TEXT NOT NULL DEFAULT 'suggested',   -- suggested|approved|rejected|auto|clean
	confidence REAL NOT NULL DEFAULT 0,
	score INTEGER NOT NULL DEFAULT 100,         -- legitimacy 0-100 (100 = fully legit)
	factors TEXT NOT NULL DEFAULT '[]',         -- score breakdown (JSON array)
	reason TEXT NOT NULL DEFAULT '',
	model TEXT NOT NULL DEFAULT '',
	trusted INTEGER NOT NULL DEFAULT 0,
	threat INTEGER NOT NULL DEFAULT 0,
	updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_classifications_status ON classifications(status);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	// Additive column migrations for databases created before a column existed.
	for _, alter := range []string{
		`ALTER TABLE rules ADD COLUMN category TEXT NOT NULL DEFAULT 'custom'`,
		`ALTER TABLE rules ADD COLUMN list_id INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE query_log ADD COLUMN category TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE query_log ADD COLUMN node TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN key_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN key_prefix TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN q_total INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN q_blocked INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN q_cached INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN q_forwarded INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN q_rewritten INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN q_errors INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN insights TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN avatar_url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE classifications ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE classifications ADD COLUMN threat INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE classifications ADD COLUMN score INTEGER NOT NULL DEFAULT 100`,
		`ALTER TABLE classifications ADD COLUMN factors TEXT NOT NULL DEFAULT '[]'`,
	} {
		if _, err := s.db.Exec(alter); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate alter: %w", err)
		}
	}
	return nil
}

// ListRules returns all rules ordered by domain.
func (s *Store) ListRules() ([]Rule, error) {
	rows, err := s.db.Query(`SELECT id, action, domain, category, enabled, list_id, updated_at FROM rules ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Action, &r.Domain, &r.Category, &r.Enabled, &r.ListID, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRule inserts or re-enables a rule and returns its id.
func (s *Store) AddRule(action, domain, category string) (int64, error) {
	if category == "" {
		category = "custom"
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec(
		`INSERT INTO rules(action, domain, category, enabled, updated_at) VALUES(?,?,?,1,?)
		 ON CONFLICT(action, domain) DO UPDATE SET category=excluded.category, enabled=1, updated_at=excluded.updated_at`,
		action, domain, category, now,
	); err != nil {
		return 0, err
	}
	var id int64
	err := s.db.QueryRow(`SELECT id FROM rules WHERE action=? AND domain=?`, action, domain).Scan(&id)
	return id, err
}

// AddRulesBulk inserts/updates many rules in one transaction, returning the count applied.
func (s *Store) AddRulesBulk(rules []Rule) (int, error) {
	if len(rules) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO rules(action, domain, category, enabled, updated_at) VALUES(?,?,?,1,?)
		 ON CONFLICT(action, domain) DO UPDATE SET category=excluded.category, enabled=1, updated_at=excluded.updated_at`)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	n := 0
	for _, r := range rules {
		cat := r.Category
		if cat == "" {
			cat = "custom"
		}
		if _, err := stmt.Exec(r.Action, r.Domain, cat, now); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// DeleteRule removes a rule by id.
func (s *Store) DeleteRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM rules WHERE id=?`, id)
	return err
}

// ClearRules removes every rule (used by a "replace" config import).
func (s *Store) ClearRules() error {
	_, err := s.db.Exec(`DELETE FROM rules`)
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

// AddRewritesBulk inserts/updates many rewrites in one transaction, returning the count applied.
func (s *Store) AddRewritesBulk(rws []Rewrite) (int, error) {
	if len(rws) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO rewrites(domain, rrtype, value, enabled, updated_at) VALUES(?,?,?,1,?)
		 ON CONFLICT(domain, rrtype) DO UPDATE SET value=excluded.value, enabled=1, updated_at=excluded.updated_at`)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	n := 0
	for _, r := range rws {
		if _, err := stmt.Exec(r.Domain, r.RRType, r.Value, now); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// DeleteRewrite removes a rewrite by id.
func (s *Store) DeleteRewrite(id int64) error {
	_, err := s.db.Exec(`DELETE FROM rewrites WHERE id=?`, id)
	return err
}

// ClearRewrites removes every rewrite (used by a "replace" config import).
func (s *Store) ClearRewrites() error {
	_, err := s.db.Exec(`DELETE FROM rewrites`)
	return err
}
