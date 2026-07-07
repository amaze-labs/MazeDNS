// Package store is the datastore for MazeDNS config and query logs. The default
// backend is embedded SQLite; an external PostgreSQL server is also supported
// (the queries are written in the SQLite dialect and adapted at runtime — see
// dialect.go).
package store

import (
	"database/sql"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver (registers "pgx")
	_ "modernc.org/sqlite"             // pure-Go SQLite driver (registers "sqlite")
)

// Store wraps the database behind a thin dialect-aware handle (dbh). On SQLite,
// WAL mode lets one writer and many readers run concurrently, so we keep two
// pools: a single-connection writer (db) and a small read pool (read). On
// PostgreSQL both pools are ordinary connection pools (no single-writer limit).
type Store struct {
	db   *dbh // writer (INSERT/UPDATE/DELETE/DDL + transactions)
	read *dbh // concurrent readers (standalone SELECTs)
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
// Open opens the embedded SQLite database at path (the default backend).
func Open(path string) (*Store, error) {
	// PRAGMAs are set in the DSN so they apply to *every* connection (including each
	// connection in the read pool). WAL + NORMAL sync are the safe fast pairing; the
	// bigger page cache + memory-mapped reads + in-memory temp B-trees cut the I/O
	// thrash of the dashboard's GROUP BY/COUNT scans over a large query_log.
	dsn := path + "?" + strings.Join([]string{
		"_pragma=busy_timeout(5000)",
		"_pragma=journal_mode(WAL)",
		"_pragma=foreign_keys(1)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=cache_size(-65536)",   // 64 MiB page cache (negative = KiB)
		"_pragma=mmap_size(268435456)", // 256 MiB memory-mapped I/O
		"_pragma=temp_store(MEMORY)",   // GROUP BY/ORDER BY temporaries in RAM
	}, "&")
	return OpenWith("sqlite", dsn)
}

// OpenWith opens the store on a given backend. driver is "sqlite" (default) or
// "pgx"/"postgres" (an external PostgreSQL server, dsn is its connection string).
func OpenWith(driver, dsn string) (*Store, error) {
	pg := driver == "pgx" || driver == "postgres"
	name := "sqlite"
	if pg {
		name = "pgx"
	}

	write, err := sql.Open(name, dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if !pg {
		write.SetMaxOpenConns(1) // SQLite allows a single writer
	}

	read, err := sql.Open(name, dsn)
	if err != nil {
		_ = write.Close()
		return nil, fmt.Errorf("open db (read pool): %w", err)
	}
	n := runtime.GOMAXPROCS(0)
	if n < 4 {
		n = 4
	}
	if n > 8 {
		n = 8
	}
	read.SetMaxOpenConns(n) // WAL / Postgres allow concurrent readers

	s := &Store{db: &dbh{DB: write, pg: pg}, read: &dbh{DB: read, pg: pg}}
	if err := s.migrate(); err != nil {
		_ = write.Close()
		_ = read.Close()
		return nil, err
	}
	return s, nil
}

// Close closes both connection pools.
func (s *Store) Close() error {
	_ = s.read.Close()
	return s.db.Close()
}

// sqliteSchema is the canonical schema in the SQLite dialect; toPostgresSchema
// adapts it for PostgreSQL (auto-increment type, float type, WITHOUT ROWID).
const sqliteSchema = `
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
-- Composite indexes for the windowed dashboard aggregations so they seek instead
-- of scanning the whole (cluster-wide, up to 90-day) log: (action,ts) covers the
-- blocked-only queries (blocked-by-category, top-blocked), (client,ts) covers the
-- per-client breakdown (Clients tab modal).
CREATE INDEX IF NOT EXISTS idx_query_log_action_ts ON query_log(action, ts);
CREATE INDEX IF NOT EXISTS idx_query_log_client_ts ON query_log(client, ts);
-- Materialized rollups so dashboard windows read tiny pre-aggregated tables
-- instead of scanning the raw query_log. Maintained incrementally from a cursor.
-- query_rollup: per-minute, per-node, per-action counts + latency sum (charts,
-- totals, by-node). client_rollup: per-hour, per-node, per-client counts (top +
-- unique clients). Both are bounded (minutes/hours x small dimensions / clients).
CREATE TABLE IF NOT EXISTS query_rollup (
	bucket  INTEGER NOT NULL,   -- unix minute = ts/60000
	node    TEXT NOT NULL,
	action  TEXT NOT NULL,
	cnt     INTEGER NOT NULL,
	lat_sum REAL NOT NULL,      -- sum of elapsed_ms (for the mean)
	PRIMARY KEY (bucket, node, action)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS client_rollup (
	hour    INTEGER NOT NULL,   -- unix hour = ts/3600000
	node    TEXT NOT NULL,
	client  TEXT NOT NULL,
	cnt     INTEGER NOT NULL,
	blocked INTEGER NOT NULL,
	PRIMARY KEY (hour, node, client)
) WITHOUT ROWID;
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
INSERT INTO meta(key, value) VALUES('config_version', 0) ON CONFLICT(key) DO NOTHING;
INSERT INTO meta(key, value) VALUES('block_paused_until', 0) ON CONFLICT(key) DO NOTHING;
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
	id TEXT PRIMARY KEY,                      -- UUIDv4, server-generated, immutable
	name TEXT NOT NULL DEFAULT '' UNIQUE,     -- mutable display label
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
	insights TEXT NOT NULL DEFAULT '',
	maintenance INTEGER NOT NULL DEFAULT 0,  -- node is drained (answers SERVFAIL)
	approved INTEGER NOT NULL DEFAULT 1,     -- token-enrolled node is admitted to the cluster
	key_issued_at INTEGER NOT NULL DEFAULT 0,      -- when the current key_hash was issued (for periodic rotation)
	prev_key_hash TEXT NOT NULL DEFAULT '',        -- previous key, still accepted during the rotation grace window
	prev_key_expires_at INTEGER NOT NULL DEFAULT 0, -- grace deadline for prev_key_hash (0 = none)
	app_version TEXT NOT NULL DEFAULT ''           -- running binary build version the node last reported
);
CREATE TABLE IF NOT EXISTS enroll_keys (
	id TEXT PRIMARY KEY,                     -- uuid
	name TEXT NOT NULL DEFAULT '',           -- admin-facing description
	key_hash TEXT NOT NULL,                  -- sha256 of the secret (the secret itself is never stored)
	key_prefix TEXT NOT NULL DEFAULT '',     -- first 8 chars, for display
	created_at INTEGER NOT NULL DEFAULT 0,
	created_by TEXT NOT NULL DEFAULT '',     -- username that created it
	expires_at INTEGER NOT NULL DEFAULT 0,   -- unix secs, 0 = never
	max_uses INTEGER NOT NULL DEFAULT 0,     -- 0 = unlimited
	use_count INTEGER NOT NULL DEFAULT 0,
	revoked INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_enroll_keys_hash ON enroll_keys(key_hash);
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
	note TEXT NOT NULL DEFAULT '',         -- operator review note (why allowed/blocked)
	updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_classifications_status ON classifications(status);
CREATE TABLE IF NOT EXISTS llm_usage (
	day TEXT PRIMARY KEY,                        -- UTC date (YYYY-MM-DD)
	calls INTEGER NOT NULL DEFAULT 0,
	errors INTEGER NOT NULL DEFAULT 0,
	prompt_tokens INTEGER NOT NULL DEFAULT 0,
	completion_tokens INTEGER NOT NULL DEFAULT 0,
	latency_ms_total INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sites (
	name TEXT PRIMARY KEY,
	description TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reputation_usage (
	day TEXT NOT NULL,                           -- UTC date (YYYY-MM-DD)
	service TEXT NOT NULL,                        -- 'virustotal' | 'abuseipdb'
	calls INTEGER NOT NULL DEFAULT 0,
	errors INTEGER NOT NULL DEFAULT 0,
	rate_limited INTEGER NOT NULL DEFAULT 0,      -- count of 429 (quota) responses
	remaining INTEGER NOT NULL DEFAULT -1,        -- last API-reported quota remaining (-1 = unknown)
	limit_total INTEGER NOT NULL DEFAULT -1,      -- last API-reported daily limit (-1 = unknown)
	PRIMARY KEY (day, service)
);
-- Tombstones for revoked nodes: an admin "remove and revoke" writes the deleted
-- node's id here so a still-running agent presenting that id at re-enrollment is
-- refused (instead of self-healing into a brand-new node). Un-revoke deletes the row.
CREATE TABLE IF NOT EXISTS revoked_nodes (
	id TEXT PRIMARY KEY,                          -- the revoked node's immutable UUID
	name TEXT NOT NULL DEFAULT '',                -- its display name at revocation (for the UI/log)
	revoked_at INTEGER NOT NULL DEFAULT 0,
	revoked_by TEXT NOT NULL DEFAULT ''           -- admin username that revoked it
);
`

func (s *Store) migrate() error {
	// Run the schema one statement at a time (Postgres rejects multi-statement
	// Exec), adapting the DDL dialect when the backend is Postgres.
	schema := sqliteSchema
	if s.db.pg {
		schema = toPostgresSchema(sqliteSchema)
	}
	for _, stmt := range splitStatements(schema) {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
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
		`ALTER TABLE classifications ADD COLUMN note TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN maintenance INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN site TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN role TEXT NOT NULL DEFAULT ''`, // '' | 'primary' | 'backup'
		`ALTER TABLE nodes ADD COLUMN approved INTEGER NOT NULL DEFAULT 1`,
		// Immutable UUID identity. Existing rows are backfilled below (fresh DBs get
		// id as the PRIMARY KEY from the canonical schema); name becomes a mutable,
		// unique display label rather than the identifier.
		`ALTER TABLE nodes ADD COLUMN id TEXT NOT NULL DEFAULT ''`,
		// Per-node key rotation: age of the current key + a grace overlap for the
		// previous key so a server-driven rotation is zero-downtime.
		`ALTER TABLE nodes ADD COLUMN key_issued_at INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN prev_key_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN prev_key_expires_at INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN app_version TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(alter); err != nil && !isDuplicateColumn(err) {
			return fmt.Errorf("migrate alter: %w", err)
		}
	}
	if err := s.backfillNodeIDs(); err != nil {
		return fmt.Errorf("migrate node ids: %w", err)
	}
	// Start the key-rotation clock at upgrade time for nodes that already have a key
	// (key_issued_at defaults to 0 = epoch, which would make every existing node
	// rotate-due on its first poll). Idempotent: once set (non-zero) it is skipped.
	if _, err := s.db.Exec(
		`UPDATE nodes SET key_issued_at=? WHERE key_issued_at=0 AND key_hash<>''`, time.Now().Unix()); err != nil {
		return fmt.Errorf("migrate key_issued_at: %w", err)
	}
	// A node's id is its identity; name is now a mutable unique label. On DBs
	// created before the id column existed, name is still the declared PRIMARY KEY —
	// these indexes give id and name the same UNIQUE guarantees the canonical schema
	// declares, so all id-keyed queries behave identically on old and new DBs.
	// Collapse duplicate OIDC accounts sharing a subject — an artifact of the old
	// username-keyed upsert (the same IdP identity could spawn multiple rows) — so
	// the unique subject index below can be created. Keep the newest row per subject
	// (MAX(id)); rows with an empty subject (pathological) are left untouched.
	// Idempotent: with no duplicates it deletes nothing.
	if _, err := s.db.Exec(
		`DELETE FROM users WHERE source='oidc' AND subject <> '' AND id NOT IN (
			SELECT MAX(id) FROM users WHERE source='oidc' AND subject <> '' GROUP BY subject)`); err != nil {
		return fmt.Errorf("migrate dedupe oidc users: %w", err)
	}
	for _, idx := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_id ON nodes(id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name)`,
		// SSO identities are keyed on the stable subject, not the mutable username.
		// A partial unique index enforces one account per (non-empty) OIDC subject
		// while leaving local users (source='local', subject='') unconstrained.
		// Portable across SQLite and Postgres.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_subject ON users(subject) WHERE source='oidc' AND subject <> ''`,
	} {
		if _, err := s.db.Exec(idx); err != nil {
			return fmt.Errorf("migrate node index: %w", err)
		}
	}
	return nil
}

// backfillNodeIDs assigns a UUIDv4 to any node row that predates the id column
// (id=”), preserving the row's key/stats/site/role/approval. Idempotent: once a
// row has an id the WHERE clause skips it, so re-running across restarts is a
// no-op. UUIDs are generated in Go because SQLite/Postgres have no portable
// built-in.
func (s *Store) backfillNodeIDs() error {
	rows, err := s.read.Query(`SELECT name FROM nodes WHERE id = ''`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, name := range names {
		if _, err := s.db.Exec(`UPDATE nodes SET id = ? WHERE name = ? AND id = ''`, uuid.NewString(), name); err != nil {
			return err
		}
	}
	return nil
}

// ListRules returns all rules ordered by domain.
func (s *Store) ListRules() ([]Rule, error) {
	rows, err := s.read.Query(`SELECT id, action, domain, category, enabled, list_id, updated_at FROM rules ORDER BY domain`)
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
	err := s.read.QueryRow(`SELECT id FROM rules WHERE action=? AND domain=?`, action, domain).Scan(&id)
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
	rows, err := s.read.Query(`SELECT id, domain, rrtype, value, enabled, updated_at FROM rewrites ORDER BY domain`)
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
	err := s.read.QueryRow(`SELECT id FROM rewrites WHERE domain=? AND rrtype=?`, domain, rrtype).Scan(&id)
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
