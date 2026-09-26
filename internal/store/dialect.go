package store

import (
	"database/sql"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// The store is written in the SQLite dialect (which is also the default backend).
// To also support PostgreSQL without touching the ~hundreds of call sites, every
// query passes through a thin wrapper that, only when the backend is Postgres:
//
//   - rebinds `?` placeholders to `$1, $2, …` (Postgres' numbered form), and
//   - rewrites SQLite's boolean-as-integer aggregates `SUM(col='x')` to the
//     portable `SUM(CASE WHEN col='x' THEN 1 ELSE 0 END)` (Postgres won't SUM a
//     boolean).
//
// Booleans themselves need no special handling: they are stored in INTEGER 0/1
// columns on both backends, and database/sql's convertAssign bridges int64↔bool
// transparently on read, so existing scans into Go bool keep working.

// boolAggRE matches a bare boolean-equality aggregate like SUM(action='blocked').
// It deliberately does not touch WHERE-clause comparisons (those are fine in
// Postgres) or aggregates already written as SUM(CASE WHEN …).
var boolAggRE = regexp.MustCompile(`SUM\(([a-z_]+)='([a-z]+)'\)`)

// translate adapts a SQLite-dialect query to the active backend.
func translate(query string, pg bool) string {
	if !pg {
		return query
	}
	query = boolAggRE.ReplaceAllString(query, "SUM(CASE WHEN $1='$2' THEN 1 ELSE 0 END)")
	return rebindPlaceholders(query)
}

// rebindPlaceholders converts ordinal `?` placeholders to Postgres' `$1, $2, …`.
// MazeDNS never uses a literal `?` inside SQL strings, so a plain scan is safe.
func rebindPlaceholders(query string) string {
	if !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		} else {
			b.WriteByte(query[i])
		}
	}
	return b.String()
}

// configTablesRE matches the tables whose content feeds the replicated config
// version (store.ConfigVersionForNode): rules and lists (ActiveRules),
// classifications (enforced AI verdicts), rewrites, and forwarders.
var configTablesRE = regexp.MustCompile(`(?i)\b(rules|lists|classifications|rewrites|forwarders)\b`)

// isConfigWrite reports whether a statement may modify a table that feeds the
// config version. It is deliberately conservative: anything that is not a
// plain SELECT and names one of those tables counts. A statement can only
// modify a table it names (the schema has no triggers and no cascading
// foreign keys), so no config write is missed; a false positive merely costs
// one cache recomputation.
func isConfigWrite(q string) bool {
	t := strings.TrimLeft(q, " \t\r\n")
	if len(t) >= 6 && strings.EqualFold(t[:6], "SELECT") {
		return false
	}
	return configTablesRE.MatchString(q)
}

// dbh wraps a *sql.DB and applies dialect translation on every call, so the rest
// of the store can keep writing SQLite-dialect SQL with `?` placeholders.
//
// It is also the choke point every write passes through, which is where the
// config generation (gen) is bumped: after any statement that may change the
// replicated config completes — for a transaction, after it commits — so the
// cached per-node config versions (configcache.go) are invalidated no matter
// which store method did the write. Bumping only after the change is visible
// is what makes the cache safe; see versionCache.
type dbh struct {
	*sql.DB
	pg  bool
	gen *atomic.Uint64 // shared config generation (nil = not tracked)
}

func (d *dbh) bumpIf(q string) {
	if d.gen != nil && isConfigWrite(q) {
		d.gen.Add(1)
	}
}

func (d *dbh) Exec(q string, a ...any) (sql.Result, error) {
	res, err := d.DB.Exec(translate(q, d.pg), a...)
	d.bumpIf(q) // even on error: a partial effect must not leave a stale cache
	return res, err
}

// execUntracked runs a statement without bumping the config generation. Only
// for writes proven not to change the replicated config (see
// InsertClassification); everything else goes through Exec.
func (d *dbh) execUntracked(q string, a ...any) (sql.Result, error) {
	return d.DB.Exec(translate(q, d.pg), a...)
}

// Query and QueryRow bump on a config write too, but a write through them (only
// INSERT ... RETURNING, see insertID) may not be complete when they return;
// such callers bump again once they have read the result.
func (d *dbh) Query(q string, a ...any) (*sql.Rows, error) {
	rows, err := d.DB.Query(translate(q, d.pg), a...)
	d.bumpIf(q)
	return rows, err
}
func (d *dbh) QueryRow(q string, a ...any) *sql.Row {
	row := d.DB.QueryRow(translate(q, d.pg), a...)
	d.bumpIf(q)
	return row
}

func (d *dbh) Begin() (*txh, error) {
	tx, err := d.DB.Begin()
	if err != nil {
		return nil, err
	}
	return &txh{Tx: tx, pg: d.pg, gen: d.gen}, nil
}

// txh is the transaction-scoped equivalent of dbh. A config write inside the
// transaction marks it dirty; the generation is bumped once it commits, never
// before (a bump before the data is visible could let a concurrent reader
// cache the old content under the new generation).
type txh struct {
	*sql.Tx
	pg    bool
	gen   *atomic.Uint64
	dirty bool
}

func (t *txh) mark(q string) {
	if isConfigWrite(q) {
		t.dirty = true
	}
}

func (t *txh) Exec(q string, a ...any) (sql.Result, error) {
	t.mark(q)
	return t.Tx.Exec(translate(q, t.pg), a...)
}
func (t *txh) Query(q string, a ...any) (*sql.Rows, error) {
	t.mark(q)
	return t.Tx.Query(translate(q, t.pg), a...)
}
func (t *txh) QueryRow(q string, a ...any) *sql.Row {
	t.mark(q)
	return t.Tx.QueryRow(translate(q, t.pg), a...)
}

// Prepare marks the transaction dirty up front: statements executed through the
// returned *sql.Stmt bypass the wrapper.
func (t *txh) Prepare(q string) (*sql.Stmt, error) {
	t.mark(q)
	return t.Tx.Prepare(translate(q, t.pg))
}

// Commit commits and then bumps the config generation if the transaction wrote
// a config table (even when Commit reports an error — being conservative only
// costs a recomputation).
func (t *txh) Commit() error {
	err := t.Tx.Commit()
	if t.dirty && t.gen != nil {
		t.gen.Add(1)
	}
	return err
}

// toPostgresSchema rewrites the SQLite DDL into its PostgreSQL equivalent: the
// auto-increment column type, the float type, and dropping SQLite's WITHOUT
// ROWID optimisation (the seed INSERTs already use the portable ON CONFLICT form).
func toPostgresSchema(schema string) string {
	r := schema
	r = strings.ReplaceAll(r, "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
	r = strings.ReplaceAll(r, ") WITHOUT ROWID", ")")
	r = strings.ReplaceAll(r, " REAL ", " DOUBLE PRECISION ")
	return r
}

// splitStatements breaks a multi-statement DDL script into individual statements.
// Postgres' extended protocol (pgx) rejects multiple statements per Exec, so each
// is run separately; comment-only / blank chunks are skipped. MazeDNS' schema has
// no `;` inside string literals, so a simple split is safe.
func splitStatements(script string) []string {
	var out []string
	for _, part := range strings.Split(script, ";") {
		hasSQL := false
		for _, line := range strings.Split(part, "\n") {
			l := strings.TrimSpace(line)
			if l != "" && !strings.HasPrefix(l, "--") {
				hasSQL = true
				break
			}
		}
		if hasSQL {
			out = append(out, strings.TrimSpace(part))
		}
	}
	return out
}

// isDuplicateColumn reports whether an ALTER TABLE ADD COLUMN failed only because
// the column already exists — the additive-migration no-op on both backends.
func isDuplicateColumn(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists")
}
