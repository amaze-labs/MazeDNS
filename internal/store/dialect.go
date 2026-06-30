package store

import (
	"database/sql"
	"regexp"
	"strconv"
	"strings"
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

// dbh wraps a *sql.DB and applies dialect translation on every call, so the rest
// of the store can keep writing SQLite-dialect SQL with `?` placeholders.
type dbh struct {
	*sql.DB
	pg bool
}

func (d *dbh) Exec(q string, a ...any) (sql.Result, error) {
	return d.DB.Exec(translate(q, d.pg), a...)
}
func (d *dbh) Query(q string, a ...any) (*sql.Rows, error) {
	return d.DB.Query(translate(q, d.pg), a...)
}
func (d *dbh) QueryRow(q string, a ...any) *sql.Row { return d.DB.QueryRow(translate(q, d.pg), a...) }

func (d *dbh) Begin() (*txh, error) {
	tx, err := d.DB.Begin()
	if err != nil {
		return nil, err
	}
	return &txh{Tx: tx, pg: d.pg}, nil
}

// txh is the transaction-scoped equivalent of dbh.
type txh struct {
	*sql.Tx
	pg bool
}

func (t *txh) Exec(q string, a ...any) (sql.Result, error) {
	return t.Tx.Exec(translate(q, t.pg), a...)
}
func (t *txh) Query(q string, a ...any) (*sql.Rows, error) {
	return t.Tx.Query(translate(q, t.pg), a...)
}
func (t *txh) QueryRow(q string, a ...any) *sql.Row { return t.Tx.QueryRow(translate(q, t.pg), a...) }
func (t *txh) Prepare(q string) (*sql.Stmt, error)  { return t.Tx.Prepare(translate(q, t.pg)) }

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
