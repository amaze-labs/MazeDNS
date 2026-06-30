package store

import (
	"errors"
	"strings"
	"testing"
)

func TestRebindPlaceholders(t *testing.T) {
	cases := map[string]string{
		"SELECT * FROM t WHERE a=? AND b=?":  "SELECT * FROM t WHERE a=$1 AND b=$2",
		"INSERT INTO t(a,b,c) VALUES(?,?,?)": "INSERT INTO t(a,b,c) VALUES($1,$2,$3)",
		"SELECT 1":                           "SELECT 1", // no placeholders
	}
	for in, want := range cases {
		if got := rebindPlaceholders(in); got != want {
			t.Errorf("rebind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTranslate(t *testing.T) {
	q := "SELECT COALESCE(SUM(action='blocked'),0), SUM(action='cache') FROM query_log WHERE ts >= ? AND client = ?"

	// SQLite: untouched.
	if got := translate(q, false); got != q {
		t.Errorf("sqlite translate changed the query:\n%s", got)
	}

	// Postgres: boolean aggregates become CASE, placeholders become $N, and a
	// WHERE-clause boolean comparison is left alone.
	got := translate(q, true)
	for _, want := range []string{
		"SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END)",
		"SUM(CASE WHEN action='cache' THEN 1 ELSE 0 END)",
		"ts >= $1 AND client = $2",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("postgres translate missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "SUM(action=") {
		t.Errorf("postgres translate left a bare boolean aggregate:\n%s", got)
	}
}

func TestToPostgresSchema(t *testing.T) {
	pg := toPostgresSchema(sqliteSchema)
	if strings.Contains(pg, "AUTOINCREMENT") {
		t.Error("AUTOINCREMENT should be rewritten to BIGSERIAL")
	}
	if !strings.Contains(pg, "BIGSERIAL PRIMARY KEY") {
		t.Error("expected BIGSERIAL PRIMARY KEY in the postgres schema")
	}
	if strings.Contains(pg, "WITHOUT ROWID") {
		t.Error("WITHOUT ROWID is SQLite-only and must be stripped")
	}
	if strings.Contains(pg, " REAL ") {
		t.Error("REAL should be rewritten to DOUBLE PRECISION")
	}
	// The portable seed form must survive in both dialects.
	if !strings.Contains(pg, "ON CONFLICT(key) DO NOTHING") {
		t.Error("expected the portable seed upsert in the postgres schema")
	}
}

func TestSplitStatements(t *testing.T) {
	stmts := splitStatements(sqliteSchema)
	if len(stmts) < 15 {
		t.Errorf("expected the schema to split into many statements, got %d", len(stmts))
	}
	for _, s := range stmts {
		if strings.TrimSpace(s) == "" {
			t.Error("split produced an empty statement")
		}
	}
	// A comment-only chunk must be dropped, a real one kept.
	got := splitStatements("-- just a comment\n;\nCREATE TABLE x(a int);\n")
	if len(got) != 1 || !strings.Contains(got[0], "CREATE TABLE x") {
		t.Errorf("splitStatements dropped/kept wrong chunks: %#v", got)
	}
}

func TestIsDuplicateColumn(t *testing.T) {
	if !isDuplicateColumn(errors.New("duplicate column name: foo")) { // sqlite
		t.Error("sqlite duplicate-column error not recognised")
	}
	if !isDuplicateColumn(errors.New(`pq: column "foo" of relation "bar" already exists`)) { // postgres
		t.Error("postgres already-exists error not recognised")
	}
	if isDuplicateColumn(errors.New("syntax error near FROM")) {
		t.Error("unrelated error wrongly treated as duplicate column")
	}
}
