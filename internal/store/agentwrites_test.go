package store

import (
	"path/filepath"
	"sort"
	"testing"
)

// queryLogIndexNames lists the secondary indexes on query_log.
func queryLogIndexNames(t *testing.T, s *Store) []string {
	t.Helper()
	q := `SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'query_log' AND name LIKE 'idx_%'`
	if s.db.pg {
		q = `SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND tablename = 'query_log' AND indexname LIKE 'idx_%'`
	}
	rows, err := s.read.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// An agent's query log is an outbox read only by id, so its store keeps no
// secondary indexes on it; opening an existing database as an agent drops
// them, and opening it normally (the control plane) brings them back.
func TestAgentStoreDropsQueryLogIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := queryLogIndexNames(t, s); len(got) != 4 {
		t.Fatalf("control-plane store: query_log indexes = %v, want 4", got)
	}
	_ = s.Close()

	s, err = Open(path, WithoutQueryLogIndexes())
	if err != nil {
		t.Fatal(err)
	}
	if got := queryLogIndexNames(t, s); len(got) != 0 {
		t.Fatalf("agent store: query_log indexes = %v, want none", got)
	}
	// The outbox operations still work without them.
	if err := s.InsertQueryLogBatch([]QueryLogEntry{{TS: 1, Name: "a.example", QType: "A", Action: "forward"}, {TS: 2, Name: "b.example", QType: "A", Action: "blocked"}}); err != nil {
		t.Fatal(err)
	}
	got, maxID, err := s.QueryLogSince(0, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("QueryLogSince = %d entries, %v", len(got), err)
	}
	if err := s.DeleteQueryLogThrough(maxID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountQueryLog(); n != 0 {
		t.Fatalf("after delete: %d rows left", n)
	}
	_ = s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := queryLogIndexNames(t, s); len(got) != 4 {
		t.Fatalf("reopened as control plane: query_log indexes = %v, want 4", got)
	}
}
