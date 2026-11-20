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

// ApplySnapshot writes only what changed: rules it already holds keep their
// rows (and ids), a changed rule is replaced, a dropped one removed, a new one
// added.
func TestApplySnapshotWritesOnlyTheDifference(t *testing.T) {
	s := openTestStore(t)
	before := []Rule{
		{Action: "deny", Domain: "keep.example", Category: "ads", Enabled: true},
		{Action: "deny", Domain: "recat.example", Category: "ads", Enabled: true},
		{Action: "deny", Domain: "toggle.example", Category: "ads", Enabled: true},
		{Action: "deny", Domain: "drop.example", Category: "ads", Enabled: true},
		{Action: "allow", Domain: "keep.example", Category: "custom", Enabled: true},
	}
	if err := s.ApplySnapshot(before, nil); err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(t, s)
	if _, err := s.RecordLocalConfigVersion(); err != nil {
		t.Fatal(err)
	}

	after := []Rule{
		{Action: "deny", Domain: "keep.example", Category: "ads", Enabled: true},
		{Action: "deny", Domain: "recat.example", Category: "malware", Enabled: true},
		{Action: "deny", Domain: "toggle.example", Category: "ads", Enabled: false},
		{Action: "allow", Domain: "keep.example", Category: "custom", Enabled: true},
		{Action: "deny", Domain: "new.example", Category: "", Enabled: true}, // "" is stored as custom
	}
	if err := s.ApplySnapshot(after, nil); err != nil {
		t.Fatal(err)
	}
	got := ruleIDs(t, s)
	for _, k := range []string{"deny keep.example", "allow keep.example"} {
		if got[k] != ids[k] {
			t.Errorf("%s: id %d -> %d, an unchanged rule must keep its row", k, ids[k], got[k])
		}
	}
	for _, k := range []string{"deny recat.example", "deny toggle.example"} {
		if got[k] == 0 || got[k] == ids[k] {
			t.Errorf("%s: id %d -> %d, a changed rule must be replaced", k, ids[k], got[k])
		}
	}
	if _, ok := got["deny drop.example"]; ok {
		t.Error("a rule missing from the snapshot must be removed")
	}
	if len(got) != len(after) {
		t.Fatalf("rules after apply = %v, want %d", got, len(after))
	}

	rules, err := s.ListRules()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"deny keep.example": "ads true", "deny recat.example": "malware true", "deny toggle.example": "ads false",
		"allow keep.example": "custom true", "deny new.example": "custom true",
	}
	for _, r := range rules {
		k := r.Action + " " + r.Domain
		if w := want[k]; w != r.Category+" "+boolStr(r.Enabled) {
			t.Errorf("%s = %s %v, want %s", k, r.Category, r.Enabled, w)
		}
	}
	// The fingerprint still sees the apply (the persisted version is not
	// reused for tables an apply changed).
	if got, want := mustLocalVersion(t, s), mustConfigVersion(t, s); got != want {
		t.Errorf("LocalConfigVersion = %q, ConfigVersion = %q", got, want)
	}
}

func mustLocalVersion(t *testing.T, s *Store) string {
	t.Helper()
	v, err := s.LocalConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustConfigVersion(t *testing.T, s *Store) string {
	t.Helper()
	v, err := s.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func ruleIDs(t *testing.T, s *Store) map[string]int64 {
	t.Helper()
	rules, err := s.ListRules()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]int64{}
	for _, r := range rules {
		m[r.Action+" "+r.Domain] = r.ID
	}
	return m
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
