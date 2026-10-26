package store

import (
	"path/filepath"
	"testing"
	"time"
)

// ClientNodes picks, per client, the node that served it the most queries in
// the window (the master's own entries as "master"), from the client rollup.
func TestClientNodes(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UnixMilli()
	q := func(ts int64, client string) QueryLogEntry {
		return QueryLogEntry{TS: ts, Client: client, Name: "example.com.", QType: "A", Action: "forward", Rcode: "NOERROR"}
	}
	old := now - 3*time.Hour.Milliseconds()
	if err := s.InsertNodeQueryLog("w1", []QueryLogEntry{q(now, "10.0.0.1"), q(now, "10.0.0.2"),
		q(old, "10.0.0.3"), q(old, "10.0.0.3")}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertNodeQueryLog("w2", []QueryLogEntry{q(now, "10.0.0.1"), q(now, "10.0.0.1"),
		q(now, "10.0.0.3")}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertQueryLogBatch([]QueryLogEntry{q(now, "10.0.0.4")}); err != nil {
		t.Fatal(err)
	}
	for more := true; more; {
		if more, err = s.RollupAdvance(1000); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.ClientNodes(now - time.Hour.Milliseconds())
	if err != nil {
		t.Fatal(err)
	}
	// 10.0.0.3's w1 queries are before the window: only w2 counts.
	want := map[string]string{"10.0.0.1": "w2", "10.0.0.2": "w1", "10.0.0.3": "w2", "10.0.0.4": "master"}
	if len(got) != len(want) {
		t.Errorf("ClientNodes = %v, want %v", got, want)
	}
	for c, n := range want {
		if got[c] != n {
			t.Errorf("%s -> %q, want %q (all: %v)", c, got[c], n, got)
		}
	}
}
