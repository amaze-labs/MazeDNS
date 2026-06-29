package store

import (
	"path/filepath"
	"testing"
	"time"
)

// The rollups must agree with the raw-log aggregations they replace, and the
// incremental advance must not double-count when run repeatedly.
func TestRollupMatchesRaw(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UnixMilli()
	mk := func(client, action string, ms float64) QueryLogEntry {
		return QueryLogEntry{TS: now, Client: client, Name: "example.com.", QType: "A", Action: action, Rcode: "NOERROR", ElapsedMS: ms}
	}
	// master entries (node "")
	if err := s.InsertQueryLogBatch([]QueryLogEntry{
		mk("10.0.0.1", "forward", 20), mk("10.0.0.1", "cache", 1),
		mk("10.0.0.2", "blocked", 5), mk("10.0.0.3", "forward", 30),
	}); err != nil {
		t.Fatal(err)
	}
	// a worker's entries (node "w1")
	if err := s.InsertNodeQueryLog("w1", []QueryLogEntry{
		mk("10.0.0.4", "forward", 40), mk("10.0.0.2", "cache", 2),
	}); err != nil {
		t.Fatal(err)
	}

	// Advance fully (and again — must be idempotent, no double count).
	for {
		more, err := s.RollupAdvance(100)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
	}
	if more, _ := s.RollupAdvance(100); more {
		t.Fatal("rollup reported more work after catching up")
	}

	since := now - time.Hour.Milliseconds()

	raw, _ := s.WindowSummary(since, nil)
	roll, _ := s.RollupSummary(since, nil)
	if roll.Totals != raw.Totals {
		t.Errorf("totals: rollup %+v != raw %+v", roll.Totals, raw.Totals)
	}
	if roll.UniqueClients != raw.UniqueClients {
		t.Errorf("unique clients: rollup %d != raw %d", roll.UniqueClients, raw.UniqueClients)
	}
	if d := roll.AvgLatencyMS - raw.AvgLatencyMS; d > 0.001 || d < -0.001 {
		t.Errorf("avg latency: rollup %.3f != raw %.3f", roll.AvgLatencyMS, raw.AvgLatencyMS)
	}

	rawClients, _ := s.QueriesByClient(since, 12, nil)
	rollClients, _ := s.RollupTopClients(since, 12, nil)
	if len(rollClients) != len(rawClients) {
		t.Fatalf("top clients count: rollup %d != raw %d", len(rollClients), len(rawClients))
	}

	rawNode, _ := s.QueriesByNode(since, nil)
	rollNode, _ := s.RollupByNode(since, nil)
	if len(rollNode) != len(rawNode) {
		t.Fatalf("by-node count: rollup %d != raw %d", len(rollNode), len(rawNode))
	}

	// Node focus filter works on the rollup (only the worker's traffic).
	rollW1, _ := s.RollupSummary(since, []string{"w1"})
	if rollW1.Totals.Total != 2 {
		t.Errorf("node-filtered rollup total = %d, want 2", rollW1.Totals.Total)
	}
}
