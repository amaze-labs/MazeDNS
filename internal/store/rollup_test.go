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

// The series must reach the bucket that is still filling: traffic from the last
// few minutes has to show up on the chart (not only in the totals).
func TestRollupSeriesIncludesCurrentBucket(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	entry := func(ts int64, action string) QueryLogEntry {
		return QueryLogEntry{TS: ts, Client: "10.0.0.1", Name: "example.com.", QType: "A", Action: action, Rcode: "NOERROR", ElapsedMS: 4}
	}
	// One query an hour ago, three right now (in the current, in-progress bucket).
	if err := s.InsertNodeQueryLog("w1", []QueryLogEntry{
		entry(now.Add(-time.Hour).UnixMilli(), "forward"),
		entry(now.UnixMilli(), "cache"), entry(now.UnixMilli(), "cache"), entry(now.UnixMilli(), "blocked"),
	}); err != nil {
		t.Fatal(err)
	}
	for {
		more, err := s.RollupAdvance(100)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
	}

	const step = 1800
	since := now.Add(-24 * time.Hour).UnixMilli()
	curBucket := (now.Unix() / step) * step

	pts, err := s.RollupTimeSeries(since, step, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) == 0 {
		t.Fatal("empty series")
	}
	last := pts[len(pts)-1]
	if last.TS != curBucket {
		t.Fatalf("last bucket ts = %d, want the current bucket %d", last.TS, curBucket)
	}
	if last.Total != 3 || last.Cached != 2 || last.Blocked != 1 {
		t.Errorf("current bucket = %+v, want total 3 (2 cached, 1 blocked)", last)
	}
	var sum int64
	for _, p := range pts {
		sum += p.Total
	}
	if sum != 4 {
		t.Errorf("series sums to %d queries, want all 4", sum)
	}
	// Buckets are contiguous and step-spaced up to now.
	for i := 1; i < len(pts); i++ {
		if pts[i].TS-pts[i-1].TS != step {
			t.Fatalf("gap between buckets %d and %d", pts[i-1].TS, pts[i].TS)
		}
	}

	lat, names, err := s.RollupLatency(since, step, nil)
	if err != nil {
		t.Fatal(err)
	}
	ll := lat[len(lat)-1]
	if ll.TS != curBucket {
		t.Fatalf("last latency bucket ts = %d, want the current bucket %d", ll.TS, curBucket)
	}
	if ll.Overall != 4 || ll.ByNode["w1"] != 4 {
		t.Errorf("current latency bucket = %+v, want 4 ms overall and for w1", ll)
	}
	if len(names) != 1 || names[0] != "w1" {
		t.Errorf("latency nodes = %v, want [w1]", names)
	}
	if len(lat) != len(pts) {
		t.Errorf("latency has %d buckets, traffic %d — they should line up", len(lat), len(pts))
	}
}

func TestSeriesBounds(t *testing.T) {
	now := time.Unix(10_000, 0) // exactly the start of the bucket 10000 (step 1000)
	start, end := seriesBounds(2_500_000, 1000, now)
	if start != 2000 || end != 10_000 {
		t.Errorf("bounds = %d..%d, want 2000..10000", start, end)
	}
	now = time.Unix(10_999, 0)
	if _, end = seriesBounds(2_500_000, 1000, now); end != 10_000 {
		t.Errorf("end = %d, want the in-progress bucket 10000", end)
	}
	// A window starting in the future collapses to one bucket instead of a negative range.
	if start, end = seriesBounds(20_000_000, 1000, now); start != 20_000 || end != 20_000 {
		t.Errorf("future window bounds = %d..%d, want 20000..20000", start, end)
	}
}
