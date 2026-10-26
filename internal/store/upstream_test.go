package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openUpstreamStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func advanceAll(t *testing.T, s *Store) {
	t.Helper()
	for more := true; more; {
		var err error
		if more, err = s.RollupAdvance(1000); err != nil {
			t.Fatal(err)
		}
	}
}

// The upstream that answered a query survives the agent's own log, shipping
// (QueryLogSince → InsertNodeQueryLog) and the Queries search, which can filter
// by it.
func TestQueryLogUpstreamRoundTrip(t *testing.T) {
	agent := openUpstreamStore(t)
	now := time.Now().UnixMilli()
	if err := agent.InsertQueryLogBatch([]QueryLogEntry{
		{TS: now, Client: "10.0.0.2", Name: "a.example.", QType: "A", Action: "forward", Rcode: "NOERROR", Upstream: "1.1.1.1"},
		{TS: now, Client: "10.0.0.2", Name: "db.corp.internal.", QType: "A", Action: "forward", Rcode: "NOERROR",
			Upstream: "10.0.0.53", Forwarder: "corp.internal"},
		{TS: now, Client: "10.0.0.2", Name: "a.example.", QType: "A", Action: "cache", Rcode: "NOERROR"},
	}); err != nil {
		t.Fatal(err)
	}
	shipped, _, err := agent.QueryLogSince(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(shipped) != 3 || shipped[0].Upstream != "1.1.1.1" || shipped[1].Forwarder != "corp.internal" || shipped[1].Upstream != "10.0.0.53" {
		t.Fatalf("agent log lost the upstream: %+v", shipped)
	}

	cp := openUpstreamStore(t)
	if err := cp.InsertNodeQueryLog("dns1", shipped); err != nil {
		t.Fatal(err)
	}
	all, total, err := cp.SearchQueryLog(QueryLogQuery{})
	if err != nil || total != 3 {
		t.Fatalf("search: %d rows, err %v", total, err)
	}
	for _, e := range all {
		if e.Name == "db.corp.internal." && (e.Upstream != "10.0.0.53" || e.Forwarder != "corp.internal") {
			t.Errorf("stored entry lost the upstream: %+v", e)
		}
	}
	for _, tc := range []struct {
		q    QueryLogQuery
		want int64
	}{
		{QueryLogQuery{Upstream: "1.1.1.1"}, 1},
		{QueryLogQuery{Upstream: "10.0.0.53", Forwarder: "corp.internal"}, 1},
		{QueryLogQuery{Upstream: "10.0.0.53", Forwarder: ""}, 1}, // "" = any forwarder
		{QueryLogQuery{Upstream: "9.9.9.9"}, 0},
	} {
		if _, n, err := cp.SearchQueryLog(tc.q); err != nil || n != tc.want {
			t.Errorf("search %+v: %d rows, err %v; want %d", tc.q, n, err, tc.want)
		}
	}
	if got, _, _ := cp.SearchQueryLog(QueryLogQuery{Sort: "upstream", Desc: true, Limit: 1}); len(got) != 1 || got[0].Upstream != "10.0.0.53" {
		t.Errorf("sort by upstream: %+v", got)
	}
}

// The upstream breakdown counts forwarded queries per (forwarder, upstream)
// with their mean latency, within the window and node filter; forwards from an
// agent that doesn't report upstreams count under an empty upstream.
func TestRollupByUpstream(t *testing.T) {
	s := openUpstreamStore(t)
	now := time.Now().UnixMilli()
	old := now - 3*time.Hour.Milliseconds()
	fwd := func(ts int64, up, fw string, ms float64) QueryLogEntry {
		return QueryLogEntry{TS: ts, Client: "c", Name: "x.", QType: "A", Action: "forward", Rcode: "NOERROR",
			Upstream: up, Forwarder: fw, ElapsedMS: ms}
	}
	if err := s.InsertNodeQueryLog("dns1", []QueryLogEntry{
		fwd(now, "1.1.1.1", "", 10), fwd(now, "1.1.1.1", "", 20), fwd(now, "9.9.9.9", "", 30),
		fwd(now, "10.0.0.53", "corp.internal", 2),
		fwd(old, "9.9.9.9", "", 5), // before the window
		{TS: now, Client: "c", Name: "x.", Action: "cache", Rcode: "NOERROR", ElapsedMS: 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertNodeQueryLog("dns2", []QueryLogEntry{fwd(now, "1.1.1.1", "", 40), fwd(now, "", "", 50)}); err != nil {
		t.Fatal(err)
	}
	advanceAll(t, s)
	advanceAll(t, s) // idempotent

	type key struct{ fw, up string }
	check := func(nodes []string, want map[key][2]float64) {
		t.Helper()
		got, err := s.RollupByUpstream(now-time.Hour.Milliseconds(), nodes)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Errorf("nodes %v: %+v, want %v", nodes, got, want)
		}
		for i, u := range got {
			w, ok := want[key{u.Forwarder, u.Upstream}]
			if !ok || float64(u.Count) != w[0] || u.AvgLatencyMS != w[1] {
				t.Errorf("nodes %v: %+v, want %v", nodes, u, w)
			}
			if i > 0 && got[i-1].Count < u.Count {
				t.Errorf("nodes %v: not busiest first: %+v", nodes, got)
			}
		}
	}
	check(nil, map[key][2]float64{
		{"", "1.1.1.1"}:                {3, 70.0 / 3},
		{"", "9.9.9.9"}:                {1, 30},
		{"corp.internal", "10.0.0.53"}: {1, 2},
		{"", ""}:                       {1, 50},
	})
	check([]string{"dns1"}, map[key][2]float64{
		{"", "1.1.1.1"}:                {2, 15},
		{"", "9.9.9.9"}:                {1, 30},
		{"corp.internal", "10.0.0.53"}: {1, 2},
	})

	// Pruned with the other rollups, and kept under a renamed node.
	id, err := s.CreateNode("dns2", "hash2", "pref2")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RenameNode(id, "dns2-new"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.RollupByUpstream(now-time.Hour.Milliseconds(), []string{"dns2-new"}); len(got) != 2 {
		t.Errorf("after rename: %+v, want dns2's 2 upstreams", got)
	}
	if err := s.PruneRollups(now + time.Hour.Milliseconds()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.RollupByUpstream(0, nil); len(got) != 0 {
		t.Errorf("after prune: %+v", got)
	}
}
