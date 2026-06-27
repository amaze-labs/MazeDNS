package store

import (
	"path/filepath"
	"testing"
	"time"
)

func seedLog(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Now().UnixMilli()
	entries := []QueryLogEntry{
		{TS: now - 1000, Client: "10.0.0.1", Name: "a.test.", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 12},
		{TS: now - 800, Client: "10.0.0.2", Name: "ads.test.", QType: "A", Action: "blocked", Rcode: "NXDOMAIN", ElapsedMS: 1},
		{TS: now - 600, Client: "10.0.0.1", Name: "b.test.", QType: "AAAA", Action: "cache", Rcode: "NOERROR", ElapsedMS: 3},
		{TS: now - 400, Client: "10.0.0.3", Name: "ads2.test.", QType: "A", Action: "blocked", Rcode: "NXDOMAIN", ElapsedMS: 2},
		{TS: now - 200, Client: "10.0.0.1", Name: "c.test.", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 25},
	}
	if err := s.InsertQueryLogBatch(entries); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWindowedTotals(t *testing.T) {
	s := seedLog(t)
	tot, err := s.WindowedTotals(time.Now().UnixMilli()-10_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tot.Total != 5 || tot.Blocked != 2 || tot.Cached != 1 || tot.Forwarded != 2 {
		t.Fatalf("totals = %+v", tot)
	}
	// Empty window must return zeroes, not an error (COALESCE over no rows).
	empty, err := s.WindowedTotals(time.Now().UnixMilli()+10_000, nil)
	if err != nil {
		t.Fatalf("empty window err: %v", err)
	}
	if empty.Total != 0 {
		t.Fatalf("empty totals = %+v", empty)
	}
}

func TestQueryLogActionFilter(t *testing.T) {
	s := seedLog(t)
	got, total, err := s.SearchQueryLog(QueryLogQuery{Action: "blocked", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("blocked filter total=%d len=%d", total, len(got))
	}
	for _, e := range got {
		if e.Action != "blocked" {
			t.Errorf("got non-blocked entry %+v", e)
		}
	}
}

func TestQueryLogSort(t *testing.T) {
	s := seedLog(t)
	// Sort by elapsed_ms ascending: 1, 2, 3, 12, 25.
	got, _, err := s.SearchQueryLog(QueryLogQuery{Sort: "ms", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	prev := float64(-1)
	for _, e := range got {
		if e.ElapsedMS < prev {
			t.Fatalf("ms not ascending: %v after %v", e.ElapsedMS, prev)
		}
		prev = e.ElapsedMS
	}
	// Descending.
	desc, _, err := s.SearchQueryLog(QueryLogQuery{Sort: "ms", Desc: true, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(desc) != 1 || desc[0].ElapsedMS != 25 {
		t.Fatalf("desc top = %+v", desc)
	}
}

func TestQueryLogTypeFilter(t *testing.T) {
	s := seedLog(t)
	got, total, err := s.SearchQueryLog(QueryLogQuery{QType: "AAAA", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(got) != 1 || got[0].QType != "AAAA" {
		t.Fatalf("qtype filter total=%d got=%+v", total, got)
	}
}
