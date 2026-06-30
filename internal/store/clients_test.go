package store

import (
	"path/filepath"
	"testing"
	"time"
)

// TestClientDetailStats verifies every per-client KPI the inspect modal shows is
// computed correctly: the action totals, unique-domain count, average latency,
// first/last seen, and the action / blocked-category / top-domain breakdowns.
func TestClientDetailStats(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	now := time.Now().UnixMilli()
	// Client under test: 10.0.0.1 — 6 queries, mixed actions, one repeated domain.
	// Another client's traffic must NOT leak into the totals.
	entries := []QueryLogEntry{
		{TS: now - 6000, Client: "10.0.0.1", Name: "a.test.", QType: "A", Action: "forward", ElapsedMS: 10},
		{TS: now - 5000, Client: "10.0.0.1", Name: "a.test.", QType: "A", Action: "cache", ElapsedMS: 2},
		{TS: now - 4000, Client: "10.0.0.1", Name: "ads.test.", QType: "A", Action: "blocked", Category: "ads", ElapsedMS: 1},
		{TS: now - 3000, Client: "10.0.0.1", Name: "track.test.", QType: "A", Action: "blocked", Category: "trackers", ElapsedMS: 1},
		{TS: now - 2000, Client: "10.0.0.1", Name: "evil.test.", QType: "A", Action: "blocked", Category: "ads", ElapsedMS: 1},
		{TS: now - 1000, Client: "10.0.0.1", Name: "b.test.", QType: "A", Action: "rewrite", ElapsedMS: 4},
		{TS: now - 1500, Client: "10.0.0.9", Name: "other.test.", QType: "A", Action: "forward", ElapsedMS: 99},
	}
	if err := s.InsertQueryLogBatch(entries); err != nil {
		t.Fatal(err)
	}

	d, err := s.ClientDetailStats("10.0.0.1", now-10_000, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Action totals (the other client is excluded).
	if d.Totals.Total != 6 {
		t.Errorf("total = %d, want 6", d.Totals.Total)
	}
	if d.Totals.Blocked != 3 {
		t.Errorf("blocked = %d, want 3", d.Totals.Blocked)
	}
	if d.Totals.Cached != 1 {
		t.Errorf("cached = %d, want 1", d.Totals.Cached)
	}
	if d.Totals.Forwarded != 1 {
		t.Errorf("forwarded = %d, want 1", d.Totals.Forwarded)
	}
	if d.Totals.Rewritten != 1 {
		t.Errorf("rewritten = %d, want 1", d.Totals.Rewritten)
	}

	// Unique domains: a.test, ads.test, track.test, evil.test, b.test = 5.
	if d.UniqueDomains != 5 {
		t.Errorf("unique_domains = %d, want 5", d.UniqueDomains)
	}

	// Avg latency over this client's 6 rows: (10+2+1+1+1+4)/6 = 3.166…
	if got := d.AvgLatencyMS; got < 3.0 || got > 3.34 {
		t.Errorf("avg_latency_ms = %.3f, want ~3.17", got)
	}

	// First/last seen are the min/max ts of this client's rows.
	if d.FirstSeen != now-6000 {
		t.Errorf("first_seen = %d, want %d", d.FirstSeen, now-6000)
	}
	if d.LastSeen != now-1000 {
		t.Errorf("last_seen = %d, want %d", d.LastSeen, now-1000)
	}

	// Blocked-by-category: ads = 2, trackers = 1, ordered by count desc.
	if len(d.Categories) != 2 || d.Categories[0].Category != "ads" || d.Categories[0].Count != 2 {
		t.Errorf("categories = %+v, want ads:2 first", d.Categories)
	}

	// Top domains: a.test appears twice, so it leads.
	if len(d.TopDomains) == 0 || d.TopDomains[0].Name != "a.test." || d.TopDomains[0].Count != 2 {
		t.Errorf("top_domains[0] = %+v, want a.test.:2", d.TopDomains)
	}

	// Top blocked: ads.test/track.test/evil.test, each blocked once.
	if len(d.TopBlocked) != 3 {
		t.Errorf("top_blocked = %+v, want 3 entries", d.TopBlocked)
	}

	// Empty window must return zeroed (not nil) slices and no error.
	empty, err := s.ClientDetailStats("10.0.0.1", now+10_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Totals.Total != 0 || empty.FirstSeen != 0 || empty.LastSeen != 0 {
		t.Errorf("empty window not zeroed: %+v", empty)
	}
	if empty.Actions == nil || empty.Categories == nil || empty.TopDomains == nil || empty.TopBlocked == nil {
		t.Error("empty window slices must be non-nil")
	}
}
