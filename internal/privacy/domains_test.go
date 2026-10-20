package privacy

import (
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func named(client, name string, ts int64) store.QueryLogEntry {
	e := entry(client, ts)
	e.Name = name
	return e
}

// A name is kept once k devices queried it; a rare name under a common
// registered domain is generalized to that domain; anything else is hidden.
func TestRareDomainsHidden(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	ts := now.UnixMilli()
	a := New(fixed(Policy{Level: LevelHideDomains, DomainK: 3}), NewKeyring(st))

	es := []store.QueryLogEntry{
		named("10.0.0.1", "www.google.com.", ts),
		named("10.0.0.2", "www.google.com.", ts),
		named("10.0.0.3", "www.google.com.", ts),
		named("10.0.0.1", "u1.tracker.example.", ts), // rare name, common registered domain
		named("10.0.0.2", "u2.tracker.example.", ts),
		named("10.0.0.3", "u3.tracker.example.", ts),
		named("10.0.0.1", "my-clinic.example.", ts), // one device only
		named("10.0.0.1", "my-clinic.example.", ts), // same device again: still one
	}
	a.Ingest(es, now)
	want := []string{
		"www.google.com.", "www.google.com.", "www.google.com.",
		"tracker.example.", "tracker.example.", "tracker.example.",
		Hidden, Hidden,
	}
	for i, e := range es {
		if e.Name != want[i] {
			t.Errorf("entry %d: name %q, want %q", i, e.Name, want[i])
		}
		if e.Client == "" || IsPseudonym(e.Client) {
			t.Errorf("entry %d: level 1 changed the client to %q", i, e.Client)
		}
	}

	// The next day a common name is kept from its first query (carried over).
	next := now.Add(24 * time.Hour)
	es = []store.QueryLogEntry{named("10.0.0.9", "www.google.com.", next.UnixMilli())}
	a.Ingest(es, next)
	if es[0].Name != "www.google.com." {
		t.Errorf("common name hidden the next morning: %q", es[0].Name)
	}
}

// After a restart the counts come back from the store.
func TestRareDomainsSeededFromStore(t *testing.T) {
	st := openStore(t)
	now := time.Now()
	ts := now.Add(-time.Hour).UnixMilli()
	if err := st.InsertNodeQueryLog("a1", []store.QueryLogEntry{
		named("10.0.0.1", "shared.example.", ts), named("10.0.0.2", "shared.example.", ts),
	}); err != nil {
		t.Fatal(err)
	}
	a := New(fixed(Policy{Level: LevelHideClients, DomainK: 2}), NewKeyring(st))
	a.SetDaySeeder(st.QueryLogDayPairs)
	es := []store.QueryLogEntry{named("10.0.0.1", "shared.example.", now.UnixMilli())}
	a.Ingest(es, now)
	if es[0].Name != "shared.example." {
		t.Errorf("name seen by 2 devices before a restart was hidden: %q", es[0].Name)
	}
}

// Switching from rare-only to hiding every domain redoes the history; the
// rare-only scrub keeps common names in stored history.
func TestScrubRareDomains(t *testing.T) {
	st := openStore(t)
	now := time.Now()
	old := now.Add(-2 * time.Hour).UnixMilli()
	if err := st.InsertNodeQueryLog("a1", []store.QueryLogEntry{
		named("10.0.0.1", "common.example.", old), named("10.0.0.2", "common.example.", old),
		named("10.0.0.1", "rare.other.", old),
	}); err != nil {
		t.Fatal(err)
	}
	p := Policy{Level: LevelHideDomains, DomainK: 2}
	a := New(func() Policy { return p }, NewKeyring(st))
	a.SetDaySeeder(st.QueryLogDayPairs)
	s := NewScrubber(st, a)
	if err := s.Scrub(now); err != nil {
		t.Fatal(err)
	}
	names := func() map[string]int {
		res, _, err := st.SearchQueryLog(store.QueryLogQuery{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]int{}
		for _, e := range res {
			m[e.Name]++
		}
		return m
	}
	if got := names(); got["common.example."] != 2 || got[Hidden] != 1 {
		t.Errorf("after rare-only scrub: %v", got)
	}
	p = Policy{Level: LevelHideDomains} // every domain
	if err := s.Scrub(now); err != nil {
		t.Fatal(err)
	}
	if got := names(); got[Hidden] != 3 {
		t.Errorf("after hiding every domain: %v", got)
	}
}

// Shortening the detail window to none reduces the full-detail entries the old
// window kept, in rare-only mode too.
func TestScrubRareDomainsWindowShortened(t *testing.T) {
	st := openStore(t)
	now := time.Now()
	recent := now.Add(-2 * time.Hour).UnixMilli()
	if err := st.InsertNodeQueryLog("a1", []store.QueryLogEntry{named("10.0.0.1", "rare.other.", recent)}); err != nil {
		t.Fatal(err)
	}
	p := Policy{Level: LevelHideDomains, DomainK: 2, DetailHours: 24}
	a := New(func() Policy { return p }, NewKeyring(st))
	a.SetDaySeeder(st.QueryLogDayPairs)
	s := NewScrubber(st, a)
	if err := s.Scrub(now); err != nil { // inside the window: kept
		t.Fatal(err)
	}
	p.DetailHours = 0
	if err := s.Scrub(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	res, _, err := st.SearchQueryLog(store.QueryLogQuery{Limit: 10})
	if err != nil || len(res) != 1 {
		t.Fatalf("got %v, %v", res, err)
	}
	if res[0].Name != Hidden {
		t.Errorf("full-detail entry kept its name after the window was removed: %q", res[0].Name)
	}
}
