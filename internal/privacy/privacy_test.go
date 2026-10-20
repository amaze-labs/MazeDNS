package privacy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func fixed(p Policy) func() Policy { return func() Policy { return p } }

func entry(client string, ts int64) store.QueryLogEntry {
	return store.QueryLogEntry{TS: ts, Client: client, Name: "example.com.", QType: "A", Action: "forward", Rcode: "NOERROR", ContentCategory: "news"}
}

func TestIngestLevels(t *testing.T) {
	st := openStore(t)
	now := time.Now()
	for _, tc := range []struct {
		level            int
		wantName         string
		wantClient       func(string) bool
		wantCategoryKept bool
	}{
		{LevelShowAll, "example.com.", func(c string) bool { return c == "10.0.0.1" }, true},
		{LevelHideDomains, Hidden, func(c string) bool { return c == "10.0.0.1" }, true},
		{LevelHideClients, Hidden, func(c string) bool { return IsPseudonym(c) && !strings.Contains(c, "10.0.0.1") }, true},
		{LevelAnonymous, Hidden, func(c string) bool { return c == "" }, true},
	} {
		a := New(fixed(Policy{Level: tc.level}), NewKeyring(st))
		es := []store.QueryLogEntry{entry("10.0.0.1", now.UnixMilli())}
		a.Ingest(es, now)
		if es[0].Name != tc.wantName || !tc.wantClient(es[0].Client) {
			t.Errorf("level %d: got name %q client %q", tc.level, es[0].Name, es[0].Client)
		}
		if es[0].ContentCategory != "news" {
			t.Errorf("level %d: content category dropped", tc.level)
		}
	}
}

// Inside the detail window an entry keeps full detail; past it (an agent's
// late backlog) the level applies at once.
func TestIngestDetailWindow(t *testing.T) {
	st := openStore(t)
	now := time.Now()
	a := New(fixed(Policy{Level: LevelHideClients, DetailHours: 6}), NewKeyring(st))
	es := []store.QueryLogEntry{
		entry("10.0.0.1", now.Add(-time.Hour).UnixMilli()),
		entry("10.0.0.1", now.Add(-7*time.Hour).UnixMilli()),
	}
	a.Ingest(es, now)
	if es[0].Client != "10.0.0.1" || es[0].Name != "example.com." {
		t.Errorf("recent entry anonymized: %+v", es[0])
	}
	if !IsPseudonym(es[1].Client) || es[1].Name != Hidden {
		t.Errorf("old entry kept detail: %+v", es[1])
	}
}

// A device keeps one pseudonym through a UTC day, gets another the next day,
// and keeps it across a restart (the day keys are persisted).
func TestPseudonymStableForTheDay(t *testing.T) {
	st := openStore(t)
	day := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC).UnixMilli()
	k := NewKeyring(st)
	morning := k.Pseudonym("10.0.0.1", day+3600000)
	evening := k.Pseudonym("10.0.0.1", day+20*3600000)
	tomorrow := k.Pseudonym("10.0.0.1", day+25*3600000)
	other := k.Pseudonym("10.0.0.2", day+3600000)
	if morning != evening {
		t.Errorf("pseudonym changed within the day: %q vs %q", morning, evening)
	}
	if morning == tomorrow || morning == other {
		t.Errorf("pseudonyms should differ across days and devices")
	}
	if again := NewKeyring(st).Pseudonym("10.0.0.1", day+3600000); again != morning {
		t.Errorf("pseudonym changed across a restart: %q vs %q", again, morning)
	}
	// Once the day's key is pruned, the same address maps elsewhere.
	k.Prune(day + 2*dayMs)
	if after := NewKeyring(st).Pseudonym("10.0.0.1", day+3600000); after == morning {
		t.Error("pruned key still reproduces the old pseudonym")
	}
}

func TestExportIgnoresDetailWindow(t *testing.T) {
	st := openStore(t)
	now := time.Now()
	a := New(fixed(Policy{Level: LevelHideDomains, DetailHours: 24}), NewKeyring(st))
	out := a.Export([]store.QueryLogEntry{entry("10.0.0.1", now.UnixMilli())})
	if len(out) != 1 || out[0].Name != Hidden {
		t.Errorf("export kept the domain: %+v", out)
	}
	a = New(fixed(Policy{Level: LevelAnonymous}), NewKeyring(st))
	if out := a.Export([]store.QueryLogEntry{entry("10.0.0.1", now.UnixMilli())}); len(out) != 0 {
		t.Errorf("anonymous mode exported %d entries", len(out))
	}
}

func rollUp(t *testing.T, st *store.Store) {
	t.Helper()
	for {
		more, err := st.RollupAdvance(1000)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			return
		}
	}
}

// Raising the level scrubs what is already stored, past the window: names,
// clients and the per-client rollup, with counts preserved.
func TestScrubHistoryOnLevelRaise(t *testing.T) {
	st := openStore(t)
	now := time.Now()
	old := now.Add(-3 * time.Hour).UnixMilli()
	recent := now.Add(-10 * time.Minute).UnixMilli()
	if err := st.InsertNodeQueryLog("a1", []store.QueryLogEntry{
		entry("10.0.0.1", old), entry("10.0.0.1", old+1), entry("10.0.0.2", old), entry("10.0.0.1", recent),
	}); err != nil {
		t.Fatal(err)
	}
	rollUp(t, st)

	p := Policy{Level: LevelHideClients, DetailHours: 1}
	s := NewScrubber(st, New(fixed(p), NewKeyring(st)))
	if err := s.Scrub(now); err != nil {
		t.Fatal(err)
	}
	res, _, err := st.SearchQueryLog(store.QueryLogQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	pseud := map[string]int{}
	for _, e := range res {
		if e.TS == recent {
			if e.Client != "10.0.0.1" || e.Name != "example.com." {
				t.Errorf("entry inside the window was scrubbed: %+v", e)
			}
			continue
		}
		if !IsPseudonym(e.Client) || e.Name != Hidden {
			t.Errorf("old entry not scrubbed: %+v", e)
		}
		pseud[e.Client]++
	}
	if len(pseud) != 2 {
		t.Errorf("want 2 distinct pseudonyms (one per device), got %v", pseud)
	}

	// The rollup carries no address older than the window, and keeps its counts.
	top, err := st.RollupTopClients(0, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, c := range top {
		total += c.Total
		if !IsPseudonym(c.Client) && c.Client != "10.0.0.1" {
			t.Errorf("rollup kept an address: %+v", c)
		}
	}
	if total != 4 {
		t.Errorf("rollup total = %d, want 4", total)
	}

	// Re-running changes nothing.
	if err := s.Scrub(now); err != nil {
		t.Fatal(err)
	}
	res2, _, _ := st.SearchQueryLog(store.QueryLogQuery{Limit: 100})
	for i := range res {
		if res[i].Client != res2[i].Client {
			t.Errorf("second scrub changed a pseudonym: %q -> %q", res[i].Client, res2[i].Client)
		}
	}
}

// Anonymous mode keeps the counts and drops the entries once counted.
func TestScrubAnonymous(t *testing.T) {
	st := openStore(t)
	now := time.Now()
	if err := st.InsertNodeQueryLog("a1", []store.QueryLogEntry{
		entry("10.0.0.1", now.Add(-time.Minute).UnixMilli()), entry("10.0.0.2", now.Add(-time.Minute).UnixMilli()),
	}); err != nil {
		t.Fatal(err)
	}
	rollUp(t, st)
	s := NewScrubber(st, New(fixed(Policy{Level: LevelAnonymous}), NewKeyring(st)))
	if err := s.Scrub(now); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountQueryLog(); n != 0 {
		t.Errorf("anonymous mode kept %d entries", n)
	}
	sum, err := st.RollupSummary(0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Totals.Total != 2 || sum.UniqueClients != 0 {
		t.Errorf("summary = %+v, want 2 queries and no clients", sum)
	}
}
