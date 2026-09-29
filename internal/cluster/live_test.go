package cluster

import (
	"context"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestLiveFilterAndTap(t *testing.T) {
	e := store.QueryLogEntry{Client: "10.0.0.7", Name: "Ads.Example.com", QType: "A", Action: "blocked", Rcode: "NXDOMAIN"}
	for _, tc := range []struct {
		f    LiveFilter
		want bool
	}{
		{LiveFilter{}, true},
		{LiveFilter{Client: "10.0.0", Domain: "example", Action: "blocked"}, true},
		{LiveFilter{Client: "10.0.1"}, false},
		{LiveFilter{Domain: "other"}, false},
		{LiveFilter{QType: "AAAA"}, false},
		{LiveFilter{Rcode: "NOERROR"}, false},
	} {
		if got := tc.f.Match(e); got != tc.want {
			t.Errorf("%+v.Match = %v, want %v", tc.f, got, tc.want)
		}
	}

	// The same viewers in any order, duplicates included, give one version.
	a, b := LiveFilter{Domain: "a"}, LiveFilter{Action: "blocked"}
	s1, s2 := NewLiveState([]LiveFilter{a, b, a}), NewLiveState([]LiveFilter{b, a})
	if s1.Version != s2.Version || len(s1.Filters) != 2 || s1.Version == NewLiveState(nil).Version {
		t.Fatalf("live state not deduped/stable: %+v %+v", s1, s2)
	}

	tap := NewLiveTap()
	tap.Write(e) // nobody watching
	tap.setFilters([]LiveFilter{{Action: "forward"}, {Domain: "example"}})
	tap.Write(e)
	tap.Write(store.QueryLogEntry{Name: "other.org", Action: "cache"})
	if len(tap.ch) != 1 {
		t.Fatalf("tap kept %d entries, want 1", len(tap.ch))
	}
}

// One cycle drains a backlog bigger than a single batch.
func TestShipLogsDrainsBacklog(t *testing.T) {
	cp := &fakeCP{snap: testSnapshot(t)}
	ag, st, _ := newAgentAgainst(t, cp)
	backlog := make([]store.QueryLogEntry, 2*shipBatch+10)
	for i := range backlog {
		backlog[i] = store.QueryLogEntry{TS: int64(i), Name: "x.example", QType: "A", Action: "forward"}
	}
	if err := st.InsertQueryLogBatch(backlog); err != nil {
		t.Fatal(err)
	}
	ag.shipLogs(context.Background())
	if max, _ := st.MaxQueryLogID(); ag.lastShipped != max || len(cp.headers) != 3 {
		t.Fatalf("shipped up to %d of %d in %d posts, want everything in 3", ag.lastShipped, max, len(cp.headers))
	}
}
