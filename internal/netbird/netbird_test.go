package netbird

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// newTestEnricher builds an enricher with the NetBird integration disabled and
// runs one refresh (client->node map, static names, rewrite index).
func newTestEnricher(t *testing.T, st *store.Store) *Enricher {
	t.Helper()
	e := NewEnricher(func() Settings { return Settings{} }, nil, st)
	e.refresh(context.Background())
	return e
}

// seedRDNS pre-fills the reverse-DNS cache so a test never hits the network:
// an empty name caches "no PTR".
func seedRDNS(e *Enricher, ip, name string) {
	e.rdnsMu.Lock()
	e.rdns[ip] = rdnsEntry{name: name, exp: time.Now().Add(time.Hour)}
	e.rdnsMu.Unlock()
}

func addRewrite(t *testing.T, st *store.Store, domain, rrtype, value, scopeType string, scopeValues ...string) int64 {
	t.Helper()
	id, err := st.AddRewriteScoped(domain, rrtype, value, scopeType, scopeValues)
	if err != nil {
		t.Fatalf("add rewrite %s: %v", domain, err)
	}
	return id
}

func TestLookupSourceOrder(t *testing.T) {
	st := newTestStore(t)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		addRewrite(t, st, "rw-"+ip[len(ip)-1:]+".example.lan", "A", ip, store.ScopeAll)
	}
	if err := SaveClientName(st, "192.0.2.1", "static-1"); err != nil {
		t.Fatal(err)
	}
	e := newTestEnricher(t, st)
	e.mu.Lock()
	e.peers = map[string]Identity{
		"192.0.2.1": {Name: "peer-1", Source: "netbird"},
		"192.0.2.2": {Name: "peer-2", Source: "netbird"},
	}
	e.mu.Unlock()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"} {
		seedRDNS(e, ip, "ptr-"+ip[len(ip)-1:]+".example.lan")
	}
	seedRDNS(e, "192.0.2.5", "")

	cases := []struct {
		ip, name, source string
	}{
		{"192.0.2.1", "static-1", "manual"},          // manual > netbird > rewrite > rdns
		{"192.0.2.2", "peer-2", "netbird"},           // netbird > rewrite > rdns
		{"192.0.2.3", "rw-3.example.lan", "rewrite"}, // rewrite > rdns
		{"192.0.2.4", "ptr-4.example.lan", "rdns"},   // rdns only
		{"192.0.2.5", "", ""},                        // nothing known
		{"192.0.2.3:5353", "rw-3.example.lan", "rewrite"},
	}
	for _, c := range cases {
		got := e.Lookup(context.Background(), c.ip)
		if got.Name != c.name || got.Source != c.source {
			t.Errorf("Lookup(%s) = %+v, want name %q source %q", c.ip, got, c.name, c.source)
		}
	}
}

func TestRewriteNamesPickAndFilter(t *testing.T) {
	st := newTestStore(t)
	// Three names for one IP: shortest wins, ties broken alphabetically.
	addRewrite(t, st, "storage.example.lan", "A", "192.0.2.10", store.ScopeAll)
	addRewrite(t, st, "nas.example.lan", "A", "192.0.2.10", store.ScopeAll)
	addRewrite(t, st, "fs1.example.lan", "A", "192.0.2.10", store.ScopeAll)
	// Ignored: disabled, wildcard, CNAME, and family mismatches.
	off := addRewrite(t, st, "a.example.lan", "A", "192.0.2.10", store.ScopeAll)
	if err := st.UpdateRewrite(off, "192.0.2.10", false, store.ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	addRewrite(t, st, "*.lab.example.lan", "A", "192.0.2.11", store.ScopeAll)
	addRewrite(t, st, "alias.example.lan", "CNAME", "192.0.2.12", store.ScopeAll)
	addRewrite(t, st, "v6-in-a.example.lan", "A", "2001:db8::13", store.ScopeAll)
	addRewrite(t, st, "v4-in-aaaa.example.lan", "AAAA", "192.0.2.14", store.ScopeAll)
	// IPv6: the stored value and the client IP are compared canonically.
	addRewrite(t, st, "v6.example.lan", "AAAA", "2001:DB8:0:0::20", store.ScopeAll)

	e := newTestEnricher(t, st)
	for _, ip := range []string{"192.0.2.11", "192.0.2.12", "2001:db8::13", "192.0.2.14"} {
		seedRDNS(e, ip, "")
	}

	got := e.Lookup(context.Background(), "192.0.2.10")
	want := Identity{Name: "fs1.example.lan", Source: "rewrite", Aliases: []string{"nas.example.lan", "storage.example.lan"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Lookup(192.0.2.10) = %+v, want %+v", got, want)
	}
	for _, ip := range []string{"192.0.2.11", "192.0.2.12", "2001:db8::13", "192.0.2.14"} {
		if got := e.Lookup(context.Background(), ip); got.Name != "" {
			t.Errorf("Lookup(%s) = %+v, want no name (rewrite must be ignored)", ip, got)
		}
	}
	for _, ip := range []string{"2001:db8::20", "2001:0db8:0000::0020", "[2001:db8::20]:53"} {
		if got := e.Lookup(context.Background(), ip); got.Name != "v6.example.lan" || got.Aliases != nil {
			t.Errorf("Lookup(%s) = %+v, want v6.example.lan without aliases", ip, got)
		}
	}
}

func TestRewriteNamesScoping(t *testing.T) {
	st := newTestStore(t)
	id1, err := st.CreateNode("agent-01", "h1", "p1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeSite(id1, "site-a", ""); err != nil {
		t.Fatal(err)
	}
	id2, err := st.CreateNode("agent-02", "h2", "p2")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeSite(id2, "site-b", ""); err != nil {
		t.Fatal(err)
	}
	// One IP named differently per scope: the shorter (globally preferred) name
	// is only in scope for agent-02.
	addRewrite(t, st, "db.example.lan", "A", "192.0.2.40", store.ScopeNodes, "agent-02")
	addRewrite(t, st, "database-a.example.lan", "A", "192.0.2.40", store.ScopeSites, "site-a")
	// Split horizon: the site-b override repoints nas for agent-02 only.
	addRewrite(t, st, "nas.example.lan", "A", "192.0.2.10", store.ScopeAll)
	addRewrite(t, st, "nas.example.lan", "A", "192.0.2.20", store.ScopeSites, "site-b")

	now := time.Now().UnixMilli()
	logFrom := func(node string, clients ...string) {
		var entries []store.QueryLogEntry
		for _, c := range clients {
			entries = append(entries, store.QueryLogEntry{TS: now, Client: c, Name: "x.example.lan", QType: "A", Action: "forward", Rcode: "NOERROR"})
		}
		if err := st.InsertNodeQueryLog(node, entries); err != nil {
			t.Fatal(err)
		}
	}
	e := newTestEnricher(t, st)
	check := func(stage, ip, name string, aliases []string) {
		t.Helper()
		got := e.Lookup(context.Background(), ip)
		if got.Name != name || got.Source != "rewrite" || !reflect.DeepEqual(got.Aliases, aliases) {
			t.Errorf("%s: Lookup(%s) = %+v, want %q aliases %v", stage, ip, got, name, aliases)
		}
	}
	// Node unknown (no queries logged yet): every scope counts, preferred-first.
	check("unknown node", "192.0.2.40", "db.example.lan", []string{"database-a.example.lan"})
	check("unknown node", "192.0.2.10", "nas.example.lan", nil)

	// Served by agent-01 (site-a): its in-scope name wins over the shorter one.
	logFrom("agent-01", "192.0.2.40", "192.0.2.20")
	e.refresh(context.Background())
	check("agent-01", "192.0.2.40", "database-a.example.lan", nil)
	// agent-01 serves nas as 192.0.2.10, not .20: fall back to any enabled
	// rewrite naming the IP rather than leaving it bare.
	check("agent-01", "192.0.2.20", "nas.example.lan", nil)

	// The client moves to agent-02 (most queries there): its in-scope name.
	logFrom("agent-02", "192.0.2.40", "192.0.2.40")
	e.refresh(context.Background())
	check("agent-02", "192.0.2.40", "db.example.lan", nil)
}

func TestRewriteNamesRefresh(t *testing.T) {
	st := newTestStore(t)
	e := newTestEnricher(t, st)
	ip := "192.0.2.50"
	seedRDNS(e, ip, "")
	lookup := func() Identity { return e.Lookup(context.Background(), ip) }

	id := addRewrite(t, st, "old.example.lan", "A", ip, store.ScopeAll)
	if got := lookup(); got.Name != "" {
		t.Fatalf("before refresh: %+v, want the index unchanged", got)
	}
	e.RefreshRewrites()
	if got := lookup(); got.Name != "old.example.lan" {
		t.Fatalf("after add: %+v", got)
	}
	// Disabling drops the name.
	if err := st.UpdateRewrite(id, ip, false, store.ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	e.RefreshRewrites()
	if got := lookup(); got.Name != "" {
		t.Fatalf("after disable: %+v, want no name", got)
	}
	// Repointing the rewrite elsewhere drops it too; a new one takes over.
	if err := st.UpdateRewrite(id, "192.0.2.51", true, store.ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	id2 := addRewrite(t, st, "new.example.lan", "A", ip, store.ScopeAll)
	e.RefreshRewrites()
	if got := lookup(); got.Name != "new.example.lan" || got.Aliases != nil {
		t.Fatalf("after edit: %+v", got)
	}
	if err := st.DeleteRewrite(id2); err != nil {
		t.Fatal(err)
	}
	e.RefreshRewrites()
	if got := lookup(); got.Name != "" {
		t.Fatalf("after delete: %+v, want no name", got)
	}
	// The periodic refresh rebuilds the index as well.
	addRewrite(t, st, "tick.example.lan", "A", ip, store.ScopeAll)
	e.refresh(context.Background())
	if got := lookup(); got.Name != "tick.example.lan" {
		t.Fatalf("after refresh tick: %+v", got)
	}
}

func TestSetClientNameOverridesRewrite(t *testing.T) {
	st := newTestStore(t)
	addRewrite(t, st, "host.example.lan", "A", "192.0.2.60", store.ScopeAll)
	e := newTestEnricher(t, st)
	if err := e.SetClientName("192.0.2.60", "my-box"); err != nil {
		t.Fatal(err)
	}
	if got := e.Lookup(context.Background(), "192.0.2.60"); got.Name != "my-box" || got.Source != "manual" {
		t.Fatalf("with static name: %+v", got)
	}
	if err := e.SetClientName("192.0.2.60", ""); err != nil {
		t.Fatal(err)
	}
	if got := e.Lookup(context.Background(), "192.0.2.60"); got.Name != "host.example.lan" || got.Source != "rewrite" {
		t.Fatalf("after clearing static name: %+v", got)
	}
}
