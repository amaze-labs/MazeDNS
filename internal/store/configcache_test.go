package store

import (
	"sync"
	"testing"
	"time"
)

func TestIsConfigWrite(t *testing.T) {
	cases := []struct {
		q    string
		want bool
	}{
		{`INSERT INTO rules(action, domain) VALUES(?,?)`, true},
		{"\n\t\tUPDATE lists SET enabled=? WHERE id=?", true},
		{`DELETE FROM classifications WHERE domain = ?`, true},
		{`INSERT INTO rewrites (domain) VALUES(?)`, true},
		{`update forwarders set enabled=0`, true},
		{`DELETE FROM rules`, true},
		{`INSERT OR REPLACE INTO rules(action) VALUES(?)`, true},
		// Reads and writes to unrelated tables never bump.
		{`SELECT id FROM rules WHERE domain=?`, false},
		{"  select scope_type from rewrites limit 1", false},
		{`UPDATE nodes SET address=?, version=? WHERE id=?`, false},
		{`INSERT INTO query_log(ts, client) VALUES(?,?)`, false},
		{`INSERT INTO query_rollup(bucket, node) SELECT bucket, ? FROM query_rollup WHERE node=?`, false},
		{`INSERT INTO app_meta(key, value) VALUES(?, ?)`, false},
		{`UPDATE lists_archive SET x=1`, false}, // whole-word match only
	}
	for _, c := range cases {
		if got := isConfigWrite(c.q); got != c.want {
			t.Errorf("isConfigWrite(%q) = %v, want %v", c.q, got, c.want)
		}
	}
}

// The cache must serve a stored version without touching the database: a
// write that bypasses the store (and so the generation) stays invisible
// until the TTL safety net expires the entry. This proves both that the
// cached path does not reload the rule set and that the TTL bounds staleness.
func TestCachedConfigVersionServedFromCacheUntilTTL(t *testing.T) {
	s := openTestStore(t)
	now := time.Unix(1_700_000_000, 0)
	s.versions.now = func() time.Time { return now }

	if _, err := s.AddRule("deny", "ads.example.lan", "ads"); err != nil {
		t.Fatal(err)
	}
	v1, err := s.CachedConfigVersionForNode("agent-01", "site-a")
	if err != nil {
		t.Fatal(err)
	}
	// Out-of-band write straight on the raw pool: no generation bump.
	if _, err := s.db.DB.Exec(`INSERT INTO rules(action, domain, category, enabled, updated_at) VALUES('deny','oob.example.lan','ads',1,1)`); err != nil {
		t.Fatal(err)
	}
	fresh, _ := s.ConfigVersionForNode("agent-01", "site-a")
	if fresh == v1 {
		t.Fatal("test setup: the out-of-band write should change the real version")
	}
	if got, _ := s.CachedConfigVersionForNode("agent-01", "site-a"); got != v1 {
		t.Fatalf("within TTL the cached version must be served without reloading: got %q want %q", got, v1)
	}
	now = now.Add(configVersionTTL)
	if got, _ := s.CachedConfigVersionForNode("agent-01", "site-a"); got != fresh {
		t.Fatalf("after the TTL the version must be recomputed: got %q want %q", got, fresh)
	}
}

// Every kind of mutation that changes what a node is served must invalidate
// its cached version. Each case starts from a warm cache and checks the
// cached value both changed and equals a fresh uncached computation.
func TestCachedConfigVersionInvalidatedByEveryMutation(t *testing.T) {
	type fixture struct {
		s      *Store
		listID int64
		rwID   int64
		fwID   int64
		ruleID int64
	}
	setup := func(t *testing.T) fixture {
		s := openTestStore(t)
		f := fixture{s: s}
		var err error
		if f.ruleID, err = s.AddRule("deny", "manual.example.lan", "custom"); err != nil {
			t.Fatal(err)
		}
		if f.listID, err = s.CreateList("blocklist", "url", "https://lists.example.lan/a", "ads", 3600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReplaceListRules(f.listID, "ads", []Rule{{Action: "deny", Domain: "list.example.lan"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.InsertClassification(Classification{Domain: "ai.example.lan", Category: "malware", Block: true, Status: ClassAuto}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.InsertClassification(Classification{Domain: "clean.example.lan", Category: "news", Status: ClassClean}); err != nil {
			t.Fatal(err)
		}
		if f.rwID, err = s.AddRewrite("nas.example.lan", "A", "192.0.2.10"); err != nil {
			t.Fatal(err)
		}
		if f.fwID, err = s.AddForwarder("corp.example.lan", []string{"192.0.2.53:53"}, ScopeAll, nil); err != nil {
			t.Fatal(err)
		}
		return f
	}
	must := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name   string
		mutate func(t *testing.T, f fixture)
	}{
		{"add rule", func(t *testing.T, f fixture) { _, err := f.s.AddRule("deny", "new.example.lan", "ads"); must(t, err) }},
		{"bulk rules", func(t *testing.T, f fixture) {
			_, err := f.s.AddRulesBulk([]Rule{{Action: "allow", Domain: "ok.example.lan"}})
			must(t, err)
		}},
		{"delete rule", func(t *testing.T, f fixture) { must(t, f.s.DeleteRule(f.ruleID)) }},
		{"clear rules", func(t *testing.T, f fixture) { must(t, f.s.ClearRules()) }},
		{"list refresh", func(t *testing.T, f fixture) {
			_, err := f.s.ReplaceListRules(f.listID, "ads", []Rule{{Action: "deny", Domain: "refreshed.example.lan"}})
			must(t, err)
		}},
		{"list disabled", func(t *testing.T, f fixture) { must(t, f.s.SetListEnabled(f.listID, false)) }},
		{"list deleted", func(t *testing.T, f fixture) { must(t, f.s.DeleteList(f.listID)) }},
		{"ai auto-block", func(t *testing.T, f fixture) {
			_, err := f.s.InsertClassification(Classification{Domain: "ai2.example.lan", Category: "ads", Block: true, Status: ClassAuto})
			must(t, err)
		}},
		{"ai rejected", func(t *testing.T, f fixture) {
			must(t, f.s.SetClassificationDecision("ai.example.lan", ClassRejected, "", "false positive"))
		}},
		{"ai status", func(t *testing.T, f fixture) { must(t, f.s.SetClassificationStatus("ai.example.lan", ClassRejected)) }},
		{"ai threat flag", func(t *testing.T, f fixture) {
			ok, err := f.s.FlagThreat("clean.example.lan", ClassAuto, "feed")
			must(t, err)
			if !ok {
				t.Fatal("FlagThreat did not change the row")
			}
		}},
		{"ai deleted", func(t *testing.T, f fixture) { must(t, f.s.DeleteClassification("ai.example.lan")) }},
		{"ai wiped", func(t *testing.T, f fixture) { _, err := f.s.DeleteAllClassifications(); must(t, err) }},
		{"add rewrite", func(t *testing.T, f fixture) {
			_, err := f.s.AddRewrite("pc.example.lan", "A", "192.0.2.20")
			must(t, err)
		}},
		{"update rewrite", func(t *testing.T, f fixture) { must(t, f.s.UpdateRewrite(f.rwID, "192.0.2.11", true, ScopeAll, nil)) }},
		{"delete rewrite", func(t *testing.T, f fixture) { must(t, f.s.DeleteRewrite(f.rwID)) }},
		{"bulk rewrites", func(t *testing.T, f fixture) {
			_, err := f.s.AddRewritesBulk([]Rewrite{{Domain: "tv.example.lan", RRType: "A", Value: "192.0.2.30"}})
			must(t, err)
		}},
		{"clear rewrites", func(t *testing.T, f fixture) { must(t, f.s.ClearRewrites()) }},
		{"add forwarder", func(t *testing.T, f fixture) {
			_, err := f.s.AddForwarder("lab.example.lan", []string{"192.0.2.54:53"}, ScopeAll, nil)
			must(t, err)
		}},
		{"update forwarder", func(t *testing.T, f fixture) {
			must(t, f.s.UpdateForwarder(f.fwID, []string{"192.0.2.55:53"}, true, ScopeAll, nil))
		}},
		{"delete forwarder", func(t *testing.T, f fixture) { must(t, f.s.DeleteForwarder(f.fwID)) }},
		{"bulk forwarders", func(t *testing.T, f fixture) {
			_, err := f.s.AddForwardersBulk([]Forwarder{{Suffix: "iot.example.lan", Upstreams: []string{"192.0.2.56:53"}, ScopeType: ScopeAll, Enabled: true}})
			must(t, err)
		}},
		{"clear forwarders", func(t *testing.T, f fixture) { must(t, f.s.ClearForwarders()) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			before, err := f.s.CachedConfigVersionForNode("agent-01", "site-a")
			must(t, err)
			if again, _ := f.s.CachedConfigVersionForNode("agent-01", "site-a"); again != before {
				t.Fatal("warm cache should be stable")
			}
			gen := f.s.configGen.Load()
			tc.mutate(t, f)
			if f.s.configGen.Load() == gen {
				t.Fatal("mutation did not bump the config generation")
			}
			got, err := f.s.CachedConfigVersionForNode("agent-01", "site-a")
			must(t, err)
			want, _ := f.s.ConfigVersionForNode("agent-01", "site-a")
			if got != want {
				t.Fatalf("cached version %q != fresh %q after %s", got, want, tc.name)
			}
			if got == before {
				t.Fatalf("version did not change after %s", tc.name)
			}
		})
	}
}

// Node-dependent inputs (name, site) are part of the cache key, so a rename or
// a site move is picked up without any invalidation.
func TestCachedConfigVersionFollowsNodeSiteAndName(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.AddRewriteScoped("nas.example.lan", "A", "192.0.2.10", ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRewriteScoped("nas.example.lan", "A", "192.0.2.11", ScopeSites, []string{"site-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddForwarder("corp.example.lan", []string{"192.0.2.53:53"}, ScopeNodes, []string{"agent-02"}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []struct{ name, site string }{
		{"agent-01", ""}, {"agent-01", "site-a"}, {"agent-02", ""}, {"agent-02", "site-a"},
	} {
		got, err := s.CachedConfigVersionForNode(n.name, n.site)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := s.ConfigVersionForNode(n.name, n.site)
		if got != want {
			t.Fatalf("%s/%s: cached %q != fresh %q", n.name, n.site, got, want)
		}
	}
	a0, _ := s.CachedConfigVersionForNode("agent-01", "")
	a1, _ := s.CachedConfigVersionForNode("agent-01", "site-a")
	b0, _ := s.CachedConfigVersionForNode("agent-02", "")
	if a0 == a1 || a0 == b0 {
		t.Fatal("different name/site views must not share a cached version")
	}
}

// The batched listing served from the cache must equal the uncached per-node
// computation, both cold and warm, and after a change.
func TestConfigVersionsForNodesCached(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.AddRule("deny", "ads.example.lan", "ads"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRewriteScoped("nas.example.lan", "A", "192.0.2.11", ScopeSites, []string{"site-a"}); err != nil {
		t.Fatal(err)
	}
	nodes := []Node{{Name: "agent-01", Site: "site-a"}, {Name: "agent-02"}, {Name: "agent-03", Site: "site-a"}}
	check := func(stage string) {
		t.Helper()
		got, err := s.ConfigVersionsForNodes(nodes)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range nodes {
			want, _ := s.ConfigVersionForNode(n.Name, n.Site)
			if got[n.Name] != want {
				t.Fatalf("%s: %s = %q, want %q", stage, n.Name, got[n.Name], want)
			}
		}
	}
	check("cold")
	// Partially warm: one node cached by the snapshot path, the rest batched.
	if _, err := s.AddRule("deny", "more.example.lan", "ads"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SnapshotForNode("agent-02", ""); err != nil {
		t.Fatal(err)
	}
	check("partial")
	check("warm")
}

// SnapshotForNode's version is the hash of exactly the content it returns,
// and it seeds the cache.
func TestSnapshotForNodeSeedsCache(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.AddRule("deny", "ads.example.lan", "ads"); err != nil {
		t.Fatal(err)
	}
	snap, err := s.SnapshotForNode("agent-01", "site-a")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Version != configHash(snap.Rules, snap.Rewrites, snap.Forwarders) {
		t.Fatal("snapshot version must hash the returned content")
	}
	if want, _ := s.ConfigVersionForNode("agent-01", "site-a"); snap.Version != want {
		t.Fatalf("snapshot version %q != ConfigVersionForNode %q", snap.Version, want)
	}
	// Seeded: an out-of-band change is not seen, so the value came from the cache.
	if _, err := s.db.DB.Exec(`DELETE FROM rules`); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.CachedConfigVersionForNode("agent-01", "site-a"); got != snap.Version {
		t.Fatalf("SnapshotForNode should have seeded the cache: got %q want %q", got, snap.Version)
	}
}

// A version computed from data loaded before a concurrent write must not be
// cached under the newer generation.
func TestVersionCacheDropsStalePut(t *testing.T) {
	var c versionCache
	c.put(2, 1, "k", "old") // generation moved from 1 to 2 while computing
	if _, ok := c.get(2, "k"); ok {
		t.Fatal("a version computed at an older generation must not be cached")
	}
	c.put(2, 2, "k", "new")
	if v, ok := c.get(2, "k"); !ok || v != "new" {
		t.Fatalf("got %q %v, want new", v, ok)
	}
	if _, ok := c.get(3, "k"); ok {
		t.Fatal("a newer generation must invalidate every entry")
	}
	// A lookup with a stale generation read must not wipe newer entries.
	c.put(3, 3, "k", "v3")
	if _, ok := c.get(2, "k"); ok {
		t.Fatal("stale generation must miss")
	}
	if v, ok := c.get(3, "k"); !ok || v != "v3" {
		t.Fatal("a stale lookup must not drop the current generation's entries")
	}
}

// Concurrent writers and cached readers: once the writers are done, the
// cached version always converges to the fresh one (run with -race).
func TestCachedConfigVersionConcurrentWrites(t *testing.T) {
	s := openTestStore(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = s.CachedConfigVersionForNode("agent-01", "")
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		if _, err := s.AddRule("deny", "d"+string(rune('a'+i%26))+".example.lan", "ads"); err != nil {
			t.Fatal(err)
		}
		if i%10 == 0 {
			_ = s.DeleteRule(int64(i/2 + 1))
		}
	}
	close(stop)
	wg.Wait()
	got, _ := s.CachedConfigVersionForNode("agent-01", "")
	want, _ := s.ConfigVersionForNode("agent-01", "")
	if got != want {
		t.Fatalf("cache did not converge after concurrent writes: %q != %q", got, want)
	}
}

// Routine classification (verdicts that are not enforced) must not
// invalidate cached versions; an enforced verdict must.
func TestUnenforcedClassificationKeepsCache(t *testing.T) {
	s := openTestStore(t)
	gen := s.configGen.Load()
	for _, c := range []Classification{
		{Domain: "clean.example.lan", Category: "news", Status: ClassClean},
		{Domain: "maybe.example.lan", Category: "ads", Block: true, Status: ClassSuggested},
		{Domain: "noblock.example.lan", Category: "ads", Block: false, Status: ClassAuto},
	} {
		if _, err := s.InsertClassification(c); err != nil {
			t.Fatal(err)
		}
	}
	if s.configGen.Load() != gen {
		t.Fatal("unenforced verdicts must not bump the config generation")
	}
	v0, _ := s.ConfigVersion()
	if _, err := s.InsertClassification(Classification{Domain: "bad.example.lan", Category: "malware", Block: true, Status: ClassApproved}); err != nil {
		t.Fatal(err)
	}
	if s.configGen.Load() == gen {
		t.Fatal("an enforced verdict must bump the config generation")
	}
	if v1, _ := s.ConfigVersion(); v1 == v0 {
		t.Fatal("test setup: an enforced verdict changes the version")
	}
}
