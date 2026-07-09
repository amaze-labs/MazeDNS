package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestCanonicalScope(t *testing.T) {
	// Empty type defaults to all; values are ignored for 'all'.
	st, vals, err := CanonicalScope("", nil)
	if err != nil || st != ScopeAll || vals != "[]" {
		t.Fatalf("default: got (%q,%q,%v), want (all,[],nil)", st, vals, err)
	}
	// Values are trimmed, deduped, sorted -> canonical JSON.
	st, vals, err = CanonicalScope("nodes", []string{" b ", "a", "b", ""})
	if err != nil || st != ScopeNodes || vals != `["a","b"]` {
		t.Fatalf("canonical: got (%q,%q,%v), want (nodes,[\"a\",\"b\"],nil)", st, vals, err)
	}
	// A scoped type with no values is an error.
	if _, _, err := CanonicalScope("sites", []string{"  "}); err == nil {
		t.Fatal("sites with no values should error")
	}
	// Unknown types are errors.
	if _, _, err := CanonicalScope("bogus", []string{"x"}); err == nil {
		t.Fatal("unknown scope type should error")
	}
}

func TestScopeMatches(t *testing.T) {
	cases := []struct {
		st, vals, name, site string
		want                 bool
	}{
		{ScopeAll, "[]", "n1", "", true},
		{ScopeNodes, `["n1","n2"]`, "n1", "", true},
		{ScopeNodes, `["n2"]`, "n1", "", false},
		{ScopeSites, `["office"]`, "n1", "office", true},
		{ScopeSites, `["office"]`, "n1", "lab", false},
		{ScopeSites, `["office"]`, "n1", "", false}, // unassigned node matches no site scope
	}
	for _, c := range cases {
		if got := ScopeMatches(c.st, c.vals, c.name, c.site); got != c.want {
			t.Errorf("ScopeMatches(%q,%q,%q,%q) = %v, want %v", c.st, c.vals, c.name, c.site, got, c.want)
		}
	}
}

func TestScopeValuesIntersect(t *testing.T) {
	if !scopeValuesIntersect(`["a","b"]`, `["b","c"]`) {
		t.Fatal("expected intersection on b")
	}
	if scopeValuesIntersect(`["a"]`, `["b"]`) {
		t.Fatal("expected no intersection")
	}
}

func TestScopeRank(t *testing.T) {
	if !(scopeRank(ScopeNodes) > scopeRank(ScopeSites) && scopeRank(ScopeSites) > scopeRank(ScopeAll)) {
		t.Fatal("rank order must be nodes > sites > all")
	}
}

func TestScopedRewritesSplitHorizon(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Same domain+rrtype under two different site scopes must coexist.
	if _, err := s.AddRewriteScoped("nas.home", "A", "10.0.0.5", ScopeSites, []string{"site-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRewriteScoped("nas.home", "A", "192.168.1.5", ScopeSites, []string{"site-b"}); err != nil {
		t.Fatalf("split-horizon insert rejected: %v", err)
	}
	// Re-adding the same domain+scope upserts (no third row).
	if _, err := s.AddRewriteScoped("nas.home", "A", "10.0.0.6", ScopeSites, []string{"site-a"}); err != nil {
		t.Fatal(err)
	}
	rws, err := s.ListRewrites()
	if err != nil || len(rws) != 2 {
		t.Fatalf("want 2 rewrites, got %d (err=%v)", len(rws), err)
	}
	// Scope fields round-trip through ListRewrites.
	found := false
	for _, r := range rws {
		if r.Value == "10.0.0.6" {
			found = true
			if r.ScopeType != ScopeSites || len(r.ScopeValues) != 1 || r.ScopeValues[0] != "site-a" {
				t.Fatalf("scope not round-tripped: %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("upserted value not found")
	}

	// Legacy AddRewrite still works and lands in scope 'all'.
	if _, err := s.AddRewrite("printer.lan", "A", "10.0.0.9"); err != nil {
		t.Fatal(err)
	}

	// UpdateRewrite edits value/enabled/scope in place.
	id := rws[0].ID
	if err := s.UpdateRewrite(id, "10.9.9.9", false, ScopeNodes, []string{"n1"}); err != nil {
		t.Fatal(err)
	}
	rws, _ = s.ListRewrites()
	var got *Rewrite
	for i := range rws {
		if rws[i].ID == id {
			got = &rws[i]
		}
	}
	if got == nil || got.Value != "10.9.9.9" || got.Enabled || got.ScopeType != ScopeNodes {
		t.Fatalf("update not applied: %+v", got)
	}
}

func TestRewriteScopeConflict(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := s.AddRewriteScoped("app.corp", "A", "10.1.1.1", ScopeSites, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	// Intersecting site lists at the same specificity conflict.
	if c, _ := s.RewriteScopeConflict("app.corp", "A", ScopeSites, `["b","c"]`, 0); !c {
		t.Fatal("expected conflict on intersecting site lists")
	}
	// Disjoint lists don't.
	if c, _ := s.RewriteScopeConflict("app.corp", "A", ScopeSites, `["c"]`, 0); c {
		t.Fatal("disjoint site lists must not conflict")
	}
	// Different specificity doesn't conflict (precedence resolves it).
	if c, _ := s.RewriteScopeConflict("app.corp", "A", ScopeNodes, `["b"]`, 0); c {
		t.Fatal("node scope must not conflict with site scope")
	}
	// The row itself is excluded when editing.
	if c, _ := s.RewriteScopeConflict("app.corp", "A", ScopeSites, `["a","b"]`, id); c {
		t.Fatal("row must not conflict with itself when excluded")
	}
}

// An existing pre-scope database is rebuilt in place: rows preserved, scope
// defaulted to 'all', and the relaxed unique key allows split-horizon rows.
func TestRewritesScopeMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE rewrites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL, rrtype TEXT NOT NULL, value TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL,
		UNIQUE(domain, rrtype))`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO rewrites(domain, rrtype, value, enabled, updated_at) VALUES('old.lan','A','1.2.3.4',1,42)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rws, err := s.ListRewrites()
	if err != nil || len(rws) != 1 || rws[0].Domain != "old.lan" || rws[0].ScopeType != ScopeAll {
		t.Fatalf("migrated row wrong: %+v err=%v", rws, err)
	}
	// The relaxed key now permits a second scope for the same domain+rrtype.
	if _, err := s.AddRewriteScoped("old.lan", "A", "5.6.7.8", ScopeNodes, []string{"n1"}); err != nil {
		t.Fatalf("post-migration split-horizon insert failed: %v", err)
	}
}
