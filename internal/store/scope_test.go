package store

import "testing"

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
