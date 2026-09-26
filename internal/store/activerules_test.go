package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"unsafe"
)

// seedListRules creates an enabled list holding n deny rules and returns the store.
func seedListRules(tb testing.TB, n int) *Store {
	tb.Helper()
	s, err := Open(filepath.Join(tb.TempDir(), "test.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { s.Close() })
	id, err := s.CreateList("blocklist", "url", "https://lists.example.lan/hosts", "ads", 0)
	if err != nil {
		tb.Fatal(err)
	}
	rules := make([]Rule, n)
	for i := range rules {
		rules[i] = Rule{Action: "deny", Domain: fmt.Sprintf("host-%06d.ads.example.lan", i)}
	}
	if _, err := s.ReplaceListRules(id, "ads", rules); err != nil {
		tb.Fatal(err)
	}
	return s
}

func TestActiveRulesFiltersAndInterns(t *testing.T) {
	s := seedListRules(t, 3)
	if _, err := s.AddRule("allow", "ok.example.lan", "custom"); err != nil {
		t.Fatal(err)
	}
	off, err := s.CreateList("disabled", "paste", "", "malware", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceListRules(off, "malware", []Rule{{Action: "deny", Domain: "off.example.lan"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetListEnabled(off, false); err != nil {
		t.Fatal(err)
	}

	rules, err := s.ActiveRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("want 3 list rules + 1 manual rule (disabled list excluded), got %d: %+v", len(rules), rules)
	}
	for i := 1; i < len(rules); i++ {
		if rules[i-1].Domain > rules[i].Domain {
			t.Fatalf("rules not ordered by domain: %+v", rules)
		}
	}
	var deny []Rule
	for _, r := range rules {
		if r.Domain == "ok.example.lan" {
			if r.Action != "allow" || r.Category != "custom" || !r.Enabled || r.ListID != 0 {
				t.Fatalf("manual rule scanned wrong: %+v", r)
			}
			continue
		}
		if r.Action != "deny" || r.Category != "ads" || !r.Enabled || r.ListID == 0 || r.ID == 0 || r.UpdatedAt == 0 {
			t.Fatalf("list rule scanned wrong: %+v", r)
		}
		deny = append(deny, r)
	}
	// Interned: every row shares one backing string for the same value.
	if len(deny) < 2 || !sameString(deny[0].Category, deny[1].Category) || !sameString(deny[0].Action, deny[1].Action) {
		t.Fatal("action/category should be interned across rows")
	}
}

// sameString reports whether a and b share one backing array (interned).
func sameString(a, b string) bool {
	return a == b && unsafe.StringData(a) == unsafe.StringData(b)
}

func BenchmarkActiveRules(b *testing.B) {
	s := seedListRules(b, 50000)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := s.ActiveRules(); err != nil {
			b.Fatal(err)
		}
	}
}
