package store

import (
	"path/filepath"
	"testing"
)

func TestReplicatedRulesIncludesAIBlocks(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.AddRule("deny", "manual.test", "custom"); err != nil {
		t.Fatal(err)
	}
	v0, _ := s.ConfigVersion()

	// A suggested (pending) verdict must NOT be replicated yet.
	if _, err := s.InsertClassification(Classification{Domain: "trackerz.io", Category: "ads", Block: true, Status: ClassSuggested}); err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ReplicatedRules()
	if hasDeny(rules, "trackerz.io") {
		t.Error("suggested verdict should not be replicated until enforced")
	}

	// Auto-blocked verdict IS replicated as a deny rule, and bumps the version.
	if _, err := s.InsertClassification(Classification{Domain: "adnet.example", Category: "ads", Block: true, Status: ClassAuto}); err != nil {
		t.Fatal(err)
	}
	rules, _ = s.ReplicatedRules()
	if !hasDeny(rules, "adnet.example") {
		t.Fatalf("auto-blocked verdict must be replicated: %+v", rules)
	}
	if v1, _ := s.ConfigVersion(); v1 == v0 {
		t.Error("config version must change when an AI block is enforced (so workers re-sync)")
	}
}

func TestReplicatedRulesDedupesDenyAndAI(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.AddRule("deny", "dup.test", "custom"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertClassification(Classification{Domain: "dup.test", Category: "ads", Block: true, Status: ClassAuto}); err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ReplicatedRules()
	n := 0
	for _, r := range rules {
		if r.Domain == "dup.test" && r.Action == "deny" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("dup.test should appear once (no duplicate action,domain), got %d", n)
	}
}

func hasDeny(rules []Rule, domain string) bool {
	for _, r := range rules {
		if r.Domain == domain && r.Action == "deny" {
			return true
		}
	}
	return false
}
