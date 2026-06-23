package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRulesRewritesAndLog(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.AddRule("deny", "ads.test", "malware"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRule("deny", "ads.test", "malware"); err != nil { // upsert, must not duplicate
		t.Fatal(err)
	}
	rules, err := s.ListRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Action != "deny" || rules[0].Domain != "ads.test" || rules[0].Category != "malware" {
		t.Fatalf("unexpected rules: %+v", rules)
	}

	// Bulk import upserts (no duplicate for ads.test) and adds the new domain.
	if n, err := s.AddRulesBulk([]Rule{
		{Action: "deny", Domain: "ads.test", Category: "ads"},
		{Action: "deny", Domain: "tracker.test", Category: "trackers"},
	}); err != nil || n != 2 {
		t.Fatalf("bulk import n=%d err=%v", n, err)
	}
	if all, _ := s.ListRules(); len(all) != 2 {
		t.Fatalf("after bulk import want 2 rules, got %d", len(all))
	}

	if _, err := s.AddRewrite("host.lan", "A", "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	rws, err := s.ListRewrites()
	if err != nil || len(rws) != 1 || rws[0].Value != "10.0.0.5" {
		t.Fatalf("unexpected rewrites: %+v err=%v", rws, err)
	}

	if err := s.InsertQueryLogBatch([]QueryLogEntry{
		{TS: time.Now().UnixMilli(), Client: "1.2.3.4", Name: "x.test.", QType: "A", Action: "blocked", Rcode: "NXDOMAIN", ElapsedMS: 1},
	}); err != nil {
		t.Fatal(err)
	}
	recent, total, err := s.SearchQueryLog("", 10, 0)
	if err != nil || total != 1 || len(recent) != 1 || recent[0].Action != "blocked" {
		t.Fatalf("unexpected query log: %+v total=%d err=%v", recent, total, err)
	}
	if n, _ := s.CountQueryLog(); n != 1 {
		t.Fatalf("count=%d want 1", n)
	}
}
