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

	if _, err := s.AddRule("deny", "ads.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRule("deny", "ads.test"); err != nil { // upsert, must not duplicate
		t.Fatal(err)
	}
	rules, err := s.ListRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Action != "deny" || rules[0].Domain != "ads.test" {
		t.Fatalf("unexpected rules: %+v", rules)
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
	recent, err := s.RecentQueryLog(10)
	if err != nil || len(recent) != 1 || recent[0].Action != "blocked" {
		t.Fatalf("unexpected query log: %+v err=%v", recent, err)
	}
	if n, _ := s.CountQueryLog(); n != 1 {
		t.Fatalf("count=%d want 1", n)
	}
}
