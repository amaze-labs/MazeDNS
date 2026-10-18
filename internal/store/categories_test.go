package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openCatStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCategoryOverrides(t *testing.T) {
	s := openCatStore(t)
	if err := s.SetCategoryOverride("example.com", "shopping", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCategoryOverride("example.com", "news", "bob"); err != nil { // replaces
		t.Fatal(err)
	}
	ov, err := s.CategoryOverrides()
	if err != nil {
		t.Fatal(err)
	}
	if o := ov["example.com"]; o.Category != "news" || o.SetBy != "bob" || o.UpdatedAt == 0 || len(ov) != 1 {
		t.Fatalf("overrides = %+v", ov)
	}
	if err := s.DeleteCategoryOverride("example.com"); err != nil {
		t.Fatal(err)
	}
	if ov, _ := s.CategoryOverrides(); len(ov) != 0 {
		t.Fatalf("after delete: %+v", ov)
	}
}

func TestClassifierCategoriesAndContentBackfill(t *testing.T) {
	s := openCatStore(t)
	for _, c := range []Classification{
		{Domain: "evil.com", Category: "phishing", Block: true, Status: ClassAuto},       // enforced
		{Domain: "maybe.com", Category: "phishing", Block: true, Status: ClassSuggested}, // not enforced
		{Domain: "shop.com", Category: "other", Status: ClassClean, ContentCategory: "shopping", ContentChecked: true},
		{Domain: "legacy.com", Category: "streaming", Status: ClassClean}, // a content verdict from before
		{Domain: "unknown.com", Category: "other", Status: ClassClean},
	} {
		if _, err := s.InsertClassification(c); err != nil {
			t.Fatal(err)
		}
	}
	// A verdict from before categories carried the model's content label as its
	// category; the migration moves it.
	if err := s.moveVerdictContentCategories(); err != nil {
		t.Fatal(err)
	}
	vc, err := s.ClassifierCategories()
	if err != nil {
		t.Fatal(err)
	}
	if vc.Enforced["evil.com"] != "phishing" || vc.Enforced["maybe.com"] != "" {
		t.Errorf("enforced = %v", vc.Enforced)
	}
	if vc.Content["shop.com"] != "shopping" || vc.Content["legacy.com"] != "streaming" || vc.Content["unknown.com"] != "" {
		t.Errorf("content = %v", vc.Content)
	}

	unchecked, err := s.UncheckedContent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(unchecked) != 3 { // all but shop.com and legacy.com (moved = answered)
		t.Fatalf("unchecked = %v, want 3", unchecked)
	}
	if err := s.SetContentCategory("unknown.com", "news"); err != nil {
		t.Fatal(err)
	}
	if unchecked, _ = s.UncheckedContent(10); len(unchecked) != 2 {
		t.Errorf("after answering one: unchecked = %v", unchecked)
	}
	if vc, _ = s.ClassifierCategories(); vc.Content["unknown.com"] != "news" {
		t.Errorf("model answer not used: %v", vc.Content)
	}
}

// Content categories go into the query log, can be filtered on, roll up by
// category for the dashboard and break down per client.
func TestContentCategoryLogAndRollup(t *testing.T) {
	s := openCatStore(t)
	now := time.Now().UnixMilli()
	if err := s.InsertNodeQueryLog("agent-1", []QueryLogEntry{
		{TS: now, Client: "10.0.0.1", Name: "facebook.com.", QType: "A", Action: "forward", Rcode: "NOERROR", ContentCategory: "social"},
		{TS: now, Client: "10.0.0.1", Name: "www.facebook.com.", QType: "A", Action: "cache", Rcode: "NOERROR", ContentCategory: "social"},
		{TS: now, Client: "10.0.0.2", Name: "bet.example.", QType: "A", Action: "blocked", Category: "gambling", Rcode: "NXDOMAIN", ContentCategory: "gambling"},
		{TS: now, Client: "10.0.0.2", Name: "old.example.", QType: "A", Action: "forward", Rcode: "NOERROR"}, // before categories
	}); err != nil {
		t.Fatal(err)
	}
	got, total, err := s.SearchQueryLog(QueryLogQuery{Content: "social"})
	if err != nil || total != 2 || len(got) != 2 || got[0].ContentCategory != "social" {
		t.Fatalf("content filter: total %d %+v err %v", total, got, err)
	}

	for more := true; more; {
		if more, err = s.RollupAdvance(1000); err != nil {
			t.Fatal(err)
		}
	}
	cats, err := s.RollupByCategory(now-3600_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 2 || cats[0] != (ContentCount{"social", 2, 0}) || cats[1] != (ContentCount{"gambling", 1, 1}) {
		t.Fatalf("rollup = %+v", cats)
	}
	if cats, _ = s.RollupByCategory(now-3600_000, []string{"other-agent"}); len(cats) != 0 {
		t.Errorf("node filter: %+v", cats)
	}

	d, err := s.ClientDetailStats("10.0.0.1", now-3600_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Content) != 1 || d.Content[0] != (CategoryCount{"social", 2}) {
		t.Errorf("client content = %+v", d.Content)
	}

	// Renaming a node carries its category rollup along.
	id, err := s.CreateNode("agent-1", "hash", "pfx")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RenameNode(id, "agent-renamed"); err != nil {
		t.Fatal(err)
	}
	if cats, _ = s.RollupByCategory(now-3600_000, []string{"agent-renamed"}); len(cats) != 2 {
		t.Errorf("after rename: %+v", cats)
	}
}

// The migration moves a verdict's content label into content_category and
// leaves the verdict category "other"; security and "other" verdicts stay; a
// content category the model already gave wins; running it again changes
// nothing.
func TestMoveVerdictContentCategories(t *testing.T) {
	s := openCatStore(t)
	for _, c := range []Classification{
		{Domain: "legacy.com", Category: "streaming", Status: ClassClean},
		{Domain: "allowed.com", Category: "news", Status: ClassRejected},
		{Domain: "both.com", Category: "gaming", Status: ClassClean, ContentCategory: "shopping", ContentChecked: true},
		{Domain: "evil.com", Category: "phishing", Block: true, Status: ClassAuto},
		{Domain: "plain.com", Category: "other", Status: ClassClean},
	} {
		if _, err := s.InsertClassification(c); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := s.moveVerdictContentCategories(); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string][2]string{}
	items, err := s.ListClassifications("", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range items {
		got[c.Domain] = [2]string{c.Category, c.ContentCategory}
	}
	for d, want := range map[string][2]string{
		"legacy.com":  {"other", "streaming"},
		"allowed.com": {"other", "news"},
		"both.com":    {"other", "shopping"},
		"evil.com":    {"phishing", ""},
		"plain.com":   {"other", ""},
	} {
		if got[d] != want {
			t.Errorf("%s: (category, content) = %v, want %v", d, got[d], want)
		}
	}
}
