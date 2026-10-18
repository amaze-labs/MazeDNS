package classifier

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// The first source that knows a domain wins: override, enforced security
// verdict, category database, the built-in list, the model's content
// category, then "other".
func TestCategorizerPrecedence(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	var b categories.Builder
	b.Add("facebook.com", "social")
	b.Add("override.com", "news")
	b.Add("evil-shop.com", "shopping")
	db := categories.NewLoadedHolder(b.Build())

	for _, c := range []store.Classification{
		{Domain: "evil-shop.com", Category: "phishing", Block: true, Status: store.ClassAuto},
		{Domain: "modelled.com", Category: "other", Status: store.ClassClean, ContentCategory: "gaming", ContentChecked: true},
		{Domain: "facebook.com", Category: "other", Status: store.ClassClean, ContentCategory: "news", ContentChecked: true},
	} {
		if _, err := st.InsertClassification(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetCategoryOverride("override.com", "finance", "alice"); err != nil {
		t.Fatal(err)
	}
	c := NewCategorizer(st, db)
	if err := c.Refresh(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][2]string{
		"www.override.com.": {"finance", SourceOverride},    // beats the database
		"evil-shop.com":     {"phishing", SourceClassifier}, // an enforced verdict beats the database
		"m.facebook.com":    {"social", SourceDatabase},     // the database beats the model
		"api.modelled.com":  {"gaming", SourceModel},        // the model fills in
		"nobody-knows.org":  {"other", SourceNone},
	} {
		cat, src := c.Category(name)
		if cat != want[0] || src != want[1] {
			t.Errorf("Category(%q) = %q from %q, want %q from %q", name, cat, src, want[0], want[1])
		}
	}

	entries := []store.QueryLogEntry{{Name: "facebook.com."}, {Name: "x.nobody-knows.org."}}
	c.Label(entries)
	if entries[0].ContentCategory != "social" || entries[1].ContentCategory != "other" {
		t.Errorf("Label = %+v", entries)
	}

	// Without a category database the built-in list and the model still apply
	// (the built-in list first: facebook.com is a platform it knows).
	c2 := NewCategorizer(st, nil)
	_ = c2.Refresh()
	if cat, src := c2.Category("facebook.com"); cat != "social" || src != SourceBuiltin {
		t.Errorf("no database: facebook.com = %q from %q, want the built-in social", cat, src)
	}
	if cat, _ := c2.Category("modelled.com"); cat != "gaming" {
		t.Errorf("no database: modelled.com = %q, want the model's gaming", cat)
	}
}

func TestIsLocalName(t *testing.T) {
	for name, want := range map[string]bool{
		"1.0.168.192.in-addr.arpa.": true,
		"b.a.9.8.ip6.arpa":          true,
		"nas.lan.":                  true,
		"printer.home.arpa":         true,
		"db.internal":               true,
		"macbook.local":             true,
		"nas":                       true, // single label
		"www.example.com":           false,
		"foo.test":                  false, // reserved for testing, not a network's own name
		"google.com":                false,
		"":                          false,
	} {
		if got := IsLocalName(name); got != want {
			t.Errorf("IsLocalName(%q) = %v, want %v", name, got, want)
		}
	}
}

// Local names are labelled "local" (an operator's override still wins); every
// other name goes through the usual sources.
func TestCategorizerLocal(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := NewCategorizer(st, nil)
	for _, name := range []string{"10.1.168.192.in-addr.arpa.", "nas.lan.", "printer."} {
		if cat, src := c.Category(name); cat != categories.Local || src != SourceLocal {
			t.Errorf("%s = %s (%s), want local", name, cat, src)
		}
	}
	if cat, _ := c.Category("unknown-site.com."); cat != categories.Other {
		t.Errorf("unknown-site.com = %s", cat)
	}
}

// A domain's first queries arrive before the classifier has labelled it, so
// they land in "other". Relabel moves them — and the dashboard's per-hour
// counts — once the domain has a category, and leaves the rest alone.
func TestCategorizerRelabel(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var b categories.Builder
	b.Add("facebook.com", "social")
	c := NewCategorizer(st, categories.NewLoadedHolder(b.Build()))

	now := time.Now().UnixMilli()
	q := func(name, action string) store.QueryLogEntry {
		return store.QueryLogEntry{TS: now, Client: "10.0.0.2", Name: name, QType: "A", Action: action, Rcode: "NOERROR"}
	}
	// Labelled on arrival, before the model knew newsite.com.
	first := []store.QueryLogEntry{q("www.newsite.com.", "forward"), q("cdn.newsite.com.", "blocked"),
		q("x.nobody-knows.org.", "forward"), q("www.facebook.com.", "forward"), q("nas.lan.", "forward")}
	first[4].ContentCategory = "other" // as an older control plane labelled it
	c.Label(first[:4])
	if err := st.InsertNodeQueryLog("agent-a", first); err != nil {
		t.Fatal(err)
	}
	for more := true; more; {
		if more, err = st.RollupAdvance(0); err != nil {
			t.Fatal(err)
		}
	}
	// Not yet folded into the rollup when the relabel runs.
	if err := st.InsertNodeQueryLog("agent-a", []store.QueryLogEntry{{TS: now, Name: "api.newsite.com.", Action: "forward", ContentCategory: "other"}}); err != nil {
		t.Fatal(err)
	}

	if _, err := st.InsertClassification(store.Classification{Domain: "newsite.com", Category: "other", Status: store.ClassClean,
		ContentCategory: "shopping", ContentChecked: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(); err != nil {
		t.Fatal(err)
	}
	n, err := c.Relabel(time.Now().Add(-time.Hour))
	if err != nil || n != 4 {
		t.Fatalf("Relabel moved %d, err %v; want 4 (3 newsite.com queries, 1 local name)", n, err)
	}
	for more := true; more; {
		if more, err = st.RollupAdvance(0); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string][2]int64{}
	rows, err := st.RollupByCategory(now-time.Hour.Milliseconds(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		got[r.Category] = [2]int64{r.Count, r.Blocked}
	}
	want := map[string][2]int64{"shopping": {3, 1}, "social": {1, 0}, "local": {1, 0}, "other": {1, 0}}
	if len(got) != len(want) {
		t.Errorf("by category = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
	if n, _ := c.Relabel(time.Now().Add(-time.Hour)); n != 0 {
		t.Errorf("a second pass moved %d", n)
	}
}

// A query a local record answered is "local" whatever its name; a well-known
// platform the database doesn't list gets its built-in category; an
// operator's override still wins over both.
func TestCategorizerLocalAnswersAndBuiltin(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SetCategoryOverride("example-corp.com", "productivity", "admin"); err != nil {
		t.Fatal(err)
	}
	c := NewCategorizer(st, categories.NewLoadedHolder(new(categories.Builder).Build()))
	if err := c.Refresh(); err != nil {
		t.Fatal(err)
	}
	entries := []store.QueryLogEntry{
		{Name: "nas.amaze-labs.com.", Action: "rewrite"},        // the network's own name under a public domain
		{Name: "www.apple.com.", Action: "forward"},             // built-in
		{Name: "www.apple.com.", Action: "rewrite"},             // pinned locally: still local
		{Name: "intranet.example-corp.com.", Action: "rewrite"}, // override wins
		{Name: "unknown-thing.net.", Action: "forward"},
	}
	c.Label(entries)
	want := []string{"local", "technology", "local", "productivity", "other"}
	for i, e := range entries {
		if e.ContentCategory != want[i] {
			t.Errorf("%s (%s) = %q, want %q", e.Name, e.Action, e.ContentCategory, want[i])
		}
	}
	if cat, src := c.Category("e1.akamaiedge.net"); cat != "cdn" || src != SourceBuiltin {
		t.Errorf("akamaiedge = %s (%s)", cat, src)
	}

	// Rows labelled "other" before this (older control plane) move too.
	now := time.Now().UnixMilli()
	if err := st.InsertNodeQueryLog("a", []store.QueryLogEntry{
		{TS: now, Name: "nas.amaze-labs.com.", Action: "rewrite", ContentCategory: "other"},
		{TS: now, Name: "www.netflix.com.", Action: "forward", ContentCategory: "other"},
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Relabel(time.Now().Add(-time.Hour)); err != nil || n != 2 {
		t.Errorf("relabel moved %d, err %v; want 2", n, err)
	}
}
