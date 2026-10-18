package classifier

import (
	"path/filepath"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// The first source that knows a domain wins: override, enforced security
// verdict, category database, the model's content category, then "other".
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

	// Without a category database the model and verdicts still apply.
	c2 := NewCategorizer(st, nil)
	_ = c2.Refresh()
	if cat, _ := c2.Category("facebook.com"); cat != "news" {
		t.Errorf("no database: facebook.com = %q, want the model's news", cat)
	}
}
