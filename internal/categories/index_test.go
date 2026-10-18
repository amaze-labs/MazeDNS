package categories

import (
	"fmt"
	"testing"
)

func TestIndexLookup(t *testing.T) {
	var b Builder
	b.Add("facebook.com", "social")
	b.Add("Amazon.IT.", "shopping")
	b.Add("ads.example.com", "ads")
	b.Add("example.com", "news")
	b.Add("both.example", "shopping")
	b.Add("both.example", "phishing") // listed twice: the content category wins
	b.Add("ignored.example", "not-a-category")
	x := b.Build()

	for name, want := range map[string]string{
		"facebook.com":      "social",
		"www.facebook.com":  "social", // a subdomain inherits its parent's category
		"amazon.it":         "shopping",
		"ads.example.com":   "ads", // the most specific listed suffix wins
		"x.ads.example.com": "ads",
		"www.example.com":   "news",
		"both.example":      "shopping",
		"ignored.example":   "",
		"notlisted.org":     "",
		"com":               "",
	} {
		got, ok := x.Lookup(name)
		if got != want || ok != (want != "") {
			t.Errorf("Lookup(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	if n := x.Len(); n != 6 {
		t.Errorf("Len = %d, want 6", n)
	}
	if c := x.Counts(); c["shopping"] != 2 || c["phishing"] != 1 { // counts every listing
		t.Errorf("Counts = %v", c)
	}
}

func TestIndexDeduplicates(t *testing.T) {
	var b Builder
	for i := 0; i < 3; i++ {
		b.Add("dup.example", "social")
	}
	if x := b.Build(); x.Len() != 1 {
		t.Errorf("Len = %d, want 1", x.Len())
	}
}

// A nil or empty index finds nothing (an agent with no category blocked).
func TestIndexEmpty(t *testing.T) {
	var x *Index
	if _, ok := x.Lookup("example.com"); ok || x.Len() != 0 {
		t.Error("nil index matched")
	}
}

func BenchmarkIndexLookup(b *testing.B) {
	var bl Builder
	for i := 0; i < 1_000_000; i++ {
		bl.Add(fmt.Sprintf("d%d.example%d.com", i, i%1000), "adult")
	}
	x := bl.Build()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Lookup("www.sub.notlisted-domain.example.org")
	}
}

// Every category has a precedence, and precedence lists only real categories.
func TestPrecedenceCoversTaxonomy(t *testing.T) {
	if len(precedence) != len(All) {
		t.Fatalf("precedence has %d categories, taxonomy %d", len(precedence), len(All))
	}
	for _, id := range precedence {
		if !Valid(id) {
			t.Errorf("precedence lists unknown %q", id)
		}
	}
	for folder, cat := range ut1Folders {
		if !Valid(cat) {
			t.Errorf("UT1 folder %s maps to unknown %q", folder, cat)
		}
	}
}
