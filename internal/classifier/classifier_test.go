package classifier

import "testing"

func TestRegisteredDomain(t *testing.T) {
	cases := map[string]string{
		"securepubads.g.doubleclick.net.": "doubleclick.net",
		"www.example.com":                 "example.com",
		"a.b.c.example.co.uk":             "example.co.uk", // multi-part public suffix
		"example.com":                     "example.com",
		"":                                "",
	}
	for in, want := range cases {
		if got := RegisteredDomain(in); got != want {
			t.Errorf("RegisteredDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseVerdict(t *testing.T) {
	// Plain JSON.
	v, err := parseVerdict(`{"category":"ads","confidence":0.9,"reason":"ad server"}`)
	if err != nil || v.Category != "ads" || !v.ShouldBlock() {
		t.Fatalf("plain: %+v err=%v", v, err)
	}
	// Wrapped in markdown / prose (models often do this).
	v, err = parseVerdict("Sure!\n```json\n{\"category\":\"clean\",\"confidence\":0.8}\n```")
	if err != nil || v.Category != "clean" || v.ShouldBlock() {
		t.Fatalf("wrapped: %+v err=%v", v, err)
	}
	// Unknown category collapses to "other" (never blocks).
	v, _ = parseVerdict(`{"category":"weird"}`)
	if v.Category != "other" || v.ShouldBlock() {
		t.Errorf("unknown category should be other/non-blocking: %+v", v)
	}
	// No JSON at all -> error.
	if _, err := parseVerdict("I cannot help"); err == nil {
		t.Error("expected error when reply has no JSON")
	}
}

func TestShouldBlock(t *testing.T) {
	for _, c := range []string{"ads", "trackers", "malware", "phishing"} {
		if !(Verdict{Category: c}).ShouldBlock() {
			t.Errorf("%q should block", c)
		}
	}
	// Content categories are recorded but never blocked.
	for _, c := range []string{"clean", "other", "", "social", "streaming", "shopping", "news", "gaming"} {
		if (Verdict{Category: c}).ShouldBlock() {
			t.Errorf("%q should not block", c)
		}
	}
}

func TestContentCategoriesParsed(t *testing.T) {
	for _, c := range contentCategories {
		v, err := parseVerdict(`{"category":"` + c + `","confidence":0.8}`)
		if err != nil || v.Category != c {
			t.Errorf("content category %q not preserved: got %q err=%v", c, v.Category, err)
		}
		if v.ShouldBlock() {
			t.Errorf("content category %q must not block", c)
		}
	}
}
