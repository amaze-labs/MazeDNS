package categories

import "testing"

func TestBuiltin(t *testing.T) {
	for name, want := range map[string]string{
		"www.apple.com.":             "technology",
		"rr3---sn-x.googlevideo.com": "streaming",
		"gemini.google.com":          "ai", // the most specific entry wins
		"www.google.com":             "search",
		"e1234.dscx.akamaiedge.net":  "cdn",
		"outlook.office365.com":      "email",
		"login.microsoftonline.com":  "productivity",
		"WWW.NETFLIX.COM.":           "streaming",
	} {
		if got, ok := Builtin(name); !ok || got != want {
			t.Errorf("Builtin(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"example.org", "notapple.com", "com", ""} {
		if got, ok := Builtin(name); ok {
			t.Errorf("Builtin(%q) = %q, want unknown", name, got)
		}
	}
}

// Every built-in label is a category of the taxonomy (and never "other" or
// "local", which come from elsewhere).
func TestBuiltinCategoriesValid(t *testing.T) {
	for d, c := range builtin {
		if !Valid(c) || c == Other || c == Local {
			t.Errorf("%s -> %q", d, c)
		}
	}
}

// Blocking search sends google.com, and the more specific entries under it
// in their own categories so agents don't block them as search.
func TestBuiltinDomains(t *testing.T) {
	got := BuiltinDomains(map[string]bool{"search": true})
	if got["google.com"] != "search" || got["gemini.google.com"] != "ai" || got["mail.google.com"] != "email" {
		t.Errorf("search blocked: google.com=%q gemini=%q mail=%q", got["google.com"], got["gemini.google.com"], got["mail.google.com"])
	}
	if _, ok := got["netflix.com"]; ok {
		t.Error("an unrelated category was sent")
	}
}
