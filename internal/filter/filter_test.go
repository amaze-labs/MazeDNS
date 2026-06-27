package filter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsBlocked(t *testing.T) {
	e := New()
	e.Add("doubleclick.net", "ads")
	e.Add("ads.example.com", "trackers")

	cases := map[string]bool{
		"doubleclick.net.":                true,  // exact (FQDN form)
		"ad.doubleclick.net.":             true,  // subdomain of a blocked domain
		"securepubads.g.doubleclick.net.": true,  // deep subdomain inherits the block
		"DOUBLECLICK.NET":                 true,  // case-insensitive
		"example.com.":                    false, // parent of a blocked domain is not blocked
		"ads.example.com":                 true,
		"notads.example.com":              false,
		"safe.org.":                       false,
	}
	for name, want := range cases {
		if got := e.IsBlocked(name); got != want {
			t.Errorf("IsBlocked(%q) = %v, want %v", name, got, want)
		}
	}

	if cat, ok := e.Match("ad.doubleclick.net"); !ok || cat != "ads" {
		t.Errorf("Match category = %q,%v; want \"ads\",true", cat, ok)
	}
}

func TestLoadHostsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "block.hosts")
	content := "# comment\n0.0.0.0 tracker.test\n127.0.0.1 ads.test # inline\nplaindomain.test\nlocalhost\n\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New()
	n, err := e.LoadHostsFile(path, "custom")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("loaded %d domains, want 3", n)
	}
	for _, d := range []string{"tracker.test", "ads.test", "plaindomain.test"} {
		if !e.IsBlocked(d) {
			t.Errorf("expected %q to be blocked", d)
		}
	}
	if e.IsBlocked("localhost") {
		t.Error("localhost should have been skipped")
	}
}
