package classifier

import (
	"strings"
	"testing"
)

func TestParseTrustedFormats(t *testing.T) {
	// Mixed formats: plain, Tranco (rank,domain), Majestic (domain in col 3),
	// hosts, header row, comment, subdomain.
	in := `# comment
GlobalRank,TldRank,Domain,TLD,RefSubNets
example.com
1,google.com
2,2,majestic.com,com,123456
0.0.0.0 microsoft.com
www.github.com
`
	set, err := parseTrusted(strings.NewReader(in), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"example.com", "google.com", "majestic.com", "microsoft.com", "github.com"} {
		if !set.Has(d) {
			t.Errorf("expected %q trusted", d)
		}
	}
	// Matching is by registered domain, so subdomains of a trusted domain match.
	if !set.Has("api.github.com") {
		t.Error("subdomain of a trusted domain should match")
	}
	if set.Has("evil.test") {
		t.Error("unlisted domain must not match")
	}
}

func TestTrustedSources(t *testing.T) {
	// Default: the built-in public list at the default cap.
	src := trustedSources(Settings{})
	if len(src) != 1 || src[0].url != DefaultTrustedURL || src[0].topN != DefaultTrustedTopN {
		t.Fatalf("default trusted sources: %+v", src)
	}
	// Disable default + add custom.
	src = trustedSources(Settings{TrustedDisableDefault: true, TrustedListURL: "https://x/list.csv"})
	if len(src) != 1 || src[0].url != "https://x/list.csv" {
		t.Fatalf("custom-only trusted sources: %+v", src)
	}
	// Disable default, no custom -> none.
	if src = trustedSources(Settings{TrustedDisableDefault: true}); len(src) != 0 {
		t.Fatalf("disabled trusted sources should be empty: %+v", src)
	}
	// Default + custom -> both.
	if src = trustedSources(Settings{TrustedListURL: "https://x/list.csv"}); len(src) != 2 {
		t.Fatalf("default+custom should give two sources: %+v", src)
	}
}

func TestThreatSources(t *testing.T) {
	// Legacy settings (no ThreatFeeds): fall back to the single urlhaus default.
	if src := threatSources(Settings{}); len(src) != 1 || src[0].url != DefaultThreatURL {
		t.Fatalf("default threat sources: %+v", src)
	}
	if src := threatSources(Settings{ThreatDisableDefault: true}); len(src) != 0 {
		t.Fatalf("disabled threat sources should be empty: %+v", src)
	}
	// Multiple built-in feeds + multiple custom sources, de-duplicated; unknown
	// feed keys are skipped.
	src := threatSources(Settings{
		ThreatFeeds:   []string{"urlhaus", "threatfox", "nope"},
		ThreatListURL: "https://x/a.txt\nhttps://x/b.txt , https://x/a.txt",
	})
	if len(src) != 4 { // urlhaus + threatfox + a.txt + b.txt (dup a.txt dropped)
		t.Fatalf("expected 4 deduped sources, got %d: %+v", len(src), src)
	}
}

func TestParseTrustedURLs(t *testing.T) {
	// URL-based feeds (e.g. OpenPhish) — extract the host.
	set, err := parseTrusted(strings.NewReader("http://evil.com/malware\nhttps://login.bad.example.org/x\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Has("evil.com") || !set.Has("example.org") {
		t.Errorf("URL hosts not extracted: %v", set.domains)
	}
}

func TestParseTrustedTopN(t *testing.T) {
	in := "a.com\nb.com\nc.com\nd.com\n"
	set, err := parseTrusted(strings.NewReader(in), 2)
	if err != nil {
		t.Fatal(err)
	}
	if set.Count() != 2 {
		t.Fatalf("topN cap not applied: count=%d", set.Count())
	}
}

func TestTrustedNilSafe(t *testing.T) {
	var set *TrustedSet
	if set.Has("anything.com") || set.Count() != 0 {
		t.Error("nil TrustedSet must be safe and empty")
	}
}
