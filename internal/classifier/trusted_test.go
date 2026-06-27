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

func TestEffectiveTrusted(t *testing.T) {
	// Blank -> built-in public default.
	if url, topN := effectiveTrusted(Settings{}); url != DefaultTrustedURL || topN != DefaultTrustedTopN {
		t.Errorf("blank should use default: %q %d", url, topN)
	}
	// "off" -> disabled.
	if url, _ := effectiveTrusted(Settings{TrustedListURL: "off"}); url != "" {
		t.Errorf("off should disable, got %q", url)
	}
	// Custom URL is used as-is.
	if url, topN := effectiveTrusted(Settings{TrustedListURL: "https://x/list.csv", TrustedTopN: 5}); url != "https://x/list.csv" || topN != 5 {
		t.Errorf("custom not honored: %q %d", url, topN)
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
