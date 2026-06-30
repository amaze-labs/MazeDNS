package classifier

import "testing"

// TrustedSet.Hits returns the per-domain source count for a counted (threat) set,
// and a 0/1 presence flag for an uncounted (trusted) set.
func TestTrustedSetHits(t *testing.T) {
	counted := &TrustedSet{
		domains: map[string]struct{}{"a.com": {}, "b.com": {}, "c.com": {}},
		counts:  map[string]int{"a.com": 3, "b.com": 1},
	}
	if got := counted.Hits("sub.a.com"); got != 3 { // registered-domain folding
		t.Errorf("a.com hits = %d, want 3", got)
	}
	if got := counted.Hits("b.com"); got != 1 {
		t.Errorf("b.com hits = %d, want 1", got)
	}
	if got := counted.Hits("nope.com"); got != 0 {
		t.Errorf("absent hits = %d, want 0", got)
	}

	uncounted := &TrustedSet{domains: map[string]struct{}{"x.com": {}}}
	if got := uncounted.Hits("x.com"); got != 1 {
		t.Errorf("uncounted present hits = %d, want 1", got)
	}
	if got := uncounted.Hits("y.com"); got != 0 {
		t.Errorf("uncounted absent hits = %d, want 0", got)
	}
}

// The threat deduction scales with corroboration, and only a multi-feed hit is a
// "strong" (floor-bypassing) signal.
func TestThreatTiers(t *testing.T) {
	deltaOf := func(in ScoreInput) int {
		for _, f := range computeScore(in).Factors {
			if f.Label == "Threat intel" {
				return f.Delta
			}
		}
		return 0
	}
	young := WhoisInfo{AgeDays: 10}
	if d := deltaOf(ScoreInput{Domain: "e.example", ThreatHits: 1, Whois: young}); d != -45 {
		t.Errorf("1 feed delta = %d, want -45", d)
	}
	if d := deltaOf(ScoreInput{Domain: "e.example", ThreatHits: 2, Whois: young}); d != -70 {
		t.Errorf("2 feeds delta = %d, want -70", d)
	}
	if d := deltaOf(ScoreInput{Domain: "e.example", ThreatHits: 5, Whois: young}); d != -90 {
		t.Errorf("3+ feeds delta = %d, want -90", d)
	}
	if (ScoreInput{ThreatHits: 1}).StrongThreat() {
		t.Error("a single feed must not be a strong threat")
	}
	if !(ScoreInput{ThreatHits: 2}).StrongThreat() {
		t.Error("two feeds must be a strong threat")
	}
}
