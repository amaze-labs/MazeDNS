package classifier

import "testing"

func block(cat string, conf float64) Verdict { return Verdict{Category: cat, Confidence: conf} }

func TestComputeScore(t *testing.T) {
	tests := []struct {
		name      string
		in        ScoreInput
		wantBlock bool // candidate && legitimacy < blockThreshold
		minLegit  int  // floor we expect (0 = don't check)
		maxLegit  int  // ceiling we expect (0 = don't check)
	}{
		{
			name:     "trusted list overrides a confident phishing verdict",
			in:       ScoreInput{Domain: "spotify.com", ListTrusted: true, Whois: WhoisInfo{AgeDays: 5000}, Verdict: block("phishing", 1.0)},
			minLegit: 100, maxLegit: 100,
		},
		{
			name:     "nameservers on trusted infra override phishing (aaplimg.com)",
			in:       ScoreInput{Domain: "aaplimg.com", NSTrustedOn: "apple.com", Whois: WhoisInfo{AgeDays: 4800}, Verdict: block("phishing", 1.0)},
			minLegit: 100, maxLegit: 100,
		},
		{
			name:      "young domain the model calls phishing is blocked",
			in:        ScoreInput{Domain: "secure-login-appie.xyz", Whois: WhoisInfo{AgeDays: 10}, Verdict: block("phishing", 0.8)},
			wantBlock: true, maxLegit: blockThreshold - 1,
		},
		{
			name:      "threat-feed hit blocks even when the model missed it",
			in:        ScoreInput{Domain: "evil.example", Threat: true, Whois: WhoisInfo{AgeDays: 4000}, Verdict: block("other", 0.4)},
			wantBlock: true, maxLegit: blockThreshold - 1,
		},
		{
			name: "established domain the model alone flags is NOT blocked",
			in:   ScoreInput{Domain: "oldcorp.com", Whois: WhoisInfo{AgeDays: 5000}, Verdict: block("phishing", 0.9)},
			// established floor keeps it >= blockThreshold
			minLegit: establishedFloor,
		},
		{
			name: "young but legitimate (model says content) is not blocked",
			in:   ScoreInput{Domain: "newstartup.com", Whois: WhoisInfo{AgeDays: 20}, Verdict: block("technology", 0.9)},
			// young deducts, but no threat indicator -> not a block candidate
			minLegit: 1,
		},
		{
			name:      "VirusTotal-malicious blocks even with a benign model verdict",
			in:        ScoreInput{Domain: "evil.example", Whois: WhoisInfo{AgeDays: 3000}, Rep: Reputation{VTChecked: true, VTMalicious: 6}, Verdict: block("other", 0.3)},
			wantBlock: true, maxLegit: blockThreshold - 1,
		},
		{
			name: "VirusTotal-clean floors a secondary app domain the model flags (tiktokv.eu)",
			in:   ScoreInput{Domain: "tiktokv.eu", Whois: WhoisInfo{AgeDays: 1500}, Rep: Reputation{VTChecked: true, VTHarmless: 80}, Verdict: block("phishing", 1.0)},
			// VT-clean floor keeps it >= blockThreshold despite a confident phishing verdict
			minLegit: reputationFloor,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := computeScore(tt.in)
			candidate := tt.in.Verdict.ShouldBlock() || tt.in.Threat || tt.in.RepMalicious()
			gotBlock := candidate && s.Legitimacy < blockThreshold
			if gotBlock != tt.wantBlock {
				t.Errorf("block = %v (legit %d), want %v", gotBlock, s.Legitimacy, tt.wantBlock)
			}
			if tt.minLegit != 0 && s.Legitimacy < tt.minLegit {
				t.Errorf("legitimacy %d < min %d (factors %+v)", s.Legitimacy, tt.minLegit, s.Factors)
			}
			if tt.maxLegit != 0 && s.Legitimacy > tt.maxLegit {
				t.Errorf("legitimacy %d > max %d (factors %+v)", s.Legitimacy, tt.maxLegit, s.Factors)
			}
			if len(s.Factors) == 0 {
				t.Errorf("expected at least one factor in the breakdown")
			}
		})
	}
}

func TestRiskyTLDAndLexical(t *testing.T) {
	if _, risky := riskyTLD("foo.xyz"); !risky {
		t.Error(".xyz should be flagged risky")
	}
	if _, risky := riskyTLD("foo.com"); risky {
		t.Error(".com should not be flagged risky")
	}
	if fs := lexicalFactors("xn--pple-43d.com"); len(fs) == 0 {
		t.Error("punycode should produce a lexical factor")
	}
	if fs := lexicalFactors("google.com"); len(fs) != 0 {
		t.Errorf("clean name should have no lexical factors, got %+v", fs)
	}
}
