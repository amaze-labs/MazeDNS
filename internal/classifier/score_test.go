package classifier

import (
	"strings"
	"testing"
)

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
			name:      "corroborated threat (2+ feeds) blocks even when the model missed it",
			in:        ScoreInput{Domain: "evil.example", Threat: true, ThreatHits: 2, Whois: WhoisInfo{AgeDays: 4000}, Verdict: block("other", 0.4)},
			wantBlock: true, maxLegit: blockThreshold - 1,
		},
		{
			name: "single-feed hit on an established domain is floored (possible misreport)",
			in:   ScoreInput{Domain: "oldcorp.com", Threat: true, ThreatHits: 1, Whois: WhoisInfo{AgeDays: 4000}},
			// one feed alone can't drag an established domain into block range
			minLegit: establishedFloor,
		},
		{
			name:      "single-feed hit on a YOUNG domain still blocks",
			in:        ScoreInput{Domain: "evil.example", Threat: true, ThreatHits: 1, Whois: WhoisInfo{AgeDays: 10}},
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
		// --- static-only path (no AI): the verdict is the zero value ---
		{
			name:      "static-only: corroborated threat (2 feeds) blocks with no model verdict",
			in:        ScoreInput{Domain: "evil.example", Threat: true, ThreatHits: 2, Whois: WhoisInfo{AgeDays: 4000}},
			wantBlock: true, maxLegit: blockThreshold - 1,
		},
		{
			name:      "static-only: VirusTotal-malicious blocks with no model verdict",
			in:        ScoreInput{Domain: "evil.example", Whois: WhoisInfo{AgeDays: 3000}, Rep: Reputation{VTChecked: true, VTMalicious: 6}},
			wantBlock: true, maxLegit: blockThreshold - 1,
		},
		{
			name: "static-only: clean unknown domain is not blocked without a threat indicator",
			in:   ScoreInput{Domain: "newstartup.com", Whois: WhoisInfo{AgeDays: 20}},
			// young deducts, but no threat/rep indicator and no model -> not a candidate
			minLegit: 1,
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

func TestAIConfigured(t *testing.T) {
	cases := []struct {
		name string
		s    Settings
		want bool
	}{
		{"both set", Settings{AIEnabled: true, Endpoint: "http://localhost:11434/v1", Model: "llama3.2"}, true},
		{"toggle off", Settings{AIEnabled: false, Endpoint: "http://localhost:11434/v1", Model: "llama3.2"}, false},
		{"endpoint only", Settings{AIEnabled: true, Endpoint: "http://localhost:11434/v1"}, false},
		{"model only (openai needs endpoint)", Settings{AIEnabled: true, Model: "llama3.2"}, false},
		{"anthropic needs only a model", Settings{AIEnabled: true, Provider: "anthropic", Model: "claude-haiku-4-5"}, true},
		{"neither (static only)", Settings{}, false},
		{"whitespace is blank", Settings{AIEnabled: true, Endpoint: "  ", Model: "\t"}, false},
	}
	for _, c := range cases {
		if got := aiConfigured(c.s); got != c.want {
			t.Errorf("%s: aiConfigured = %v, want %v", c.name, got, c.want)
		}
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

func TestBrandImpersonation(t *testing.T) {
	flagged := []string{
		"paypa1.com",              // homoglyph: 1 -> l
		"g00gle.net",              // homoglyph: 0 -> o
		"secure-paypal-login.xyz", // brand as a token
		"login-apple-id.top",      // brand as a token
	}
	for _, d := range flagged {
		label := d[:strings.IndexByte(d, '.')]
		if _, ok := brandImpersonationFactor(label); !ok {
			t.Errorf("%q should be flagged as brand impersonation", d)
		}
	}
	clean := []string{
		"paypal",     // the brand itself — not impersonation
		"google",     // the brand itself
		"applesauce", // contains "apple" but not as a separate token
		"mystartup",  // unrelated
	}
	for _, label := range clean {
		if f, ok := brandImpersonationFactor(label); ok {
			t.Errorf("%q should NOT be flagged, got %+v", label, f)
		}
	}
}
