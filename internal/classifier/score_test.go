package classifier

import (
	"strings"
	"testing"
	"time"
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
			name: "a brand's own nameservers outweigh a confident phishing verdict (aaplimg.com)",
			in:   ScoreInput{Domain: "aaplimg.com", NSTrustedOn: "apple.com", Whois: WhoisInfo{AgeDays: 4800}, Verdict: block("phishing", 1.0)},
			// 85 + 20 (age) + 15 (own nameservers) − 50 (model) = 70
			minLegit: 70,
		},
		{
			name:      "own nameservers can't outvote a corroborated threat",
			in:        ScoreInput{Domain: "evil.com", NSTrustedOn: "apple.com", Threat: true, ThreatHits: 2, Whois: WhoisInfo{AgeDays: 4800}},
			wantBlock: true, maxLegit: blockThreshold - 1,
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

// fullTrust is every positive signal at once: an old, locked, owned, signed,
// clean domain.
func fullTrust() (WhoisInfo, Reputation) {
	return WhoisInfo{
			AgeDays:    6000,
			Registrant: "Example Corp",
			Expires:    time.Now().AddDate(5, 0, 0).Format(time.RFC3339),
			Status:     []string{"server transfer prohibited", "server delete prohibited"},
			DNSSEC:     true,
		}, Reputation{
			VTChecked: true, VTHarmless: 70,
			KasperskyChecked: true, KasperskyZone: "Green",
			AbuseChecked: true, AbuseIP: "192.0.2.1",
		}
}

func factorDelta(s Score, label string) (int, bool) {
	for _, f := range s.Factors {
		if f.Label == label {
			return f.Delta, true
		}
	}
	return 0, false
}

func TestScoreTrustEvidenceRaisesScore(t *testing.T) {
	w, rep := fullTrust()
	s := computeScore(ScoreInput{Domain: "examplecorp.com", Whois: w, Rep: rep})
	if s.Legitimacy != 100 {
		t.Errorf("legitimacy = %d, want 100 (factors %+v)", s.Legitimacy, s.Factors)
	}
	for _, label := range []string{"Domain age", "Registry lock", "Registrant", "Registration term", "DNSSEC", "VirusTotal", "Kaspersky OpenTIP", "AbuseIPDB"} {
		if d, ok := factorDelta(s, label); !ok || d <= 0 {
			t.Errorf("%s: delta %d (present %v), want a positive factor", label, d, ok)
		}
	}
}

// Worked example: an old, clean domain on a single feed is a likely misreport.
// The positive evidence alone keeps it out of block range, before any floor.
func TestScoreOldCleanDomainOnOneFeed(t *testing.T) {
	in := ScoreInput{Domain: "oldcorp.com", Threat: true, ThreatHits: 1,
		Whois: WhoisInfo{AgeDays: 4000},
		Rep:   Reputation{VTChecked: true, VTHarmless: 60, KasperskyChecked: true, KasperskyZone: "Green"}}
	s := computeScore(in)
	if s.Legitimacy != 80 { // 85 + 20 + 10 + 10 − 45
		t.Errorf("legitimacy = %d, want 80 (factors %+v)", s.Legitimacy, s.Factors)
	}
	if _, floored := factorDelta(s, "Established floor"); floored {
		t.Error("the floor should not be needed any more")
	}
}

// Worked example: a fresh brand look-alike on a feed scores 0 and auto-blocks.
func TestScoreYoungLookAlike(t *testing.T) {
	s := computeScore(ScoreInput{Domain: "secure-paypal-login.xyz", Threat: true, ThreatHits: 1, Whois: WhoisInfo{AgeDays: 5}})
	if s.Legitimacy != 0 {
		t.Errorf("legitimacy = %d, want 0 (factors %+v)", s.Legitimacy, s.Factors)
	}
}

// Worked example: an unknown domain on one feed is suggested for review, not
// auto-blocked — the same outcome as before the rebalance.
func TestScoreUnknownDomainOnOneFeed(t *testing.T) {
	s := computeScore(ScoreInput{Domain: "unknown.com", Threat: true, ThreatHits: 1})
	if s.Legitimacy >= blockThreshold || s.Legitimacy < autoThreshold {
		t.Errorf("legitimacy = %d, want in [%d, %d) — suggested, not auto", s.Legitimacy, autoThreshold, blockThreshold)
	}
}

// The model alone, on a domain we know nothing about, must not auto-block.
func TestScoreModelAloneDoesNotAutoBlock(t *testing.T) {
	s := computeScore(ScoreInput{Domain: "unknown.com", Verdict: block("phishing", 1.0)})
	if s.Legitimacy < autoThreshold {
		t.Errorf("legitimacy = %d, want >= %d", s.Legitimacy, autoThreshold)
	}
}

// A pile of trust evidence can't outvote a corroborated threat.
func TestScoreTrustCapAgainstStrongThreat(t *testing.T) {
	w, rep := fullTrust()
	s := computeScore(ScoreInput{Domain: "examplecorp.com", Threat: true, ThreatHits: 2, Whois: w, Rep: rep})
	if s.Legitimacy >= blockThreshold {
		t.Errorf("legitimacy = %d, want a block (factors %+v)", s.Legitimacy, s.Factors)
	}
	if d, ok := factorDelta(s, "Trust cap"); !ok || d >= 0 {
		t.Errorf("trust cap delta = %d (present %v), want negative", d, ok)
	}
	sum := 0
	for _, f := range s.Factors {
		sum += f.Delta
	}
	if baseLegitimacy+sum != s.Legitimacy {
		t.Errorf("factors sum to %d, score is %d — breakdown must add up", baseLegitimacy+sum, s.Legitimacy)
	}
}

func TestScoreHostingPlatformAndUnknownAge(t *testing.T) {
	s := computeScore(ScoreInput{Domain: "evecurls.workers.dev", Platform: "workers.dev"})
	if d, _ := factorDelta(s, "Hosting platform"); d != -10 {
		t.Errorf("hosting platform delta = %d, want -10", d)
	}
	if _, ok := factorDelta(s, "Domain age"); ok {
		t.Error("a platform subdomain should not get a domain-age factor")
	}
	// An unknown registration date is neutral now — many registries publish none.
	s = computeScore(ScoreInput{Domain: "heise.de"})
	if d, ok := factorDelta(s, "Domain age"); !ok || d != 0 {
		t.Errorf("unknown age delta = %d (present %v), want a 0 note", d, ok)
	}
	if s.Legitimacy != baseLegitimacy {
		t.Errorf("legitimacy = %d, want %d", s.Legitimacy, baseLegitimacy)
	}
}

func TestRegistrationFactors(t *testing.T) {
	now := time.Now()
	held := registrationFactors(WhoisInfo{Status: []string{"clientHold"}}, now)
	if len(held) != 1 || held[0].Delta != -20 {
		t.Errorf("clientHold factors = %+v, want one -20", held)
	}
	// Client-side locks are a registrar default — not a registry lock.
	if fs := registrationFactors(WhoisInfo{Status: []string{"clientTransferProhibited", "clientDeleteProhibited"}}, now); len(fs) != 0 {
		t.Errorf("client locks factors = %+v, want none", fs)
	}
	for _, org := range []string{"REDACTED FOR PRIVACY", "Domains By Proxy, LLC", "Data Protected", "Contact Privacy Inc."} {
		if fs := registrationFactors(WhoisInfo{Registrant: org}, now); len(fs) != 0 {
			t.Errorf("registrant %q factors = %+v, want none", org, fs)
		}
	}
	// A yearly renewal is normal for everyone — no bonus.
	if fs := registrationFactors(WhoisInfo{Expires: now.AddDate(0, 11, 0).Format(time.RFC3339)}, now); len(fs) != 0 {
		t.Errorf("1-year term factors = %+v, want none", fs)
	}
}

// The model reads an attacker-chosen name, so it can lower a score but never
// vouch for a domain, however confident.
func TestScoreModelNeverRaises(t *testing.T) {
	s := computeScore(ScoreInput{Domain: "news.com", Verdict: Verdict{Category: "news", Confidence: 1.0}})
	if d, ok := factorDelta(s, "Model assessment"); !ok || d != 0 {
		t.Errorf("content verdict delta = %d (present %v), want a 0 note", d, ok)
	}
}

// Port-43 WHOIS is plain TCP and forgeable: it may lower a score, never raise it.
func TestScorePlainWhoisNeverRaises(t *testing.T) {
	w, _ := fullTrust()
	w.Source = "whois"
	s := computeScore(ScoreInput{Domain: "examplecorp.io", Whois: w, Verdict: block("phishing", 0.9)})
	for _, f := range s.Factors {
		if f.Delta > 0 {
			t.Errorf("plain WHOIS raised the score: %+v", f)
		}
	}
	young := computeScore(ScoreInput{Domain: "new.io", Whois: WhoisInfo{AgeDays: 5, Source: "whois"}})
	if d, _ := factorDelta(young, "Domain age"); d != -45 {
		t.Errorf("young plain-WHOIS age delta = %d, want -45", d)
	}
}
