package classifier

import (
	"fmt"
	"math"
	"strings"
)

// This file implements the legitimacy scoring system. Rather than trusting the
// model's confidence as the verdict (a small local model hallucinates "phishing
// @ 100%" against clear evidence), every domain STARTS fully legitimate (100)
// and each risk factor — the way a SOC analyst would weigh them — deducts from
// that score. The model's own read is just ONE bounded factor among the static
// signals, so it can no longer single-handedly sink a legitimate domain.

// Factor is one contribution to a domain's legitimacy score. Delta is added to
// the running score: negative raises suspicion, zero is neutral/informational.
// The ordered list of factors is exactly what the UI shows as "what dropped the
// score".
type Factor struct {
	Label  string `json:"label"`
	Detail string `json:"detail"`
	Delta  int    `json:"delta"`
}

// Score is the outcome of the analysis: a 0–100 legitimacy value plus the
// factors that produced it. A domain is a block candidate below blockThreshold.
type Score struct {
	Legitimacy int      `json:"legitimacy"`
	Factors    []Factor `json:"factors"`
}

const (
	blockThreshold   = 50  // legitimacy below this -> block (if there's a threat indicator)
	autoThreshold    = 35  // ...and below this, confident enough to auto-block
	establishedFloor = 55  // a non-threat established domain can't be pushed below this by soft signals
	reputationFloor  = 65  // a VirusTotal-clean domain can't be pushed below this by soft signals
	establishedDays  = 730 // ~2 years: "established"
)

// ScoreInput is everything the scorer weighs. The model's Verdict is computed
// WITH the static signals (trusted/threat/whois) already in hand, then folded
// back in here as one more (bounded) factor.
type ScoreInput struct {
	Domain      string
	ListTrusted bool       // on the popular/trusted-domains allowlist
	CDN         bool       // a CDN / cloud-edge provider (whole provider is trusted)
	NSTrustedOn string     // registered domain of trusted authoritative nameservers, if any
	Threat      bool       // on at least one threat-intel feed
	ThreatHits  int        // how many feeds list it (corroboration; 1 may be a misreport)
	ThreatLabel string     // which feed/source matched (for the breakdown)
	Whois       WhoisInfo  // registration data
	Rep         Reputation // public reputation services (VirusTotal / AbuseIPDB)
	Verdict     Verdict    // the model's assessment
}

// threatHits returns how many feeds list the domain, tolerating callers that only
// set the legacy Threat bool (treated as a single hit).
func (in ScoreInput) threatHits() int {
	if in.ThreatHits > 0 {
		return in.ThreatHits
	}
	if in.Threat {
		return 1
	}
	return 0
}

// RepMalicious reports whether the reputation services indicate the domain is
// malicious (so it becomes a block candidate on its own).
func (in ScoreInput) RepMalicious() bool { return in.Rep.Malicious() }

// StrongThreat reports a *corroborated* malicious signal: the domain is on two or
// more threat feeds, or a reputation service flags it. A single-feed hit is NOT
// strong on its own (it can be a misreport of an otherwise-clean domain), so it
// does not bypass the established / reputation-clean floors below.
func (in ScoreInput) StrongThreat() bool {
	return in.threatHits() >= 2 || in.RepMalicious()
}

func imin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// computeScore turns the signals into a legitimacy score + an auditable factor
// breakdown.
func computeScore(in ScoreInput) Score {
	// Trusted is authoritative: a domain on the popularity allowlist — or served
	// by a trusted entity's own nameservers (which can't be faked) — cannot be
	// malicious. This is the strongest false-positive guard, so it short-circuits
	// to a perfect score, overriding the model and even a threat-feed hit.
	if in.ListTrusted || in.CDN || in.NSTrustedOn != "" {
		detail := "on the trusted top-domains list — cannot be malicious"
		switch {
		case in.CDN && !in.ListTrusted:
			detail = "CDN / cloud-edge infrastructure — trusted (a verdict would apply to the whole provider)"
		case in.NSTrustedOn != "" && !in.ListTrusted:
			detail = fmt.Sprintf("authoritative nameservers on trusted infrastructure (%s) — cannot be malicious", in.NSTrustedOn)
		}
		return Score{Legitimacy: 100, Factors: []Factor{{Label: "Trusted", Detail: detail, Delta: 0}}}
	}

	legit := 100
	var fs []Factor
	add := func(label, detail string, delta int) {
		fs = append(fs, Factor{Label: label, Detail: detail, Delta: delta})
		legit += delta
	}
	note := func(label, detail string) { fs = append(fs, Factor{Label: label, Detail: detail, Delta: 0}) }

	// Threat intel — weighed by corroboration. A domain on a single feed may be a
	// misreport (threat lists do carry clean domains reported by mistake), so it
	// deducts less and respects the established / reputation-clean floors below.
	// Listing on several feeds is strong, near-definitive evidence.
	if hits := in.threatHits(); hits > 0 {
		var delta int
		var detail string
		switch {
		case hits >= 3:
			delta, detail = -90, fmt.Sprintf("listed on %d threat-intel feeds — strongly corroborated", hits)
		case hits == 2:
			delta, detail = -70, "listed on 2 threat-intel feeds — corroborated"
		default:
			delta, detail = -45, "listed on 1 threat-intel feed — single source (possible misreport)"
		}
		if in.ThreatLabel != "" && hits == 1 {
			detail = "listed on " + in.ThreatLabel + " — single source (possible misreport)"
		}
		add("Threat intel", detail, delta)
	}

	// Domain age — the single best phishing/malware indicator (they are young and
	// ephemeral). Established domains pay nothing.
	switch age := in.Whois.AgeDays; {
	case age <= 0:
		add("Domain age", "registration date unknown", -10)
	case age < 30:
		add("Domain age", fmt.Sprintf("registered %d days ago — very new", age), -45)
	case age < 90:
		add("Domain age", fmt.Sprintf("registered %d days ago — new", age), -28)
	case age < 180:
		add("Domain age", fmt.Sprintf("registered %d days ago", age), -15)
	case age < 365:
		add("Domain age", fmt.Sprintf("registered %d days ago", age), -6)
	default:
		note("Domain age", fmt.Sprintf("%d days old — established", age))
	}

	// Risky TLD — some TLDs are disproportionately abused for malware/phishing.
	if tld, risky := riskyTLD(in.Domain); risky {
		add("Risky TLD", "."+tld+" is frequently abused for phishing/malware", -15)
	}

	// Lexical structure — random-looking, very long, punycode (homograph) or
	// hyphen/digit-heavy names are classic DGA / look-alike patterns.
	for _, f := range lexicalFactors(in.Domain) {
		add(f.Label, f.Detail, f.Delta)
	}

	// Reputation services — third-party corroboration. A clean VirusTotal report
	// is a meaningful "leave it alone" signal (cuts false positives on secondary
	// app domains); a malicious one is a strong deduction.
	if in.Rep.VTChecked {
		switch {
		case in.Rep.VTMalicious >= 2:
			add("VirusTotal", fmt.Sprintf("%d vendors flag it malicious", in.Rep.VTMalicious), -imin(60, in.Rep.VTMalicious*12))
		case in.Rep.VTSuspicious >= 3:
			add("VirusTotal", fmt.Sprintf("%d vendors flag it suspicious", in.Rep.VTSuspicious), -imin(30, in.Rep.VTSuspicious*6))
		case in.Rep.VTHarmless > 0:
			note("VirusTotal", fmt.Sprintf("clean — %d vendors harmless, 0 malicious", in.Rep.VTHarmless))
		}
	}
	if in.Rep.AbuseChecked && in.Rep.AbuseScore >= 25 {
		add("AbuseIPDB", fmt.Sprintf("IP %s abuse confidence %d%% (%d reports)", in.Rep.AbuseIP, in.Rep.AbuseScore, in.Rep.AbuseReports), -imin(50, in.Rep.AbuseScore/2))
	}

	// Model assessment — the LLM's own read, made WITH all the signals above in
	// hand. It contributes (up to -50) but, by being one bounded factor, it can no
	// longer by itself sink an otherwise-legitimate domain (the false-positive fix).
	if in.Verdict.ShouldBlock() {
		conf := in.Verdict.Confidence
		if conf <= 0 {
			conf = 0.5
		}
		add("Model assessment", fmt.Sprintf("%s (%.0f%% confident)", in.Verdict.Category, conf*100), -int(math.Round(conf*50)))
	} else {
		cat := in.Verdict.Category
		if cat == "" {
			cat = "other"
		}
		note("Model assessment", cat+" — not a threat category")
	}

	// Established-domain floor — phishing/malware is overwhelmingly young, so an old
	// domain without a *corroborated* threat signal can't be dragged into block
	// range by soft signals (model + lexical + a lone feed) alone. A single-feed
	// hit on an old domain is treated as a likely misreport and floored here.
	if in.Whois.AgeDays >= establishedDays && !in.StrongThreat() && legit < establishedFloor {
		add("Established floor", fmt.Sprintf("%d-day-old domain — soft signals alone don't block it", in.Whois.AgeDays), establishedFloor-legit)
	}

	// Reputation-clean floor — a domain VirusTotal reports clean (and that isn't
	// corroborated as malicious) shouldn't be sunk into block range by the model, a
	// lone feed, or name shape alone.
	repClean := in.Rep.VTChecked && in.Rep.VTMalicious == 0 && in.Rep.VTSuspicious == 0 && in.Rep.VTHarmless > 0
	if repClean && !in.StrongThreat() && legit < reputationFloor {
		add("Reputation floor", "VirusTotal reports it clean — soft signals alone don't block it", reputationFloor-legit)
	}

	if legit < 0 {
		legit = 0
	} else if legit > 100 {
		legit = 100
	}
	return Score{Legitimacy: legit, Factors: fs}
}

// riskyTLDs is a conservative list of TLDs with disproportionate abuse rates
// (Spamhaus / Interisle "most abused TLDs"). Membership is a soft signal only.
var riskyTLDs = map[string]bool{
	"zip": true, "mov": true, "top": true, "xyz": true, "tk": true, "ml": true,
	"ga": true, "cf": true, "gq": true, "work": true, "click": true, "link": true,
	"loan": true, "men": true, "gdn": true, "icu": true, "cam": true, "buzz": true,
	"rest": true, "fit": true, "cyou": true, "sbs": true, "quest": true, "country": true,
	"kim": true, "monster": true, "bar": true, "casa": true, "cfd": true, "wang": true,
}

func riskyTLD(domain string) (string, bool) {
	i := strings.LastIndexByte(domain, '.')
	if i < 0 {
		return "", false
	}
	tld := domain[i+1:]
	return tld, riskyTLDs[tld]
}

// lexicalFactors inspects the registered domain's primary label for look-alike /
// machine-generated patterns. Each is a soft (small) deduction.
func lexicalFactors(domain string) []Factor {
	label := domain
	if i := strings.IndexByte(domain, '.'); i >= 0 {
		label = domain[:i]
	}
	var fs []Factor
	if strings.HasPrefix(label, "xn--") {
		fs = append(fs, Factor{"Lexical: punycode", "internationalized name (xn--) — homograph/look-alike risk", -20})
	}
	if n := strings.Count(label, "-"); n >= 3 {
		fs = append(fs, Factor{"Lexical: hyphens", fmt.Sprintf("%d hyphens — common in look-alike domains", n), -8})
	}
	digits := 0
	for i := 0; i < len(label); i++ {
		if label[i] >= '0' && label[i] <= '9' {
			digits++
		}
	}
	if len(label) > 0 && (digits >= 5 || float64(digits)/float64(len(label)) > 0.33) {
		fs = append(fs, Factor{"Lexical: digits", "digit-heavy name — common in generated/abuse domains", -8})
	}
	if len(label) >= 25 {
		fs = append(fs, Factor{"Lexical: length", fmt.Sprintf("%d-character name — unusually long", len(label)), -8})
	}
	if len(label) >= 12 && entropy(label) > 3.8 {
		fs = append(fs, Factor{"Lexical: randomness", "high-entropy name — looks machine-generated (DGA)", -12})
	}
	if f, ok := brandImpersonationFactor(label); ok {
		fs = append(fs, f)
	}
	return fs
}

// impersonationTargets are high-value brands commonly imitated for phishing. A
// domain that looks like one of these but isn't it (a real brand domain is caught
// earlier by the trusted/nameserver short-circuits) is a classic look-alike.
var impersonationTargets = []string{
	"paypal", "google", "apple", "icloud", "microsoft", "office365", "outlook",
	"amazon", "facebook", "instagram", "whatsapp", "netflix", "linkedin", "dropbox",
	"coinbase", "binance", "metamask", "wellsfargo", "chase", "bankofamerica",
	"americanexpress", "yahoo", "gmail", "steam", "roblox", "discord", "spotify",
}

// homoglyphs maps look-alike characters to the letter they imitate, so a
// "paypa1" / "g00gle" style swap can be normalized back to the brand.
var homoglyphs = map[rune]rune{
	'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's',
}

func normalizeHomoglyphs(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if n, ok := homoglyphs[r]; ok {
			b.WriteRune(n)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// brandImpersonationFactor flags a primary label that imitates a known brand:
// either a homoglyph look-alike (normalizes to the brand but isn't typed as it,
// e.g. "paypa1") or the brand embedded as a separate token alongside extra text
// (e.g. "secure-paypal-login"). It deliberately does NOT fire on the brand itself.
// On its own this only lowers the score — a block still needs a threat indicator —
// so it's safe to be a little aggressive.
func brandImpersonationFactor(label string) (Factor, bool) {
	if len(label) < 4 {
		return Factor{}, false
	}
	norm := normalizeHomoglyphs(label)
	tokens := strings.FieldsFunc(label, func(r rune) bool { return r == '-' || r == '.' || r == '_' })
	for _, b := range impersonationTargets {
		if label == b {
			return Factor{}, false // it IS the brand's name — not impersonation
		}
		if norm == b {
			return Factor{Label: "Lexical: look-alike", Detail: fmt.Sprintf("imitates %q via look-alike characters", b), Delta: -28}, true
		}
		// Brand as a distinct token within a longer, multi-part name.
		if len(tokens) > 1 {
			for _, t := range tokens {
				if t == b {
					return Factor{Label: "Lexical: brand in name", Detail: fmt.Sprintf("contains the brand %q with extra text — possible look-alike", b), Delta: -22}, true
				}
			}
		}
	}
	return Factor{}, false
}

// entropy is the Shannon entropy (bits/char) of a string — high values flag
// random-looking names.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
