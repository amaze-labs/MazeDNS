package classifier

import (
	"math"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// A Lexicon is learned from the trusted (popular) domain list, so no outside
// service is needed:
//
//   - a character-bigram model of what real domain names look like. Machine-
//     generated names (DGA) score far below real ones even when their letter
//     entropy is ordinary, and word-salad names stay natural;
//   - the brands look-alikes imitate: the most popular registered domains'
//     first labels, plus a few high-value targets that are always included.
//
// It is rebuilt whenever the trusted list (re)loads.
type Lexicon struct {
	logp [lexAlpha][lexAlpha]float64 // log P(next | prev) with add-one smoothing
	// randomCut is the naturalness below which a label looks generated: the
	// 1st percentile of the training labels (so ~1% of real names would trip
	// it, which is why it is a soft signal).
	randomCut float64
	brands    []string        // brand labels, most popular first
	brandSet  map[string]bool // the brand labels
	known     map[string]bool // every trusted first label (a real name, not a squat)
}

// The bigram alphabet: a–z, 0–9, '-', start and end of label.
const (
	lexAlpha  = 39
	lexStart  = 37
	lexEnd    = 38
	lexMinLen = 8 // naturalness is too noisy on shorter labels
)

func lexIndex(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= '0' && c <= '9':
		return 26 + int(c-'0')
	case c == '-':
		return 36
	}
	return -1
}

// firstLabel is the registered domain's first label ("paypal" of "paypal.co.uk").
func firstLabel(domain string) string {
	if i := strings.IndexByte(domain, '.'); i >= 0 {
		return domain[:i]
	}
	return domain
}

// BuildLexicon learns a Lexicon from the trusted set: naturalness from every
// domain, brands from the top ones. nil when the set is too small to learn from.
func BuildLexicon(set *TrustedSet) *Lexicon {
	if set.Count() < 1000 {
		return nil
	}
	var counts [lexAlpha][lexAlpha]float64
	l := &Lexicon{brandSet: map[string]bool{}, known: map[string]bool{}}
	var labels []string
	set.Each(func(d string) {
		lab := firstLabel(d)
		l.known[lab] = true
		prev := lexStart
		ok := true
		for i := 0; i < len(lab); i++ {
			c := lexIndex(lab[i])
			if c < 0 {
				ok = false
				break
			}
			counts[prev][c]++
			prev = c
		}
		if !ok {
			return
		}
		counts[prev][lexEnd]++
		if len(lab) >= lexMinLen {
			labels = append(labels, lab)
		}
	})
	for i := 0; i < lexAlpha; i++ {
		var row float64
		for j := 0; j < lexAlpha; j++ {
			row += counts[i][j]
		}
		for j := 0; j < lexAlpha; j++ {
			l.logp[i][j] = math.Log((counts[i][j] + 1) / (row + lexAlpha))
		}
	}
	// The cut-off: the 1st percentile of the training labels' naturalness.
	if len(labels) > 0 {
		sc := make([]float64, len(labels))
		for i, lab := range labels {
			sc[i], _ = l.naturalness(lab)
		}
		sort.Float64s(sc)
		l.randomCut = sc[len(sc)/100]
	}
	// Brands: the most popular names long enough to be distinctive, then the
	// always-included targets.
	for _, d := range set.Top(lexBrandTop) {
		lab := firstLabel(d)
		if len(lab) >= 5 && !l.brandSet[lab] && !genericLabel[lab] {
			l.brands = append(l.brands, lab)
			l.brandSet[lab] = true
		}
	}
	for _, b := range impersonationTargets {
		if !l.brandSet[b] {
			l.brands = append(l.brands, b)
			l.brandSet[b] = true
		}
	}
	return l
}

// lexBrandTop is how many of the most popular domains count as brands.
const lexBrandTop = 400

// genericLabel are popular first labels that are ordinary words or shared
// platforms: a name close to them is not imitating anyone.
var genericLabel = map[string]bool{
	"blogspot": true, "wordpress": true, "medium": true,
	"amazonaws": true, "cloudfront": true, "akamaihd": true, "googleapis": true,
	"gstatic": true, "googleusercontent": true, "creativecommons": true, "w3org": true,
	"office": true, "online": true, "service": true, "support": true, "secure": true,
	"system": true, "social": true, "global": true, "digital": true, "health": true,
	"travel": true, "studio": true, "design": true, "market": true, "games": true,
}

// naturalness is the label's mean bigram log-probability (higher = more like a
// real name), and whether the label only uses the model's alphabet.
func (l *Lexicon) naturalness(label string) (float64, bool) {
	prev := lexStart
	var sum float64
	for i := 0; i < len(label); i++ {
		c := lexIndex(label[i])
		if c < 0 {
			return 0, false
		}
		sum += l.logp[prev][c]
		prev = c
	}
	sum += l.logp[prev][lexEnd]
	return sum / float64(len(label)+1), true
}

// LooksGenerated reports whether a label reads as machine-generated: long
// enough to judge, and less natural than 99% of real domain names.
func (l *Lexicon) LooksGenerated(label string) bool {
	if l == nil || len(label) < lexMinLen {
		return false
	}
	n, ok := l.naturalness(label)
	return ok && n < l.randomCut
}

// phishKeywords are words combosquats glue to a brand ("paypal-login",
// "appleidsupport"): on their own perfectly ordinary.
var phishKeywords = []string{
	"login", "signin", "logon", "secure", "security", "verify", "verification",
	"account", "accounts", "update", "support", "help", "wallet", "auth",
	"billing", "payment", "recovery", "recover", "unlock", "confirm", "service",
	"services", "online", "id", "app", "web", "mail", "portal", "customer",
	"bonus", "gift", "promo", "airdrop", "claim", "refund", "alert", "notice",
}

// lookalike checks a first label against the brands: a typo of one
// (Damerau–Levenshtein distance 1, or 2 for long names), a brand with a
// phishing keyword glued on, or an internationalized name whose letters are
// confusable with a brand's. It returns the factor and whether one matched.
// A label that is itself a known popular name never matches.
func (l *Lexicon) lookalike(label string) (Factor, bool) {
	if l == nil || l.known[label] {
		return Factor{}, false
	}
	// IDN homograph: decode, fold confusable letters to ASCII, compare.
	if strings.HasPrefix(label, "xn--") {
		if u, err := idna.ToUnicode(label); err == nil {
			if sk := confusableSkeleton(u); sk != "" && sk != label && l.brandSet[sk] {
				return Factor{Label: "Lexical: IDN homograph", Detail: "“" + u + "” is spelled with look-alike letters for “" + sk + "”", Delta: -35}, true
			}
		}
		return Factor{}, false
	}
	if len(label) < 6 {
		return Factor{}, false
	}
	for _, b := range l.brands {
		if b == label {
			return Factor{}, false
		}
	}
	for _, b := range l.brands {
		max := 1
		if len(b) >= 10 {
			max = 2
		}
		if d := len(label) - len(b); d > max || -d > max {
			continue
		}
		if damerau(label, b, max) <= max {
			return Factor{Label: "Lexical: typosquat", Detail: "one typo away from “" + b + "”", Delta: -25}, true
		}
	}
	flat := strings.ReplaceAll(label, "-", "")
	for _, b := range l.brands {
		if len(b) < 5 || !strings.Contains(flat, b) || flat == b {
			continue
		}
		rest := strings.Replace(flat, b, "", 1)
		for _, k := range phishKeywords {
			// Short keywords ("id", "app") only as the whole rest, so "amazonidea" isn't one.
			if rest == k || (len(k) >= 4 && (strings.HasPrefix(rest, k) || strings.HasSuffix(rest, k))) {
				return Factor{Label: "Lexical: brand + keyword", Detail: "“" + b + "” combined with “" + k + "” — a common phishing pattern", Delta: -22}, true
			}
		}
	}
	return Factor{}, false
}

// brandInSubdomain reports a full name that puts a brand in front of an
// unrelated registered domain ("paypal.com.account-check.xyz",
// "appleid-login.example.net"): the brand the user sees is not the domain
// they are on.
func (l *Lexicon) brandInSubdomain(name, registered string) (string, bool) {
	if l == nil {
		return "", false
	}
	sub := strings.TrimSuffix(name, "."+registered)
	if sub == name || sub == "" {
		return "", false
	}
	regLabel := firstLabel(registered)
	for _, lab := range strings.Split(sub, ".") {
		for _, tok := range strings.FieldsFunc(lab, func(r rune) bool { return r == '-' || r == '_' }) {
			if len(tok) >= 5 && l.brandSet[tok] && tok != regLabel && !genericLabel[tok] {
				return tok, true
			}
		}
	}
	return "", false
}

// confusableSkeleton folds a Unicode label to the ASCII it imitates:
// diacritics are stripped and Cyrillic/Greek look-alikes mapped (a subset of
// Unicode TR39 confusables). "" when a letter has no ASCII look-alike.
func confusableSkeleton(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(s) {
		if unicode.Is(unicode.Mn, r) {
			continue // combining accent
		}
		if r < 128 {
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		m, ok := confusables[r]
		if !ok {
			return ""
		}
		b.WriteRune(m)
	}
	return b.String()
}

var confusables = map[rune]rune{
	// Cyrillic
	'а': 'a', 'в': 'b', 'с': 'c', 'ԁ': 'd', 'е': 'e', 'һ': 'h', 'і': 'i', 'ј': 'j',
	'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'ԛ': 'q', 'ѕ': 's', 'т': 't',
	'у': 'y', 'х': 'x', 'ү': 'y', 'ӏ': 'l', 'ԝ': 'w', 'ь': 'b', 'ɡ': 'g',
	// Greek
	'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
	'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
	// Latin look-alikes outside ASCII
	'ı': 'i', 'ł': 'l', 'ø': 'o', 'đ': 'd', 'ħ': 'h', 'ŀ': 'l', 'ƅ': 'b', 'ɑ': 'a',
}

// damerau is the optimal-string-alignment distance between a and b, giving up
// (returning max+1) once every alignment exceeds max.
func damerau(a, b string, max int) int {
	la, lb := len(a), len(b)
	prev2 := make([]int, lb+1)
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		rowMin := cur[0]
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			v := min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				v = min(v, prev2[j-2]+1)
			}
			cur[j] = v
			rowMin = min(rowMin, v)
		}
		if rowMin > max {
			return max + 1
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[lb]
}
