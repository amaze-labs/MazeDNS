package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/idna"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// testLexicon learns from a synthetic popular list: a few brands at the top,
// then thousands of word-pair names (natural, like real domains).
func testLexicon(t *testing.T) *Lexicon {
	t.Helper()
	words := strings.Fields(`blue green house garden river stone light market news daily cloud
		world travel book store music photo city home sport game food health shop online
		money bank north south ocean mountain forest paper design studio smart quick bright
		silver golden star moon sun water fire earth wind media group digital local happy`)
	set := &TrustedSet{domains: map[string]struct{}{}}
	add := func(d string) {
		if _, dup := set.domains[d]; !dup {
			set.domains[d] = struct{}{}
			set.ranked = append(set.ranked, d)
		}
	}
	for _, b := range []string{"paypal.com", "google.com", "amazon.com", "netflix.com", "microsoft.com", "facebook.com"} {
		add(b)
	}
	for _, a := range words {
		for _, b := range words {
			add(a + b + ".com")
		}
	}
	l := BuildLexicon(set)
	if l == nil {
		t.Fatal("lexicon not built")
	}
	return l
}

func TestLexiconNaturalness(t *testing.T) {
	l := testLexicon(t)
	for _, generated := range []string{"xkqzvbwjtpqmd", "qwzxjkvbnmpl", "zq9x7kw2vfjq"} {
		if !l.LooksGenerated(generated) {
			t.Errorf("%s should look generated", generated)
		}
	}
	for _, real := range []string{"bluegardenhouse", "silvermoonstudio", "northforest"} {
		if l.LooksGenerated(real) {
			t.Errorf("%s should look natural", real)
		}
	}
	if l.LooksGenerated("xkq") {
		t.Error("short labels are never judged")
	}
}

func TestLexiconLookalikes(t *testing.T) {
	l := testLexicon(t)
	idn, err := idna.ToASCII("pаypal") // Cyrillic а
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		label, want string
	}{
		{"paypall", "Lexical: typosquat"},
		{"gooogle", "Lexical: typosquat"},
		{"amaozn", "Lexical: typosquat"}, // transposition
		{"paypal-login", "Lexical: brand + keyword"},
		{"netflixbilling", "Lexical: brand + keyword"},
		{"appleid", "Lexical: brand + keyword"}, // a short keyword counts as the whole rest
		{"amazonidea", ""},
		{"paypal", ""},     // the brand itself
		{"bluegarden", ""}, // a known popular name
		{"randomshop", ""}, // nothing like a brand
		{idn, "Lexical: IDN homograph"},
	}
	for _, tc := range cases {
		f, ok := l.lookalike(tc.label)
		if got := map[bool]string{true: f.Label}[ok]; got != tc.want {
			t.Errorf("lookalike(%q) = %q (%s), want %q", tc.label, got, f.Detail, tc.want)
		}
	}
	if b, ok := l.brandInSubdomain("paypal.com.account-check.xyz", "account-check.xyz"); !ok || b != "paypal" {
		t.Errorf("brand in subdomain = %q %v", b, ok)
	}
	if _, ok := l.brandInSubdomain("www.paypal.com", "paypal.com"); ok {
		t.Error("the brand's own subdomain is not impersonation")
	}
}

func TestObserverTunnelingAndNX(t *testing.T) {
	l := testLexicon(t)
	o := newObserver(func() *Lexicon { return l })
	now := time.Now()
	triggered := 0
	for i := 0; i < 80; i++ {
		sub := fmt.Sprintf("%x", sha(i)) // 32 hex chars: an encoded chunk
		if o.add("exfil.example", store.QueryLogEntry{Client: "10.0.0.9", Name: sub + ".exfil.example.", QType: "TXT"}, now) {
			triggered++
		}
	}
	b := o.get("exfil.example")
	if !b.Tunneling() || triggered != 1 {
		t.Fatalf("tunneling: %+v, triggered %d (want once)", b, triggered)
	}
	// A CDN-like domain with a few ordinary hostnames is not tunneling.
	for _, h := range []string{"www", "mail", "static", "api", "cdn"} {
		o.add("normal.example", store.QueryLogEntry{Client: "10.0.0.1", Name: h + ".normal.example.", QType: "A"}, now)
	}
	if o.get("normal.example").Tunneling() {
		t.Fatal("ordinary hostnames flagged as tunneling")
	}
	for i := 0; i < 6; i++ {
		o.add("dga.example", store.QueryLogEntry{Client: "10.0.0.2", Name: "dga.example.", Rcode: "NXDOMAIN"}, now)
	}
	if !o.get("dga.example").MostlyNX() {
		t.Fatal("mostly-NXDOMAIN not detected")
	}
}

func sha(i int) []byte {
	b := make([]byte, 16)
	x := uint64(i)*0x9E3779B97F4A7C15 + 0x1234567
	for j := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[j] = byte(x)
	}
	return b
}

func TestScoreBehaviourAndLexiconFactors(t *testing.T) {
	l := testLexicon(t)
	b := Behaviour{Queries: 90, Clients: 1, Subdomains: 80, RandomSubs: 80, LongestSub: 32, TXTLike: 90,
		Names: []string{"paypal.com.account-check.xyz"}}
	s := computeScore(ScoreInput{Domain: "account-check.xyz", Lex: l, Behaviour: b})
	labels := map[string]bool{}
	for _, f := range s.Factors {
		labels[f.Label] = true
	}
	for _, want := range []string{"Seen on this network", "Behaviour: DNS tunneling", "Brand in subdomain"} {
		if !labels[want] {
			t.Errorf("missing factor %q in %+v", want, s.Factors)
		}
	}
	if s.Legitimacy >= blockThreshold {
		t.Errorf("legitimacy %d, want below %d", s.Legitimacy, blockThreshold)
	}
}

func testWorker(t *testing.T, mode Mode) (*Worker, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	set := Settings{Enabled: true, Mode: string(mode), TrustedDisableDefault: true, ThreatFeeds: []string{}, NSCheckDisabled: true}
	return NewWorker(st, func() Settings { return set }, nil), st
}

// Tunneling seen on the network makes a domain a block candidate, but only for
// review: never auto-blocked on that heuristic alone.
func TestTunnelingIsReviewOnly(t *testing.T) {
	w, st := testWorker(t, ModeAuto)
	for i := 0; i < 80; i++ {
		w.obs.add("exfil.example", store.QueryLogEntry{Client: "10.0.0.9", Name: fmt.Sprintf("%x.exfil.example.", sha(i)), QType: "TXT"}, time.Now())
	}
	w.process(context.Background(), "exfil.example")
	cs, err := st.ListClassifications("", "exfil.example", 10, 0)
	if err != nil || len(cs) != 1 {
		t.Fatalf("classification: %v %+v", err, cs)
	}
	if c := cs[0]; c.Status != store.ClassSuggested || !c.Block {
		t.Fatalf("status %q block %v, want a suggestion", c.Status, c.Block)
	}
}

// Aged evidence sends machine verdicts back to scoring; human decisions and
// still-listed or still-fresh verdicts stay.
func TestRescoreAged(t *testing.T) {
	w, st := testWorker(t, ModeSuggest)
	young, _ := json.Marshal([]Factor{{Label: "Domain age", Detail: "registered 12 days ago — very new", Delta: -45}})
	unknown, _ := json.Marshal([]Factor{{Label: "Domain age", Detail: "registration date unknown — the registry doesn't publish it, or the lookup failed"}})
	for _, c := range []store.Classification{
		{Domain: "young.example", Status: store.ClassClean, Factors: young},
		{Domain: "young-human.example", Status: store.ClassRejected, Factors: young},
		{Domain: "unlisted.example", Status: store.ClassSuggested, Block: true, Threat: true},
		{Domain: "unknown.example", Status: store.ClassClean, Factors: unknown},
	} {
		if _, err := st.InsertClassification(c); err != nil {
			t.Fatal(err)
		}
	}
	// A day later only the feed-dropped verdict is due (whois is off, so the
	// unknown-date one never is).
	if n := w.rescoreAged(time.Now().Add(25 * time.Hour)); n != 1 {
		t.Fatalf("day 1: %d re-queued, want 1", n)
	}
	// A month later the young one is due too; the human decision never.
	if n := w.rescoreAged(time.Now().Add(31 * 24 * time.Hour)); n != 1 {
		t.Fatalf("day 31: %d re-queued, want 1", n)
	}
	for d, want := range map[string]bool{"young.example": false, "young-human.example": true, "unlisted.example": false, "unknown.example": true} {
		if got, _ := st.IsClassified(d); got != want {
			t.Errorf("%s classified = %v, want %v", d, got, want)
		}
	}
}

// The OpenAI-compatible request carries the verdict JSON schema; a server that
// rejects it gets the plain prompt from then on.
func TestStructuredOutputOpenAI(t *testing.T) {
	var withSchema, without int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatReq
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if req.ResponseFormat != nil {
			withSchema++
			http.Error(w, `{"error":{"message":"response_format not supported"}}`, http.StatusBadRequest)
			return
		}
		without++
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"{\"category\":\"phishing\",\"confidence\":0.8,\"reason\":\"x\"}"}}]}`)
	}))
	defer srv.Close()
	c := NewClient(ProviderOpenAI, srv.URL, "m", "", 5*time.Second)
	for i := 0; i < 2; i++ {
		v, _, err := c.Classify(context.Background(), "x.example", Hints{})
		if err != nil || v.Category != "phishing" {
			t.Fatalf("call %d: %+v %v", i, v, err)
		}
	}
	if withSchema != 1 || without != 2 {
		t.Fatalf("schema requests %d, plain %d; want 1 and 2 (fallback remembered)", withSchema, without)
	}
	// The schema only allows known categories.
	enum := verdictSchema()["properties"].(map[string]any)["category"].(map[string]any)["enum"].([]string)
	if len(enum) != len(validCategories) {
		t.Fatalf("schema categories %d, want %d", len(enum), len(validCategories))
	}
}

// Anthropic gets a forced tool call; its input is the verdict.
func TestStructuredOutputAnthropic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req anthropicReq
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if len(req.Tools) != 1 || req.ToolChoice["name"] != "record_verdict" {
			t.Errorf("no forced tool: %+v", req.ToolChoice)
		}
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"Here you go."},
			{"type":"tool_use","name":"record_verdict","input":{"category":"malware","confidence":0.7,"reason":"c2"}}],
			"stop_reason":"tool_use"}`)
	}))
	defer srv.Close()
	c := NewClient(ProviderAnthropic, srv.URL, "m", "k", 5*time.Second)
	v, _, err := c.Classify(context.Background(), "x.example", Hints{})
	if err != nil || v.Category != "malware" || v.Confidence != 0.7 {
		t.Fatalf("verdict %+v %v", v, err)
	}
}

// A CDN CNAME target carries the customer's hostname ("www.apple.com" on
// akadns.net): no brand-in-subdomain there, but still on a publishing
// platform, where anyone can put a brand in front.
func TestBrandInSubdomainSkipsCDNTargets(t *testing.T) {
	l := testLexicon(t)
	score := func(name string) Score {
		d := RegisteredDomain(name)
		return computeScore(ScoreInput{Domain: d, Platform: HostingPlatform(name), Lex: l,
			Behaviour: Behaviour{Queries: 1, Clients: 1, Subdomains: 1, Names: []string{name}}})
	}
	has := func(s Score) bool {
		for _, f := range s.Factors {
			if f.Label == "Brand in subdomain" {
				return true
			}
		}
		return false
	}
	for _, n := range []string{"www.paypal.com.akadns.net", "www.paypal.com.edgesuite.net", "paypal.z01.azurefd.net"} {
		if has(score(n)) {
			t.Errorf("%s: brand in subdomain on a CDN target", n)
		}
	}
	if !has(score("paypal.com.evil.github.io")) {
		t.Error("paypal.com.evil.github.io: brand in subdomain missed on a publishing platform")
	}
}
