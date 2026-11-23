package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// Mode controls enforcement of model verdicts.
type Mode string

const (
	ModeOff     Mode = "off"     // classification disabled
	ModeSuggest Mode = "suggest" // record verdicts; user approves before they block
	ModeAuto    Mode = "auto"    // block-category verdicts take effect immediately
)

// ParseMode normalizes a mode string (defaulting to off).
func ParseMode(s string) Mode {
	switch Mode(s) {
	case ModeSuggest:
		return ModeSuggest
	case ModeAuto:
		return ModeAuto
	default:
		return ModeOff
	}
}

// Settings is the live, UI-editable classifier configuration (persisted in the
// store and read fresh on every use, so changes apply without a restart).
type Settings struct {
	Enabled    bool   `json:"enabled"`
	AIEnabled  bool   `json:"ai_enabled"` // master switch for the optional LLM layer
	Provider   string `json:"provider"`   // openai (OpenAI-compatible) | anthropic
	Endpoint   string `json:"endpoint"`
	Model      string `json:"model"`
	APIKey     string `json:"api_key"`
	Mode       string `json:"mode"`        // off|suggest|auto
	MinGapMS   int    `json:"min_gap_ms"`  // min spacing between model calls
	TimeoutSec int    `json:"timeout_sec"` // per-request timeout (local models can be slow to warm up)
	// Trusted list (known-legitimate domains): a flagged domain here is never
	// blocked. The built-in public default is used unless TrustedDisableDefault;
	// TrustedListURL adds a custom source (file/URL); TrustedTopN caps a ranked
	// default list.
	TrustedListURL        string `json:"trusted_list_url"`
	TrustedTopN           int    `json:"trusted_top_n"`
	TrustedDisableDefault bool   `json:"trusted_disable_default"`
	// Threat lists (known-malicious domains): a domain here corroborates a
	// malicious verdict (boosting it) and is flagged even if the model missed it.
	// ThreatFeeds enables built-in public feeds (see ThreatFeedCatalog);
	// ThreatListURL adds custom sources (one per line / comma-separated).
	ThreatFeeds          []string `json:"threat_feeds"`
	ThreatListURL        string   `json:"threat_list_url"`
	ThreatDisableDefault bool     `json:"threat_disable_default"` // legacy (pre-ThreatFeeds)
	// WhoisEnabled enriches each classification with the domain's registration
	// data (via RDAP) — domain age is a strong signal for the model.
	WhoisEnabled bool `json:"whois_enabled"`
	// NRDEnabled downloads the free newly-registered-domains lists (hagezi/nrd,
	// ~90 MB a day, ~45 MB in memory): a domain registered in the last two
	// weeks is known to be young without looking anything up.
	NRDEnabled bool `json:"nrd_enabled"`
	// NetRepEnabled checks the address a domain resolves to against Spamhaus
	// DROP / ASN-DROP (free lists of hijacked and criminal networks); the
	// address's network is looked up with Team Cymru's free DNS service.
	NetRepEnabled bool `json:"netrep_enabled"`
	// CTEnabled asks crt.sh (Certificate Transparency) when the domain got its
	// first certificate, used when the registration date is unknown.
	CTEnabled bool `json:"ct_enabled"`
	// Reputation enrichment (optional, key-gated): corroborate verdicts against
	// public reputation services. A clean report raises legitimacy; a malicious
	// one lowers it. VirusTotal checks the domain; AbuseIPDB checks its resolved IP.
	VTEnabled        bool   `json:"vt_enabled"`
	VTAPIKey         string `json:"vt_api_key"`
	AbuseIPDBEnabled bool   `json:"abuseipdb_enabled"`
	AbuseIPDBAPIKey  string `json:"abuseipdb_api_key"`
	// Kaspersky OpenTIP (opentip.kaspersky.com): per-domain threat-zone lookup.
	OpenTIPEnabled bool   `json:"opentip_enabled"`
	OpenTIPAPIKey  string `json:"opentip_api_key"`
	// ExcludeDomains are never classified, nor any name under them (see
	// exclude.go): the network's own domains, kept away from third parties.
	ExcludeDomains []string `json:"exclude_domains"`
	// NSCheckDisabled turns off the nameserver check (nscheck.go), which asks
	// Cloudflare/Quad9 over DoH whether a domain's zone resolves. Stored as
	// "disabled" so settings from before the switch keep it on.
	NSCheckDisabled bool `json:"ns_check_disabled"`
}

// aiConfigured reports whether the optional LLM layer should run. The AI master
// switch must be on, a model is always required, and an endpoint is required only
// for the OpenAI-compatible provider (Anthropic uses its public API by default).
// Otherwise classification falls back to static analysis on the deterministic
// signals alone.
func aiConfigured(s Settings) bool {
	if !s.AIEnabled || strings.TrimSpace(s.Model) == "" {
		return false
	}
	if normalizeProvider(s.Provider) == ProviderAnthropic {
		return true // endpoint optional (defaults to the public API)
	}
	return strings.TrimSpace(s.Endpoint) != ""
}

func (s Settings) minGap() time.Duration {
	if s.MinGapMS <= 0 {
		return time.Second
	}
	return time.Duration(s.MinGapMS) * time.Millisecond
}

// Timeout is the per-request timeout, defaulting generously since a local model
// often loads on the first call (which is what causes "context deadline
// exceeded").
func (s Settings) Timeout() time.Duration {
	if s.TimeoutSec <= 0 {
		return 60 * time.Second
	}
	return time.Duration(s.TimeoutSec) * time.Second
}

// Worker classifies newly-seen domains in the background and persists verdicts.
// It reads its configuration through `get` on every operation, so enabling,
// disabling, or repointing the model takes effect live.
type Worker struct {
	store  *store.Store
	get    func() Settings // current settings (runtime-changeable)
	reload func() error    // rebuild resolver policy after an enforced verdict
	queue  chan string

	mu     sync.Mutex
	recent map[string]time.Time // in-memory dedup of registered domains

	clientMu  sync.Mutex
	client    *Client
	clientKey string

	trusted *setHolder
	threat  *setHolder
	whois   *WhoisCache
	rep     *RepCache

	zoneResolves func(ctx context.Context, domain string) bool // overridden in tests

	// The conditional forwarders' domains, cached (exclude.go).
	fwdMu       sync.Mutex
	fwdSuffixes []string
	fwdAt       time.Time

	// catDB is the category database: a domain it knows needs no content
	// category from the model (nil = no database: always ask).
	catDB *categories.Holder

	// lex is learned from the trusted list (lexicon.go); obs tallies the query
	// stream per domain (observe.go).
	lex atomic.Pointer[Lexicon]
	obs *observer

	// Free open-data signals (nrd.go, netrep.go, ct.go).
	nrd    nrdHolder
	netrep netrepHolder
	ct     *ctCache
}

// NewWorker builds a classification worker driven by the live settings getter.
func NewWorker(st *store.Store, get func() Settings, reload func() error) *Worker {
	w := &Worker{
		store:   st,
		get:     get,
		reload:  reload,
		queue:   make(chan string, 2048),
		recent:  make(map[string]time.Time),
		trusted: newSetHolder("trusted", false),
		threat:  newSetHolder("threat", true), // count how many feeds list each domain
		whois:   NewWhoisCache(),
		rep:     NewRepCache(),

		zoneResolves: zoneResolves,
	}
	w.obs = newObserver(w.lex.Load)
	w.ct = newCTCache()
	// The lexicon is learned from the trusted list: rebuild it when that loads.
	w.trusted.onChange = func() { w.lex.Store(BuildLexicon(w.trusted.set.Load())) }
	// Whenever the threat set (re)loads, re-check existing clean verdicts against it
	// so domains that became malicious after we last saw them get flagged.
	w.threat.onChange = w.rescanThreat
	// Persist reputation-API usage (VirusTotal / AbuseIPDB) so the UI can show how
	// close each key is to its daily quota.
	w.rep.SetRecorder(func(c RepCall) {
		_ = st.RecordReputationUsage(c.Service, c.Errored, c.RateLimited, c.Remaining, c.Limit)
	})
	return w
}

// threatRefreshInterval is how often long-lived threat feeds are re-pulled so a
// node doesn't keep trusting a stale startup snapshot.
const threatRefreshInterval = time.Hour

// Whois returns cached registration data for a domain (used by the UI detail view).
func (w *Worker) Whois(ctx context.Context, domain string) (WhoisInfo, error) {
	return w.whois.Lookup(ctx, domain)
}

// clientFor returns a cached client for the current endpoint/model/key, rebuilding
// it only when those change.
func (w *Worker) clientFor(s Settings) *Client {
	key := fmt.Sprintf("%s|%s|%s|%s|%s", s.Provider, s.Endpoint, s.Model, s.APIKey, s.Timeout())
	w.clientMu.Lock()
	defer w.clientMu.Unlock()
	if w.client == nil || w.clientKey != key {
		w.client = NewClient(s.Provider, s.Endpoint, s.Model, s.APIKey, s.Timeout())
		w.clientKey = key
	}
	return w.client
}

// Enqueue submits a queried name for classification. It extracts the registered
// domain, skips ones seen recently, and never blocks the caller (drops on a full
// queue) — the DNS hot path must not wait on this.
// Observe records one query from the stream (its behaviour signals) and
// submits its name for classification. A classified domain whose behaviour
// turns into a tunneling pattern goes back to scoring.
func (w *Worker) Observe(e store.QueryLogEntry) {
	s := w.get()
	if !s.Enabled || ParseMode(s.Mode) == ModeOff {
		return
	}
	domain := RegisteredDomain(e.Name)
	if domain == "" || IsReservedName(domain) || w.Excluded(e.Name) {
		return
	}
	if w.obs.add(domain, e, time.Now()) {
		w.rescoreDomain(domain, "behaviour changed: DNS tunneling pattern")
	}
	w.Enqueue(e.Name)
}

func (w *Worker) Enqueue(name string) {
	s := w.get()
	if !s.Enabled || ParseMode(s.Mode) == ModeOff {
		return
	}
	domain := RegisteredDomain(name)
	if domain == "" || IsReservedName(domain) {
		return // reserved / private-use names never exist publicly
	}
	if w.Excluded(name) {
		return // the network's own names never leave it (exclude.go)
	}
	w.mu.Lock()
	if t, ok := w.recent[domain]; ok && time.Since(t) < time.Hour {
		w.mu.Unlock()
		return
	}
	w.recent[domain] = time.Now()
	if len(w.recent) > 50000 {
		w.pruneLocked()
	}
	w.mu.Unlock()

	select {
	case w.queue <- domain:
	default: // queue full — drop; it'll be seen again on the next query
	}
}

func (w *Worker) pruneLocked() {
	cutoff := time.Now().Add(-time.Hour)
	for k, t := range w.recent {
		if t.Before(cutoff) {
			delete(w.recent, k)
		}
	}
}

// Run consumes the queue until ctx is cancelled, classifying one domain at a
// time with at least the configured gap between model calls.
func (w *Worker) Run(ctx context.Context) {
	slog.Info("classifier worker started")
	// Start loading the trusted/threat lists up front so the first classified
	// domains already have the signals (rather than racing the first lookup) —
	// only while classification is on: nothing is downloaded otherwise.
	if s := w.get(); s.Enabled {
		w.trusted.ensureSync(trustedSources(s))
		w.threat.ensureSync(threatSources(s))
	}
	go w.refreshThreatLoop(ctx)
	go w.rescoreLegacyTrusted(ctx) // feeds the queue below, so it can't run inline
	go w.rescoreLoop(ctx)          // verdicts whose evidence aged (rescore.go)
	go w.rescoreReflagged()        // once: verdicts an older feed recheck flagged unscored
	// Content categories for verdicts from before categories existed are asked
	// of the model while the queue is idle, one call per tick, so the backfill
	// never competes with newly seen domains.
	backfill := time.NewTicker(contentBackfillEvery)
	defer backfill.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-backfill.C:
			w.backfillContent(ctx)
		case domain := <-w.queue:
			cur := w.get()
			w.process(ctx, domain)
			// The inter-domain gap exists only to rate-limit LLM calls. In static-only
			// mode there's no model to throttle, so drain the queue at full speed
			// (reputation lookups have their own cache/limits) — fewer dropped domains.
			if !aiConfigured(cur) {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(cur.minGap()):
			}
		}
	}
}

// refreshThreatLoop periodically re-pulls the threat feeds while the feature is
// enabled, so a long-running node picks up newly-listed malware domains. Each
// successful refresh triggers rescanThreat via the set holder's onChange hook.
func (w *Worker) refreshThreatLoop(ctx context.Context) {
	t := time.NewTicker(threatRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s := w.get()
			if !s.Enabled {
				// Turned off: let the lists go (they reload when it's back on).
				w.trusted.ensureSync(nil)
				w.threat.ensureSync(nil)
				continue
			}
			if ParseMode(s.Mode) == ModeOff {
				continue
			}
			w.threat.refresh(threatSources(s))
		}
	}
}

// rescanThreat re-checks the clean (untrusted) verdicts against the threat
// set after it (re)loads. A domain the feeds now list more widely than when
// it was scored — newly listed, or from one feed to several — is scored again
// through the whole pipeline, so the listing is weighed with everything else
// (age, trust floors, corroboration) instead of flagged outright: one feed on
// long-established cloud infrastructure no longer lands in Review by itself.
// Comparing with the listing its verdict recorded keeps a domain that stays
// clean from being scored again on every refresh.
func (w *Worker) rescanThreat() {
	s := w.get()
	if !s.Enabled || ParseMode(s.Mode) == ModeOff {
		return
	}
	verdicts, err := w.store.CleanVerdicts()
	if err != nil {
		slog.Warn("threat rescan: list clean verdicts failed", "err", err)
		return
	}
	queued := 0
	for _, v := range verdicts {
		hits := w.threat.hits(v.Domain)
		if hits == 0 || feedLevel(hits) <= feedLevel(scoredFeedHits(v.Factors)) {
			continue
		}
		if queued >= rescanBatch {
			break // the rest on the next refresh: they are still listed then
		}
		if w.rescoreDomain(v.Domain, fmt.Sprintf("now listed on %d threat-intel feeds", hits)) {
			queued++
		}
	}
	if queued > 0 {
		slog.Info("threat rescan: newly listed domains sent back to scoring", "count", queued)
	}
}

// rescanBatch caps the domains one feed refresh sends back to scoring (each
// may spend reputation lookups).
const rescanBatch = 200

// feedLevel is how corroborated a listing is, as the scorer weighs it: none,
// one feed, two, three or more.
func feedLevel(hits int) int { return min(hits, 3) }

// scoredFeedHits reads, from a verdict's factors, how many feeds listed the
// domain when it was scored (0 = none).
func scoredFeedHits(factorsJSON string) int {
	var fs []Factor
	if json.Unmarshal([]byte(factorsJSON), &fs) != nil {
		return 0
	}
	for _, f := range fs {
		if f.Label != "Threat intel" {
			continue
		}
		switch {
		case f.Delta <= -90:
			return 3
		case f.Delta <= -70:
			return 2
		default:
			return 1
		}
	}
	return 0
}

// TrustedCount / ThreatCount report the loaded set sizes (for the UI). Trusted
// includes the always-on CDN/cloud-edge allowlist.
func (w *Worker) TrustedCount() int { return w.trusted.count() + CDNCount() }
func (w *Worker) ThreatCount() int  { return w.threat.count() }

// TrustedSearch / ThreatSearch return matching domains (for the list viewers).
// Trusted results lead with matching CDN providers.
func (w *Worker) TrustedSearch(q string, limit int) []string {
	ql := strings.ToLower(strings.TrimSpace(q))
	var out []string
	for _, d := range CDNTrustedDomains {
		if ql == "" || strings.Contains(d, ql) {
			out = append(out, d)
			if len(out) >= limit {
				return out
			}
		}
	}
	return append(out, w.trusted.search(q, limit-len(out))...)
}
func (w *Worker) ThreatSearch(q string, limit int) []string { return w.threat.search(q, limit) }

func (w *Worker) process(ctx context.Context, domain string) {
	s := w.get()
	mode := ParseMode(s.Mode)
	if !s.Enabled || mode == ModeOff {
		return
	}
	if w.Excluded(domain) {
		return // excluded after it was queued
	}
	w.trusted.ensureSync(trustedSources(s))
	w.threat.ensureSync(threatSources(s))
	w.nrd.ensure(s.NRDEnabled)
	w.netrep.ensure(s.NetRepEnabled)
	if done, err := w.store.IsClassified(domain); err != nil || done {
		return // already have a verdict (or DB error) — classify once.
	}

	// Fast path: a domain on the trusted/popular list — or CDN / cloud-edge infra —
	// short-circuits to fully legitimate (computeScore ignores every other signal
	// for it). Record it now and SKIP the expensive WHOIS / reputation / LLM
	// lookups, which also conserves third-party API budget (e.g. VirusTotal's daily
	// quota) and keeps the queue moving on the common case.
	listTrusted := w.trusted.has(domain)
	cdn := cdnInfrastructure(domain) // a verdict here would apply to the whole provider — never blockable
	if listTrusted || cdn {
		w.recordTrusted(ScoreInput{Domain: domain, ListTrusted: listTrusted, CDN: cdn})
		w.categorize(ctx, s, domain) // the shortcut skipped the model: ask it what the domain is
		return
	}

	// WHOIS (optional): registration data, and nameserver ownership — a domain
	// served only by a trusted company's own nameservers is weighed as trust
	// evidence (not a shortcut: see trustedNameservers).
	var whois WhoisInfo
	platform := HostingPlatform(domain)
	if s.WhoisEnabled && platform == "" { // a platform subdomain has no registration of its own
		if info, werr := w.whois.Lookup(ctx, domain); werr == nil {
			whois = info
		} else {
			// The verdict freezes its factors, so a failed lookup here permanently
			// records "registration date unknown" — make that visible.
			slog.Warn("whois lookup failed — verdict scored without domain age", "domain", domain, "err", werr)
		}
	}
	nsOwner := w.trustedNameservers(ctx, domain, whois)

	// Open-data age and network signals (each behind its own switch).
	nrdDays := w.nrd.days(domain)
	certAge, noCert := 0, false
	if s.CTEnabled && whois.AgeDays <= 0 && nrdDays == 0 && platform == "" {
		switch a := w.ct.firstCertAge(ctx, domain); {
		case a > 0:
			certAge = a
		case a == 0:
			noCert = true
		}
	}
	var netRep NetRep
	if s.NetRepEnabled {
		netRep = w.netrep.check(ctx, domain)
	}

	// Not trusted: spend the remaining signals. Threat-feed membership is a cheap
	// in-memory lookup that also tells us how many feeds list the domain. A hit on
	// 2+ feeds is corroborated enough to be a definitive block, so we can skip the
	// costly reputation + LLM work entirely (saves API quota and LLM tokens).
	threatHits := w.threat.hits(domain)
	threat := threatHits > 0
	strong := threatHits >= 2 || netRep.Listed()

	var rep Reputation
	if !strong {
		rep = w.rep.Lookup(ctx, domain, s)
		strong = rep.Malicious()
	}

	// The local LLM is an OPTIONAL enrichment layer mainly used to cut false
	// positives. Skip it when a corroborated threat / reputation hit already makes
	// the block definitive — the model can't reduce a false positive there, so the
	// call would only spend tokens. With AI off (or no model), classification runs
	// purely on the deterministic signals above.
	var v Verdict
	asked := false // whether the model was actually consulted for this verdict
	if aiConfigured(s) && !strong {
		start := time.Now()
		vv, usage, err := w.clientFor(s).Classify(ctx, domain, Hints{Threat: threat, Whois: whois.summary(), Reputation: rep.summary()})
		_ = w.store.RecordLLMUsage(err != nil, usage.PromptTokens, usage.CompletionTokens, int(time.Since(start).Milliseconds()))
		if err != nil {
			// AI is configured but unreachable: retry on the next sighting rather than
			// recording a model-less verdict that would stick. (Static-only users never
			// reach this path.)
			slog.Warn("classify failed", "domain", domain, "err", err)
			return
		}
		v = vv
		asked = true
	}

	// Score the domain: start at baseLegitimacy and let the evidence move it.
	// A lone threat-feed hit is weighed as a possible misreport (see computeScore);
	// corroboration across feeds, or a reputation flag, blocks decisively.
	in := ScoreInput{Domain: domain, Platform: platform, NSTrustedOn: nsOwner, Threat: threat, ThreatHits: threatHits, Whois: whois, Rep: rep, Verdict: v,
		Lex: w.lex.Load(), Behaviour: w.obs.get(domain), NRDDays: nrdDays, CertAgeDays: certAge, NoCert: noCert, Net: netRep}
	score := computeScore(in)

	// A block requires an actual threat indicator (the model named a security
	// category, a threat feed matched, or a reputation service flagged it) AND a low
	// legitimacy score. So young / risky-TLD legitimate domains are NOT blocked on
	// structure alone, and a trusted/established domain stays well above the threshold.
	// A tunneling pattern seen on this network is an indicator too, but only for
	// review: it is a heuristic, never enough to auto-block on its own.
	tunnel := in.Behaviour.Tunneling()
	candidate := v.ShouldBlock() || threat || in.RepMalicious() || tunnel || netRep.Listed()
	block := candidate && score.Legitimacy < blockThreshold
	reviewOnly := tunnel && !v.ShouldBlock() && !threat && !in.RepMalicious() && !netRep.Listed()

	category := v.Category
	if (threat || in.RepMalicious() || netRep.Listed()) && !v.ShouldBlock() {
		category = "malware" // flagged by a feed/reputation but the model missed it
	} else if tunnel && !v.ShouldBlock() {
		category = "malware" // data smuggled over DNS: a compromised client
	}
	// A verdict's category is the reason it blocks; one that doesn't block is
	// "other" — a malicious tag the trust/score overrode is dropped, and what the
	// domain is (social, …) is its content category, recorded separately below.
	if !block || category == "" {
		category = "other"
	}

	status := store.ClassClean
	if block {
		if mode == ModeAuto && score.Legitimacy < autoThreshold && !reviewOnly {
			status = store.ClassAuto // confidently malicious -> enforce now
		} else {
			status = store.ClassSuggested // borderline -> review
		}
	}

	factors, _ := json.Marshal(score.Factors)
	reason := strings.TrimSpace(fmt.Sprintf("legitimacy %d%%. %s", score.Legitimacy, strings.TrimSpace(v.Reason)))
	model := s.Model
	if !asked || model == "" {
		// No LLM in play (off, or skipped because the evidence was already
		// decisive): the verdict comes from the deterministic signals alone, and
		// must not be shown as the model's opinion.
		model = "static analysis"
	}
	// What the domain is: the model's content category when it was asked (a
	// security answer says nothing about content), or nothing to ask when the
	// category database knows the domain.
	content, checked := "", w.knownToCategoryDB(domain)
	if asked {
		checked = true
		if IsContentCategory(v.Category) && v.Category != categories.Other {
			content = v.Category
		}
	}
	inserted, err := w.store.InsertClassification(store.Classification{
		Domain: domain, Category: category, Block: block, Status: status,
		Confidence: v.Confidence, Score: score.Legitimacy, Factors: factors,
		Reason: reason, Model: model, Trusted: false, Threat: threat,
		ContentCategory: content, ContentChecked: checked,
	})
	if err != nil {
		slog.Warn("store classification failed", "domain", domain, "err", err)
		return
	}
	slog.Debug("classified", "domain", domain, "category", category, "status", status, "legitimacy", score.Legitimacy, "threat", threat)
	if inserted && status == store.ClassAuto && w.reload != nil {
		_ = w.reload()
	}
}

// trustedNameservers returns the trusted company whose own nameservers serve
// domain (see nscheck.go), or "". Only RDAP (HTTPS) data counts: port-43 WHOIS
// is plain TCP, so an on-path attacker could claim a brand's nameservers. Every
// listed nameserver must belong to that one company and none to a shared DNS
// host, and the zone must actually resolve.
func (w *Worker) trustedNameservers(ctx context.Context, domain string, whois WhoisInfo) string {
	if w.get().NSCheckDisabled || whois.Source != "rdap" || len(whois.Nameservers) == 0 {
		return ""
	}
	owner := ""
	for _, ns := range whois.Nameservers {
		reg := RegisteredDomain(ns)
		if reg == "" || sharedDNSHost(reg) || (owner != "" && reg != owner) {
			return ""
		}
		owner = reg
	}
	if !w.trusted.has(owner) || !w.zoneResolves(ctx, domain) {
		return ""
	}
	return owner
}

// recordTrusted stores a clean verdict for a domain the fast paths proved
// legitimate (trusted list, CDN, or trusted nameservers), reusing computeScore so
// the stored factor breakdown matches what the full path would have produced.
func (w *Worker) recordTrusted(in ScoreInput) {
	score := computeScore(in)
	reason := fmt.Sprintf("legitimacy %d%%", score.Legitimacy)
	if len(score.Factors) > 0 {
		reason += ". " + score.Factors[0].Detail
	}
	factors, _ := json.Marshal(score.Factors)
	if _, err := w.store.InsertClassification(store.Classification{
		Domain: in.Domain, Category: "other", Block: false, Status: store.ClassClean,
		Score: score.Legitimacy, Factors: factors, Reason: reason,
		Model: "static analysis", Trusted: true,
	}); err != nil {
		slog.Warn("store classification failed", "domain", in.Domain, "err", err)
	}
}
