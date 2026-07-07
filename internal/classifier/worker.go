package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

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
	}
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
func (w *Worker) Enqueue(name string) {
	s := w.get()
	if !s.Enabled || ParseMode(s.Mode) == ModeOff {
		return
	}
	domain := RegisteredDomain(name)
	if domain == "" {
		return
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
	// domains already have the signals (rather than racing the first lookup).
	s := w.get()
	w.trusted.ensureSync(trustedSources(s))
	w.threat.ensureSync(threatSources(s))
	go w.refreshThreatLoop(ctx)
	for {
		select {
		case <-ctx.Done():
			return
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
			if !s.Enabled || ParseMode(s.Mode) == ModeOff {
				continue
			}
			w.threat.refresh(threatSources(s))
		}
	}
}

// rescanThreat re-checks existing clean (untrusted) verdicts against the current
// threat set and flips any now-listed domain to a block, so a domain that turned
// malicious after we classified it doesn't stay allowed until it's re-queried.
// Fired after the threat set (re)loads.
func (w *Worker) rescanThreat() {
	s := w.get()
	if !s.Enabled || ParseMode(s.Mode) == ModeOff {
		return
	}
	domains, err := w.store.CleanDomains()
	if err != nil {
		slog.Warn("threat rescan: list clean domains failed", "err", err)
		return
	}
	autoMode := ParseMode(s.Mode) == ModeAuto
	flipped, autoFlipped := 0, 0
	for _, d := range domains {
		hits := w.threat.hits(d)
		if hits == 0 {
			continue
		}
		// A lone feed could be a misreport — only multi-feed corroboration auto-blocks
		// a previously-clean domain; a single feed is sent to review instead.
		status := store.ClassSuggested
		reason := "re-flagged: now listed on 1 threat-intel feed — review (possible misreport)"
		if hits >= 2 {
			reason = fmt.Sprintf("re-flagged: now listed on %d threat-intel feeds", hits)
			if autoMode {
				status = store.ClassAuto
			}
		}
		ok, err := w.store.FlagThreat(d, status, reason)
		if err != nil {
			slog.Warn("threat rescan: flag failed", "domain", d, "err", err)
			continue
		}
		if ok {
			flipped++
			if status == store.ClassAuto {
				autoFlipped++
			}
		}
	}
	if flipped > 0 {
		slog.Info("threat rescan re-flagged clean domains", "count", flipped, "auto", autoFlipped)
		if autoFlipped > 0 && w.reload != nil {
			_ = w.reload()
		}
	}
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
	w.trusted.ensureSync(trustedSources(s))
	w.threat.ensureSync(threatSources(s))
	if done, err := w.store.IsClassified(domain); err != nil || done {
		return // already have a verdict (or DB error) — classify once.
	}

	// Fast path: a domain on the trusted/popular list — or CDN / cloud-edge infra —
	// short-circuits to fully legitimate (computeScore ignores every other signal
	// for it). Record it now and SKIP the expensive WHOIS / reputation / LLM
	// lookups, which also conserves third-party API budget (e.g. VirusTotal's daily
	// quota) and keeps the queue moving on the common case.
	listTrusted := w.trusted.has(domain)
	cdn := IsCDN(domain) // a verdict here would apply to the whole provider — never blockable
	if listTrusted || cdn {
		w.recordTrusted(ScoreInput{Domain: domain, ListTrusted: listTrusted, CDN: cdn})
		return
	}

	// WHOIS (optional) is looked up next because it yields a second fast path:
	// nameserver trust. A domain served by a trusted entity's own authoritative
	// nameservers (NS can't be faked) is that entity's infrastructure, so it cannot
	// be phishing *of* it — short-circuit before spending reputation/LLM budget.
	var whois WhoisInfo
	if s.WhoisEnabled {
		if info, werr := w.whois.Lookup(ctx, domain); werr == nil {
			whois = info
		} else {
			// The verdict freezes its factors, so a failed lookup here permanently
			// records "registration date unknown" — make that visible.
			slog.Warn("whois lookup failed — verdict scored without domain age", "domain", domain, "err", werr)
		}
	}
	for _, ns := range whois.Nameservers {
		if reg := RegisteredDomain(ns); reg != "" && (w.trusted.has(reg) || IsCDN(ns)) {
			w.recordTrusted(ScoreInput{Domain: domain, NSTrustedOn: reg, Whois: whois})
			return
		}
	}

	// Not trusted: spend the remaining signals. Threat-feed membership is a cheap
	// in-memory lookup that also tells us how many feeds list the domain. A hit on
	// 2+ feeds is corroborated enough to be a definitive block, so we can skip the
	// costly reputation + LLM work entirely (saves API quota and LLM tokens).
	threatHits := w.threat.hits(domain)
	threat := threatHits > 0
	strong := threatHits >= 2

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
	}

	// Score the domain: start at 100% legitimate and let every risk factor deduct.
	// A lone threat-feed hit is weighed as a possible misreport (see computeScore);
	// corroboration across feeds, or a reputation flag, blocks decisively.
	in := ScoreInput{Domain: domain, Threat: threat, ThreatHits: threatHits, Whois: whois, Rep: rep, Verdict: v}
	score := computeScore(in)

	// A block requires an actual threat indicator (the model named a security
	// category, a threat feed matched, or a reputation service flagged it) AND a low
	// legitimacy score. So young / risky-TLD legitimate domains are NOT blocked on
	// structure alone, and a trusted/established domain stays well above the threshold.
	candidate := v.ShouldBlock() || threat || in.RepMalicious()
	block := candidate && score.Legitimacy < blockThreshold

	category := v.Category
	if (threat || in.RepMalicious()) && !v.ShouldBlock() {
		category = "malware" // flagged by a feed/reputation but the model missed it
	}
	// A clean verdict must not keep a malicious tag: if it isn't blocked, drop any
	// security category the model assigned (it was overridden by trust/score).
	if !block && blockCategories[category] {
		category = "other"
	}
	// Static-only analysis (no model) leaves the category blank for clean domains —
	// content categories (social/streaming/…) need the LLM. Fall back to "other".
	if category == "" {
		category = "other"
	}

	status := store.ClassClean
	if block {
		if mode == ModeAuto && score.Legitimacy < autoThreshold {
			status = store.ClassAuto // confidently malicious -> enforce now
		} else {
			status = store.ClassSuggested // borderline -> review
		}
	}

	factors, _ := json.Marshal(score.Factors)
	reason := strings.TrimSpace(fmt.Sprintf("legitimacy %d%%. %s", score.Legitimacy, strings.TrimSpace(v.Reason)))
	model := s.Model
	if model == "" {
		model = "static analysis" // no LLM in play — verdict from the deterministic signals
	}
	inserted, err := w.store.InsertClassification(store.Classification{
		Domain: domain, Category: category, Block: block, Status: status,
		Confidence: v.Confidence, Score: score.Legitimacy, Factors: factors,
		Reason: reason, Model: model, Trusted: false, Threat: threat,
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
