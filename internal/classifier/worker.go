package classifier

import (
	"context"
	"fmt"
	"log/slog"
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
	// Threat list (known-malicious domains): a domain here corroborates a
	// malicious verdict (boosting it) and is treated as suspicious even if the
	// model missed it. Built-in public default unless ThreatDisableDefault.
	ThreatListURL        string `json:"threat_list_url"`
	ThreatDisableDefault bool   `json:"threat_disable_default"`
	// WhoisEnabled enriches each classification with the domain's registration
	// data (via RDAP) — domain age is a strong signal for the model.
	WhoisEnabled bool `json:"whois_enabled"`
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
}

// NewWorker builds a classification worker driven by the live settings getter.
func NewWorker(st *store.Store, get func() Settings, reload func() error) *Worker {
	return &Worker{
		store:   st,
		get:     get,
		reload:  reload,
		queue:   make(chan string, 2048),
		recent:  make(map[string]time.Time),
		trusted: newSetHolder("trusted"),
		threat:  newSetHolder("threat"),
		whois:   NewWhoisCache(),
	}
}

// Whois returns cached registration data for a domain (used by the UI detail view).
func (w *Worker) Whois(ctx context.Context, domain string) (WhoisInfo, error) {
	return w.whois.Lookup(ctx, domain)
}

// clientFor returns a cached client for the current endpoint/model/key, rebuilding
// it only when those change.
func (w *Worker) clientFor(s Settings) *Client {
	key := fmt.Sprintf("%s|%s|%s|%s", s.Endpoint, s.Model, s.APIKey, s.Timeout())
	w.clientMu.Lock()
	defer w.clientMu.Unlock()
	if w.client == nil || w.clientKey != key {
		w.client = NewClient(s.Endpoint, s.Model, s.APIKey, s.Timeout())
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
	w.trusted.ensure(trustedSources(s))
	w.threat.ensure(threatSources(s))
	for {
		select {
		case <-ctx.Done():
			return
		case domain := <-w.queue:
			w.process(ctx, domain)
			select {
			case <-ctx.Done():
				return
			case <-time.After(w.get().minGap()):
			}
		}
	}
}

// TrustedCount / ThreatCount report the loaded set sizes (for the UI).
func (w *Worker) TrustedCount() int { return w.trusted.count() }
func (w *Worker) ThreatCount() int  { return w.threat.count() }

// TrustedSearch / ThreatSearch return matching domains (for the list viewers).
func (w *Worker) TrustedSearch(q string, limit int) []string { return w.trusted.search(q, limit) }
func (w *Worker) ThreatSearch(q string, limit int) []string  { return w.threat.search(q, limit) }

func (w *Worker) process(ctx context.Context, domain string) {
	s := w.get()
	mode := ParseMode(s.Mode)
	if !s.Enabled || mode == ModeOff {
		return
	}
	w.trusted.ensure(trustedSources(s))
	w.threat.ensure(threatSources(s))
	if done, err := w.store.IsClassified(domain); err != nil || done {
		return // already have a verdict (or DB error) — classify once.
	}

	// Look the deterministic signals up FIRST, then let the model decide with them
	// in hand (so its category + reasoning incorporate the threat/trusted/WHOIS
	// context).
	trusted := w.trusted.has(domain)
	threat := w.threat.has(domain)
	hints := Hints{Trusted: trusted, Threat: threat}
	if s.WhoisEnabled {
		if info, werr := w.whois.Lookup(ctx, domain); werr == nil {
			hints.Whois = info.summary()
		}
	}
	v, err := w.clientFor(s).Classify(ctx, domain, hints)
	if err != nil {
		slog.Warn("classify failed", "domain", domain, "err", err)
		return
	}
	category, block, conf, reason := v.Category, v.ShouldBlock(), v.Confidence, v.Reason

	// Safety rails — applied after the model as a backstop (a small local model can
	// still hallucinate even with the hints):
	//  - a known threat must never be left non-blocking,
	//  - a trusted domain must never be blocked.
	if threat {
		conf = maxF(conf, 0.97)
		if !block {
			category, block = "malware", true
			reason = "on threat list — flagged malicious (model missed it). " + reason
		} else {
			reason = "confirmed on threat list. " + reason
		}
	}
	if trusted && !threat {
		block = false
		reason = "on trusted list — not blocked. " + reason
	}

	status := store.ClassClean
	if block {
		if mode == ModeAuto {
			status = store.ClassAuto
		} else {
			status = store.ClassSuggested
		}
	}
	inserted, err := w.store.InsertClassification(store.Classification{
		Domain: domain, Category: category, Block: block, Status: status,
		Confidence: conf, Reason: reason, Model: s.Model, Trusted: trusted, Threat: threat,
	})
	if err != nil {
		slog.Warn("store classification failed", "domain", domain, "err", err)
		return
	}
	slog.Debug("classified", "domain", domain, "category", category, "status", status, "trusted", trusted, "threat", threat)
	if inserted && status == store.ClassAuto && w.reload != nil {
		_ = w.reload()
	}
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
