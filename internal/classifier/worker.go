package classifier

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
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
	// TrustedListURL points at a public list of known-legitimate domains (a file
	// path or URL — plain/hosts/ranked-CSV). When the model flags a domain on
	// this list it is treated as a likely false positive: never auto-blocked,
	// only suggested for review. TrustedTopN caps how many entries are loaded.
	TrustedListURL string `json:"trusted_list_url"`
	TrustedTopN    int    `json:"trusted_top_n"`
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

	trusted     atomic.Pointer[TrustedSet]
	trustedSrc  atomic.Value // string: the source the current trusted set was built from
	trustedBusy atomic.Bool
}

// NewWorker builds a classification worker driven by the live settings getter.
func NewWorker(st *store.Store, get func() Settings, reload func() error) *Worker {
	return &Worker{
		store:  st,
		get:    get,
		reload: reload,
		queue:  make(chan string, 2048),
		recent: make(map[string]time.Time),
	}
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

// ensureTrusted (re)loads the trusted list in the background when the configured
// source changes, swapping it in atomically. Never blocks the worker.
func (w *Worker) ensureTrusted(s Settings) {
	src := s.TrustedListURL + "|" + strconv.Itoa(s.TrustedTopN)
	if s.TrustedListURL == "" {
		if cur, _ := w.trustedSrc.Load().(string); cur != src {
			w.trusted.Store(nil)
			w.trustedSrc.Store(src)
		}
		return
	}
	if cur, _ := w.trustedSrc.Load().(string); cur == src {
		return
	}
	if !w.trustedBusy.CompareAndSwap(false, true) {
		return // a load is already in flight
	}
	go func() {
		defer w.trustedBusy.Store(false)
		set, err := LoadTrusted(s.TrustedListURL, s.TrustedTopN)
		if err != nil {
			slog.Warn("trusted list load failed", "source", s.TrustedListURL, "err", err)
			return
		}
		w.trusted.Store(set)
		w.trustedSrc.Store(src)
		slog.Info("trusted list loaded", "source", s.TrustedListURL, "domains", set.Count())
	}()
}

// TrustedCount returns how many domains are loaded in the trusted set.
func (w *Worker) TrustedCount() int { return w.trusted.Load().Count() }

func (w *Worker) process(ctx context.Context, domain string) {
	s := w.get()
	mode := ParseMode(s.Mode)
	if !s.Enabled || mode == ModeOff {
		return
	}
	w.ensureTrusted(s)
	if done, err := w.store.IsClassified(domain); err != nil || done {
		return // already have a verdict (or DB error) — classify once.
	}
	v, err := w.clientFor(s).Classify(ctx, domain)
	if err != nil {
		slog.Warn("classify failed", "domain", domain, "err", err)
		return
	}
	block := v.ShouldBlock()
	reason := v.Reason
	// False-positive guard: if the model flags a domain that's on the trusted
	// list, never auto-block it — record it as a suggestion for human review.
	trusted := block && w.trusted.Load().Has(domain)
	status := store.ClassClean
	if block {
		if mode == ModeAuto && !trusted {
			status = store.ClassAuto
		} else {
			status = store.ClassSuggested
		}
	}
	if trusted {
		reason = "on trusted list — review before blocking. " + reason
	}
	inserted, err := w.store.InsertClassification(store.Classification{
		Domain: domain, Category: v.Category, Block: block, Status: status,
		Confidence: v.Confidence, Reason: reason, Model: s.Model, Trusted: trusted,
	})
	if err != nil {
		slog.Warn("store classification failed", "domain", domain, "err", err)
		return
	}
	slog.Debug("classified", "domain", domain, "category", v.Category, "block", block, "status", status, "trusted", trusted)
	// An auto-block verdict takes effect immediately — rebuild the policy.
	if inserted && status == store.ClassAuto && w.reload != nil {
		_ = w.reload()
	}
}
