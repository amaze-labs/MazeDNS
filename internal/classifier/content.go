package classifier

import (
	"context"
	"log/slog"
	"time"

	"github.com/IPMaze/MazeDNS/internal/categories"
)

// contentBackfillEvery paces the backfill of content categories for verdicts
// recorded before categories existed (see Worker.backfillContent).
const contentBackfillEvery = 10 * time.Second

// SetCategoryDB gives the worker the category database, so it asks the model
// for a content category only for domains the database doesn't know.
func (w *Worker) SetCategoryDB(h *categories.Holder) { w.catDB = h }

// knownToCategoryDB reports whether the category database labels domain.
func (w *Worker) knownToCategoryDB(domain string) bool {
	if w.catDB == nil {
		return false
	}
	_, ok := w.catDB.Lookup(domain)
	return ok
}

// categoryDBReady reports whether "not in the database" can be trusted: there
// is no database, or it has loaded at least once. Until then every domain
// looks unknown, and asking the model would waste calls UT1 would answer.
func (w *Worker) categoryDBReady() bool {
	return w.catDB == nil || w.catDB.Status().UpdatedAt > 0
}

// categorize asks the model what a scored domain is, when the category
// database doesn't know it and a model is configured, and records the answer.
// Without a model the domain stays unasked, for when one is configured.
func (w *Worker) categorize(ctx context.Context, s Settings, domain string) {
	if w.knownToCategoryDB(domain) {
		_ = w.store.SetContentCategory(domain, "") // nothing to ask
		return
	}
	if !aiConfigured(s) || !w.categoryDBReady() {
		return // stays unasked: the backfill picks it up later
	}
	start := time.Now()
	v, usage, err := w.clientFor(s).Classify(ctx, domain, Hints{})
	_ = w.store.RecordLLMUsage(err != nil, usage.PromptTokens, usage.CompletionTokens, int(time.Since(start).Milliseconds()))
	if err != nil {
		slog.Warn("categorize failed", "domain", domain, "err", err)
		return // stays unasked: retried by the backfill
	}
	content := ""
	if IsContentCategory(v.Category) && v.Category != categories.Other {
		content = v.Category
	}
	if err := w.store.SetContentCategory(domain, content); err != nil {
		slog.Warn("store content category failed", "domain", domain, "err", err)
	}
}

// backfillContent works through verdicts that were never asked for a content
// category: those the category database knows are marked done in bulk; the
// first one it doesn't know is asked of the model (one call per tick).
func (w *Worker) backfillContent(ctx context.Context) {
	s := w.get()
	if !s.Enabled || !aiConfigured(s) || !w.categoryDBReady() {
		return
	}
	domains, err := w.store.UncheckedContent(50)
	if err != nil {
		return
	}
	for _, d := range domains {
		if w.knownToCategoryDB(d) || w.Excluded(d) {
			_ = w.store.SetContentCategory(d, "") // nothing to ask (or not to be asked)
			continue
		}
		w.categorize(ctx, s, d)
		return
	}
}
