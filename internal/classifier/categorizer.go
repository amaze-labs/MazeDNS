package classifier

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// Where a domain's category came from (Categorizer.Category).
const (
	SourceOverride   = "override"   // an operator set it
	SourceClassifier = "classifier" // an enforced security verdict
	SourceDatabase   = "database"   // the category database (UT1)
	SourceModel      = "model"      // the language model
	SourceNone       = ""           // nothing knows it: "other"
)

// categorizerRefresh is how often the categorizer reloads overrides and
// verdicts; edits through the API reload at once (Refresh).
const categorizerRefresh = 30 * time.Second

// Categorizer labels every domain the control plane sees with what it is. The
// first source that knows the domain wins:
//
//  1. an operator's override;
//  2. an enforced security verdict (the classifier blocks it as phishing, …);
//  3. the category database (UT1);
//  4. the language model's content category, for domains the database lacks;
//  5. "other".
type Categorizer struct {
	st *store.Store
	db *categories.Holder // nil = no category database

	mu        sync.RWMutex
	overrides map[string]store.CategoryOverride
	verdicts  store.VerdictCategories
}

// NewCategorizer returns a Categorizer over the store and (optional) category
// database. Call Refresh, then Run to keep it current.
func NewCategorizer(st *store.Store, db *categories.Holder) *Categorizer {
	return &Categorizer{st: st, db: db, overrides: map[string]store.CategoryOverride{}}
}

// Refresh reloads overrides and verdicts from the store.
func (c *Categorizer) Refresh() error {
	ov, err := c.st.CategoryOverrides()
	if err != nil {
		return err
	}
	vc, err := c.st.ClassifierCategories(isLegacyContent)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.overrides, c.verdicts = ov, vc
	c.mu.Unlock()
	return nil
}

// Run refreshes periodically until ctx ends.
func (c *Categorizer) Run(ctx context.Context) {
	t := time.NewTicker(categorizerRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Refresh(); err != nil {
				slog.Warn("categorizer refresh failed", "err", err)
			}
		}
	}
}

// Category returns name's category and where it came from.
func (c *Categorizer) Category(name string) (category, source string) {
	domain := RegisteredDomain(name)
	c.mu.RLock()
	o, overridden := c.overrides[domain]
	enforced := c.verdicts.Enforced[domain]
	model := c.verdicts.Content[domain]
	c.mu.RUnlock()
	switch {
	case overridden:
		return o.Category, SourceOverride
	case enforced != "":
		return enforced, SourceClassifier
	}
	if c.db != nil {
		if cat, ok := c.db.Lookup(name); ok {
			return cat, SourceDatabase
		}
	}
	if model != "" && model != categories.Other {
		return model, SourceModel
	}
	return categories.Other, SourceNone
}

// Override returns the operator's override for domain's registered domain.
func (c *Categorizer) Override(name string) (store.CategoryOverride, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	o, ok := c.overrides[RegisteredDomain(name)]
	return o, ok
}

// Label sets ContentCategory on each entry (in place).
func (c *Categorizer) Label(entries []store.QueryLogEntry) {
	for i := range entries {
		entries[i].ContentCategory, _ = c.Category(entries[i].Name)
	}
}

// Status reports the category database's state (zero if there is none).
func (c *Categorizer) Status() categories.Status {
	if c.db == nil {
		return categories.Status{}
	}
	return c.db.Status()
}

// isLegacyContent reports whether a verdict category from before content
// categories were stored separately is a content one (a model's label).
func isLegacyContent(cat string) bool {
	return IsContentCategory(cat) && cat != categories.Other
}
