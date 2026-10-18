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
	SourceBuiltin    = "builtin"    // the built-in list of common platforms
	SourceModel      = "model"      // the language model
	SourceLocal      = "local"      // a name that only exists inside a network
	SourceNone       = ""           // nothing knows it: "other"
)

// categorizerRefresh is how often the categorizer reloads overrides and
// verdicts; edits through the API reload at once (Refresh).
const categorizerRefresh = 30 * time.Second

// A query is labelled when it arrives, which for a new domain is before the
// classifier has looked at it — so its first queries land in "other". Every
// relabelEvery, queries from the last relabelWindow still in "other" are
// labelled again, and move once their domain has a category (a few pages per
// pass, newest first, bounded so a busy cluster's pass stays cheap).
const (
	relabelEvery    = 5 * time.Minute
	relabelWindow   = 7 * 24 * time.Hour
	relabelPage     = 20000
	relabelMaxPages = 50
)

// Categorizer labels every domain the control plane sees with what it is. The
// first source that knows the domain wins:
//
//  1. an operator's override;
//  2. a local name (reverse lookup, private-use TLD, single label): "local";
//  3. an enforced security verdict (the classifier blocks it as phishing, …);
//  4. the category database (UT1);
//  5. the built-in list of common platforms (Apple, Microsoft, CDNs, …);
//  6. the language model's content category, for domains neither knows;
//  7. "other".
//
// A query answered by a local record (a rewrite) is "local" whatever its
// name: see Label.
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
	vc, err := c.st.ClassifierCategories()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.overrides, c.verdicts = ov, vc
	c.mu.Unlock()
	return nil
}

// Run refreshes periodically, and relabels queries left in "other", until ctx
// ends.
func (c *Categorizer) Run(ctx context.Context) {
	t := time.NewTicker(categorizerRefresh)
	defer t.Stop()
	relabel := time.NewTimer(time.Minute) // first pass once the database has had time to load
	defer relabel.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Refresh(); err != nil {
				slog.Warn("categorizer refresh failed", "err", err)
			}
		case <-relabel.C:
			if n, err := c.Relabel(time.Now().Add(-relabelWindow)); err != nil {
				slog.Warn("relabel queries failed", "err", err)
			} else if n > 0 {
				slog.Info("relabelled queries whose domain now has a category", "queries", n)
			}
			relabel.Reset(relabelEvery)
		}
	}
}

// Relabel gives queries since `since` still labelled "other" the category
// their domain has now, and returns how many moved.
func (c *Categorizer) Relabel(since time.Time) (int, error) {
	if c.db != nil && c.db.Status().UpdatedAt == 0 {
		return 0, nil // the database hasn't loaded: everything would look unknown
	}
	known := map[string]string{} // name -> category, per pass
	moved := 0
	var before int64
	for page := 0; page < relabelMaxPages; page++ {
		rows, err := c.st.OtherQueries(since.UnixMilli(), before, relabelPage)
		if err != nil {
			return moved, err
		}
		labels := map[int64]string{}
		for _, r := range rows {
			key := r.Name
			if answeredLocally(r.Action) {
				key = "\x00local\x00" + r.Name
			}
			cat, ok := known[key]
			if !ok {
				cat = c.queryCategory(r.Name, r.Action)
				known[key] = cat
			}
			if cat != categories.Other {
				labels[r.ID] = cat
			}
		}
		n, err := c.st.RelabelContent(labels)
		moved += n
		if err != nil {
			return moved, err
		}
		if len(rows) < relabelPage {
			break
		}
		before = rows[len(rows)-1].ID
	}
	return moved, nil
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
	case IsLocalName(name):
		return categories.Local, SourceLocal
	case enforced != "":
		return enforced, SourceClassifier
	}
	if c.db != nil {
		if cat, ok := c.db.Lookup(name); ok {
			return cat, SourceDatabase
		}
	}
	// A customer's name on a shared hosting platform (see builtinCategory)
	// gets the platform's built-in label only when the model has nothing to
	// say about it; any other name, before the model.
	builtin, inList := categories.Builtin(name)
	onPlatform := HostingPlatform(name) != ""
	if inList && !onPlatform {
		return builtin, SourceBuiltin
	}
	if model != "" && model != categories.Other {
		return model, SourceModel
	}
	if inList {
		return builtin, SourceBuiltin
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
		entries[i].ContentCategory = c.queryCategory(entries[i].Name, entries[i].Action)
	}
}

// builtinCovers reports whether the built-in list decides name's category
// ahead of the model. Not for a customer's name on a shared hosting platform
// (evil.github.io, shop.myshopify.com, a bucket on amazonaws.com): anyone can
// publish there, so the platform's label says little about the site and must
// not cover up what the model says about it — it is only a fallback there.
func builtinCovers(name string) bool {
	if HostingPlatform(name) != "" {
		return false
	}
	_, ok := categories.Builtin(name)
	return ok
}

// answeredLocally reports whether a query's answer came from the network's
// own records (a rewrite, or a name the resolver is authoritative for).
func answeredLocally(action string) bool { return action == "rewrite" || action == "authoritative" }

// queryCategory is a query's category: "local" when a local record answered
// it (the network's own names, whatever they look like), otherwise its
// name's. An operator's override and a security verdict the classifier
// enforces still win: a local answer never hides that a name is phishing.
func (c *Categorizer) queryCategory(name, action string) string {
	cat, src := c.Category(name)
	if answeredLocally(action) && src != SourceOverride && src != SourceClassifier {
		return categories.Local
	}
	return cat
}

// Status reports the category database's state (zero if there is none).
func (c *Categorizer) Status() categories.Status {
	if c.db == nil {
		return categories.Status{}
	}
	return c.db.Status()
}

// DomainsFor returns the per-domain corrections agents need to block the given
// categories exactly as the control plane labels them: every operator override
// (one moving a domain out of a blocked category exempts it), and the model's
// labels in blocked categories for domains the database doesn't know (where it
// does, its category is what the control plane shows, so it is what counts).
func (c *Categorizer) DomainsFor(blocked []string) map[string]string {
	if len(blocked) == 0 {
		return nil
	}
	want := make(map[string]bool, len(blocked))
	for _, b := range blocked {
		want[b] = true
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.overrides))
	for d, o := range c.overrides {
		out[d] = o.Category
	}
	inDB := func(d string) bool {
		if c.db == nil {
			return false
		}
		_, known := c.db.Lookup(d)
		return known
	}
	// The built-in list in the blocked categories, where the database
	// doesn't already label the domain.
	for d, cat := range categories.BuiltinDomains(want) {
		if _, overridden := out[d]; !overridden && !inDB(d) {
			out[d] = cat
		}
	}
	for d, cat := range c.verdicts.Content {
		if !want[cat] {
			continue
		}
		if _, set := out[d]; set || inDB(d) {
			continue
		}
		if builtinCovers(d) {
			continue // the built-in list labels it (in another category)
		}
		out[d] = cat
	}
	return out
}
