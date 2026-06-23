// Package lists fetches and refreshes remote rule lists (e.g. a .list file in a
// GitHub repo) on a schedule, replacing the owning list's rules in the store.
package lists

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/IPMaze/MazeDNS/internal/ruleimport"
	"github.com/IPMaze/MazeDNS/internal/store"
)

const maxListBytes = 32 << 20 // 32 MiB safety cap

// Refresher polls URL-backed lists and re-fetches those whose interval elapsed.
type Refresher struct {
	store  *store.Store
	reload func() error
	client *http.Client
}

// NewRefresher builds a Refresher; reload (may be nil) rebuilds the policy after
// any list changes.
func NewRefresher(st *store.Store, reload func() error) *Refresher {
	return &Refresher{store: st, reload: reload, client: &http.Client{Timeout: 30 * time.Second}}
}

// Run checks for due lists every minute until ctx is cancelled.
func (rf *Refresher) Run(ctx context.Context) {
	slog.Info("list refresher started")
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	rf.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rf.tick(ctx)
		}
	}
}

func (rf *Refresher) tick(ctx context.Context) {
	due, err := rf.store.DueURLLists(time.Now().Unix())
	if err != nil {
		slog.Warn("list refresh query failed", "err", err)
		return
	}
	changed := false
	for _, l := range due {
		if rf.Refresh(ctx, l) {
			changed = true
		}
	}
	if changed && rf.reload != nil {
		_ = rf.reload()
	}
}

// Refresh fetches one URL list and replaces its rules, recording the outcome.
// It returns true if the fetch succeeded (rules were replaced).
func (rf *Refresher) Refresh(ctx context.Context, l store.List) bool {
	n, err := rf.fetchAndApply(ctx, l)
	if err != nil {
		slog.Warn("list refresh failed", "list", l.Name, "url", l.URL, "err", err)
		_ = rf.store.MarkListFetched(l.ID, err.Error())
		return false
	}
	_ = rf.store.MarkListFetched(l.ID, "")
	slog.Info("list refreshed", "list", l.Name, "rules", n)
	return true
}

func (rf *Refresher) fetchAndApply(ctx context.Context, l store.List) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "MazeDNS")
	resp, err := rf.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("fetch returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes))
	if err != nil {
		return 0, err
	}
	parsed := ruleimport.Parse(string(body))
	if len(parsed) == 0 {
		return 0, fmt.Errorf("no valid rules found at %s", l.URL)
	}
	rules := make([]store.Rule, 0, len(parsed))
	for _, p := range parsed {
		rules = append(rules, store.Rule{Action: p.Action, Domain: p.Domain})
	}
	return rf.store.ReplaceListRules(l.ID, l.Category, rules)
}
