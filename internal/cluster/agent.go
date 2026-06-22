package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// Agent runs on a worker: it periodically pulls the config snapshot from the
// master and applies it to the local store, then triggers a policy reload.
type Agent struct {
	masterURL string
	token     string
	interval  time.Duration
	store     *store.Store
	reload    func() error
	client    *http.Client
}

// NewAgent builds a replication agent.
func NewAgent(masterURL, token string, interval time.Duration, st *store.Store, reload func() error) *Agent {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Agent{
		masterURL: strings.TrimRight(masterURL, "/"),
		token:     token,
		interval:  interval,
		store:     st,
		reload:    reload,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Run syncs immediately, then every interval until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) {
	slog.Info("cluster agent started", "master", a.masterURL, "interval", a.interval)
	a.syncOnce(ctx)
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.syncOnce(ctx)
		}
	}
}

func (a *Agent) syncOnce(ctx context.Context) {
	snap, err := a.fetch(ctx)
	if err != nil {
		slog.Warn("cluster sync failed", "err", err)
		return
	}
	cur, _ := a.store.GetConfigVersion()
	if snap.Version == cur {
		return // already up to date
	}
	if err := a.store.ApplySnapshot(snap.Version, snap.Rules, snap.Rewrites); err != nil {
		slog.Warn("cluster apply failed", "err", err)
		return
	}
	if a.reload != nil {
		_ = a.reload()
	}
	slog.Info("cluster synced", "version", snap.Version, "rules", len(snap.Rules), "rewrites", len(snap.Rewrites))
}

func (a *Agent) fetch(ctx context.Context) (*Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.masterURL+"/api/cluster/snapshot", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("master returned status %d", resp.StatusCode)
	}
	var snap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return nil, err
	}
	return &snap, nil
}
