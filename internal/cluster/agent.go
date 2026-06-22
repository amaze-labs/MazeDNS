package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// Agent runs on a worker: it periodically pulls the config snapshot from the
// master (authenticating with this node's API key), applies it to the local
// store, triggers a policy reload, and reports this node's stats to the master.
type Agent struct {
	masterURL string
	nodeKey   string
	interval  time.Duration
	store     *store.Store
	reload    func() error
	stats     func() store.NodeStats
	client    *http.Client
}

// NewAgent builds a replication agent. nodeKey is the per-node API key issued by
// the master; stats (may be nil) reports this node's query counters each poll.
func NewAgent(masterURL, nodeKey string, interval time.Duration, st *store.Store, reload func() error, stats func() store.NodeStats) *Agent {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Agent{
		masterURL: strings.TrimRight(masterURL, "/"),
		nodeKey:   nodeKey,
		interval:  interval,
		store:     st,
		reload:    reload,
		stats:     stats,
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
	req.Header.Set("Authorization", "Bearer "+a.nodeKey)
	ver, _ := a.store.GetConfigVersion()
	req.Header.Set("X-MazeDNS-Node-Version", strconv.FormatInt(ver, 10))
	if a.stats != nil {
		if b, err := json.Marshal(a.stats()); err == nil {
			req.Header.Set("X-MazeDNS-Stats", string(b))
		}
	}
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
