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

const shipBatch = 5000 // max query-log entries shipped to the master per cycle

// Agent runs on a worker: each cycle it pulls the config snapshot from the
// master (authenticating with this node's API key), applies it, reports this
// node's counters, and ships its new query-log entries to the master so the
// dashboard is cluster-wide. None of this touches the DNS hot path.
type Agent struct {
	masterURL   string
	nodeKey     string
	interval    time.Duration
	store       *store.Store
	reload      func() error
	stats       func() store.NodeStats
	setPause    func(int64)
	client      *http.Client
	lastShipped int64
}

// NewAgent builds a replication agent. nodeKey is the per-node API key issued by
// the master; stats (may be nil) reports this node's query counters each poll;
// setPause (may be nil) applies the cluster-wide block-pause deadline.
func NewAgent(masterURL, nodeKey string, interval time.Duration, st *store.Store, reload func() error, stats func() store.NodeStats, setPause func(int64)) *Agent {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	// Resume shipping from where we left off; on first run skip the existing
	// backlog so we only forward entries logged from now on.
	last, _ := st.GetMetaInt("shipped_log_id")
	if last == 0 {
		if max, err := st.MaxQueryLogID(); err == nil {
			last = max
			_ = st.SetMetaInt("shipped_log_id", last)
		}
	}
	return &Agent{
		masterURL:   strings.TrimRight(masterURL, "/"),
		nodeKey:     nodeKey,
		interval:    interval,
		store:       st,
		reload:      reload,
		stats:       stats,
		setPause:    setPause,
		client:      &http.Client{Timeout: 15 * time.Second},
		lastShipped: last,
	}
}

// Run runs a sync+ship cycle immediately, then every interval until cancelled.
func (a *Agent) Run(ctx context.Context) {
	slog.Info("cluster agent started", "master", a.masterURL, "interval", a.interval)
	a.cycle(ctx)
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.cycle(ctx)
		}
	}
}

func (a *Agent) cycle(ctx context.Context) {
	a.syncOnce(ctx)
	a.shipLogs(ctx)
}

// shipLogs forwards new query-log entries to the master in batches, advancing a
// persisted cursor. Runs off the DNS path on the agent goroutine.
func (a *Agent) shipLogs(ctx context.Context) {
	entries, maxID, err := a.store.QueryLogSince(a.lastShipped, shipBatch)
	if err != nil {
		slog.Warn("ship logs: read failed", "err", err)
		return
	}
	if len(entries) == 0 {
		return
	}
	if err := a.postLogs(ctx, entries); err != nil {
		slog.Warn("ship logs: post failed", "err", err)
		return
	}
	a.lastShipped = maxID
	_ = a.store.SetMetaInt("shipped_log_id", maxID)
}

func (a *Agent) postLogs(ctx context.Context, entries []store.QueryLogEntry) error {
	body, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.masterURL+"/api/cluster/log", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.nodeKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("master returned status %d", resp.StatusCode)
	}
	return nil
}

func (a *Agent) syncOnce(ctx context.Context) {
	snap, err := a.fetch(ctx)
	if err != nil {
		slog.Warn("cluster sync failed", "err", err)
		return
	}
	// The block pause is applied every poll (it isn't part of the version hash).
	if a.setPause != nil {
		a.setPause(snap.PausedUntil)
	}
	cur, _ := a.store.ConfigVersion()
	if snap.Version == cur {
		return // rules already up to date
	}
	if err := a.store.ApplySnapshot(snap.Rules, snap.Rewrites); err != nil {
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
	ver, _ := a.store.ConfigVersion()
	req.Header.Set("X-MazeDNS-Node-Version", ver)
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
