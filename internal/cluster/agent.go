package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	masterURL      string
	nodeKey        string
	advertiseAddr  string // site-reachable address reported to the master ('' = use RemoteAddr)
	interval       time.Duration
	store          *store.Store
	reload         func() error
	stats          func() store.NodeStats
	setPause       func(int64)
	setMaintenance func(bool)
	client         *http.Client
	lastShipped    int64
	reenroll       func(ctx context.Context) (string, error) // re-obtain a node key on revocation (nil = disabled)
}

// SetReenroll installs a callback the agent uses to recover when the control
// plane rejects its key (HTTP 401): it re-enrolls with the shared join token,
// receives a fresh key, persists it, and returns it. Enables zero-touch key
// rotation and self-healing after a control-plane DB reset.
func (a *Agent) SetReenroll(fn func(ctx context.Context) (string, error)) { a.reenroll = fn }

// NewAgent builds a replication agent. nodeKey is the per-node API key issued by
// the master; stats (may be nil) reports this node's query counters each poll;
// setPause (may be nil) applies the cluster-wide block-pause deadline;
// setMaintenance (may be nil) applies this node's drain flag.
func NewAgent(masterURL, masterIP, nodeKey, advertiseAddr string, interval time.Duration, st *store.Store, reload func() error, stats func() store.NodeStats, setPause func(int64), setMaintenance func(bool)) *Agent {
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
		masterURL:      strings.TrimRight(masterURL, "/"),
		nodeKey:        nodeKey,
		advertiseAddr:  strings.TrimSpace(advertiseAddr),
		interval:       interval,
		store:          st,
		reload:         reload,
		stats:          stats,
		setPause:       setPause,
		setMaintenance: setMaintenance,
		client:         &http.Client{Timeout: 15 * time.Second, Transport: masterTransport(masterIP)},
		lastShipped:    last,
	}
}

// masterTransport returns an HTTP transport. When masterIP is set, every
// connection to the master is dialed at that fixed IP regardless of DNS, while
// TLS (SNI/cert verification) still uses the hostname from the URL — so a worker
// can reach the master even if it can't resolve the master's name.
func masterTransport(masterIP string) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if masterIP == "" {
		return base
	}
	slog.Info("cluster: pinning master IP (DNS bypassed)", "ip", masterIP)
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if _, port, err := net.SplitHostPort(addr); err == nil {
			addr = net.JoinHostPort(masterIP, port)
		}
		return dialer.DialContext(ctx, network, addr)
	}
	return base
}

// Run runs a sync+ship cycle immediately, then every interval until cancelled.
func (a *Agent) Run(ctx context.Context) {
	slog.Info("cluster agent started", "master", a.masterURL, "interval", a.interval)
	// Behind a TLS reverse proxy the master URL must be the proxy (https, no
	// direct API port). A plain-http master URL either won't reach a proxy-only
	// deployment or ships the node key in cleartext (see FIND-02).
	if !strings.HasPrefix(a.masterURL, "https://") {
		slog.Warn("cluster master URL is not https; behind a TLS reverse proxy use the proxy URL (e.g. https://host, no :8080)", "master", a.masterURL)
	}
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
		return statusError(resp)
	}
	return nil
}

// statusError turns a non-200 response into an error that includes the master's
// response body (bounded). The body is what distinguishes the failure modes —
// e.g. "missing node key" (the Authorization header was stripped, typically by
// a reverse proxy) vs "invalid node key" (the key isn't enrolled on the master)
// — and a proxy login page or 404 points at proxy routing/auth rather than the
// node key at all.
func statusError(resp *http.Response) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if msg := strings.TrimSpace(string(snippet)); msg != "" {
		return fmt.Errorf("master returned status %d: %s", resp.StatusCode, msg)
	}
	return fmt.Errorf("master returned status %d", resp.StatusCode)
}

func (a *Agent) syncOnce(ctx context.Context) {
	snap, err := a.fetch(ctx)
	if err != nil {
		slog.Warn("cluster sync failed", "err", err)
		return
	}
	// The block pause and this node's maintenance flag are applied every poll
	// (they aren't part of the version hash).
	if a.setPause != nil {
		a.setPause(snap.PausedUntil)
	}
	if a.setMaintenance != nil {
		a.setMaintenance(snap.Maintenance)
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
	if a.advertiseAddr != "" {
		req.Header.Set("X-MazeDNS-Advertise-Addr", a.advertiseAddr)
	}
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
	if resp.StatusCode == http.StatusUnauthorized && a.reenroll != nil {
		// Our key was rejected (revoked, or the control plane lost its DB). Re-join
		// with the shared token to get a fresh one; the next cycle uses it.
		if newKey, rerr := a.reenroll(ctx); rerr != nil {
			slog.Warn("cluster re-enroll failed", "err", rerr)
		} else {
			a.nodeKey = newKey
			slog.Info("cluster re-enrolled after key rejection")
		}
		return nil, statusError(resp)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp)
	}
	var snap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return nil, err
	}
	return &snap, nil
}
