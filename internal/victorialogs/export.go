// Package victorialogs ships the query log to a VictoriaLogs instance for
// long-term retention beyond the local SQLite window.
package victorialogs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// shippedCursorKey persists how far the exporter has shipped, so a restart resumes
// instead of re-shipping (and on first run we skip the backlog).
const shippedCursorKey = "vl_shipped_log_id"

const shipBatch = 5000 // max entries per POST

// maxBatchesPerCycle bounds one cycle's catch-up: while a backlog remains (a
// busy cluster, VictoriaLogs back after an outage, the export just turned on),
// batches go back to back instead of one per interval — at one 5,000-entry
// batch per 15s the export could never keep up with more than ~330 queries/s.
const maxBatchesPerCycle = 40

// Config is the live VictoriaLogs export configuration, re-read each cycle so UI
// edits apply without a restart.
type Config struct {
	Enabled  bool
	URL      string // base URL, e.g. http://victorialogs:9428
	Interval time.Duration
	Username string
	Password string
}

const idleRecheck = 30 * time.Second

// Exporter periodically ships new query-log entries to VictoriaLogs' jsonline
// ingestion endpoint. Run it on the master, whose query log is cluster-wide.
type Exporter struct {
	get    func() Config
	store  *store.Store
	client *http.Client
	cursor int64
	// reduce, when set, trims entries to what may leave MazeDNS (the privacy
	// level); it may drop them all.
	reduce func([]store.QueryLogEntry) []store.QueryLogEntry
}

// SetReduce installs the privacy filter applied to every batch before it ships.
func (e *Exporter) SetReduce(fn func([]store.QueryLogEntry) []store.QueryLogEntry) { e.reduce = fn }

// NewExporter builds an exporter. get supplies the live config.
func NewExporter(get func() Config, st *store.Store) *Exporter {
	// Resume from the persisted cursor; on first run skip the existing backlog so we
	// only forward entries logged from now on.
	cursor, _ := st.GetMetaInt(shippedCursorKey)
	if cursor == 0 {
		if max, err := st.MaxQueryLogID(); err == nil {
			cursor = max
			_ = st.SetMetaInt(shippedCursorKey, cursor)
		}
	}
	return &Exporter{
		get:    get,
		store:  st,
		client: &http.Client{Timeout: 20 * time.Second},
		cursor: cursor,
	}
}

// Run ships on the configured interval while enabled, re-reading config each cycle,
// until ctx is cancelled.
func (e *Exporter) Run(ctx context.Context) {
	for {
		cfg := e.get()
		wait := idleRecheck
		if cfg.Enabled && strings.TrimSpace(cfg.URL) != "" {
			for i := 0; i < maxBatchesPerCycle; i++ {
				n, err := e.ship(ctx, cfg)
				if err != nil {
					slog.Warn("victorialogs ship failed", "err", err)
					break
				}
				if n < shipBatch {
					break // caught up
				}
			}
			if wait = cfg.Interval; wait <= 0 {
				wait = 15 * time.Second
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// ship forwards one batch of new query-log entries since the cursor as
// newline-delimited JSON, and returns how many it sent.
func (e *Exporter) ship(ctx context.Context, cfg Config) (int, error) {
	entries, maxID, err := e.store.QueryLogSince(e.cursor, shipBatch)
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	if len(entries) == 0 {
		return 0, nil
	}
	read := len(entries)
	if e.reduce != nil {
		if entries = e.reduce(entries); len(entries) == 0 {
			e.cursor = maxID
			_ = e.store.SetMetaInt(shippedCursorKey, maxID)
			return read, nil
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, q := range entries {
		node := q.Node
		if node == "" {
			node = "master"
		}
		// VictoriaLogs ingests one JSON object per line; _time/_msg are mapped via
		// the query params below, the rest become searchable fields.
		_ = enc.Encode(map[string]any{
			"_time":    time.UnixMilli(q.TS).UTC().Format(time.RFC3339Nano),
			"_msg":     q.Action + " " + strings.TrimSuffix(q.Name, ".") + " " + q.QType,
			"node":     node,
			"client":   q.Client,
			"name":     strings.TrimSuffix(q.Name, "."),
			"qtype":    q.QType,
			"action":   q.Action,
			"category": q.Category, // the block reason
			// What the domain is (social, shopping, …), labelled on arrival.
			"content_category": q.ContentCategory,
			"rcode":            q.Rcode,
			"elapsed_ms":       q.ElapsedMS,
			// Which upstream answered a forwarded query, and the conditional
			// forwarder that routed it ('' = the default upstreams).
			"upstream":  q.Upstream,
			"forwarder": q.Forwarder,
		})
	}

	url := strings.TrimRight(cfg.URL, "/") +
		"/insert/jsonline?_time_field=_time&_msg_field=_msg&_stream_fields=node,action"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/stream+json")
	if cfg.Username != "" || cfg.Password != "" {
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return 0, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	e.cursor = maxID
	_ = e.store.SetMetaInt(shippedCursorKey, maxID)
	return read, nil
}
