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
}

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
			if err := e.ship(ctx, cfg); err != nil {
				slog.Warn("victorialogs ship failed", "err", err)
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

// ship forwards new query-log entries since the cursor as newline-delimited JSON.
func (e *Exporter) ship(ctx context.Context, cfg Config) error {
	entries, maxID, err := e.store.QueryLogSince(e.cursor, shipBatch)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if len(entries) == 0 {
		return nil
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
			"_time":      time.UnixMilli(q.TS).UTC().Format(time.RFC3339Nano),
			"_msg":       q.Action + " " + strings.TrimSuffix(q.Name, ".") + " " + q.QType,
			"node":       node,
			"client":     q.Client,
			"name":       strings.TrimSuffix(q.Name, "."),
			"qtype":      q.QType,
			"action":     q.Action,
			"category":   q.Category,
			"rcode":      q.Rcode,
			"elapsed_ms": q.ElapsedMS,
		})
	}

	url := strings.TrimRight(cfg.URL, "/") +
		"/insert/jsonline?_time_field=_time&_msg_field=_msg&_stream_fields=node,action"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/stream+json")
	if cfg.Username != "" || cfg.Password != "" {
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	e.cursor = maxID
	_ = e.store.SetMetaInt(shippedCursorKey, maxID)
	return nil
}
