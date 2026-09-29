package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// Live query streaming (agent -> control plane). The control plane never
// connects to agents, so the agent drives both directions with plain requests
// that survive any reverse proxy:
//
//   - GET /api/cluster/live?have=<version> is a long poll: it returns the
//     filters of the live viewers watching this node as soon as they differ from
//     the version the agent holds (or after a short wait, unchanged).
//   - POST /api/cluster/live carries the matching queries, batched every
//     livePushInterval, only while somebody is watching.
//
// Live is best effort: entries are dropped whenever a buffer is full or a push
// fails. The cursor-based query-log shipping stays the only path into the
// control plane's query_log, so nothing is stored twice or lost.
const (
	livePushInterval = 500 * time.Millisecond
	liveBatch        = 2000 // max entries per push
	liveBuffer       = 4096 // tapped entries waiting for the next push
	liveRetry        = 5 * time.Second
	liveUnsupported  = 5 * time.Minute // control plane predates live streaming
)

// LiveFilter is one live viewer's selection, evaluated on the agent (to send
// only what somebody watches) and again on the control plane (per viewer).
// Empty fields match everything; Domain is lower-case.
type LiveFilter struct {
	Client   string `json:"client,omitempty"` // substring of the client IP
	Domain   string `json:"domain,omitempty"` // substring of the query name
	QType    string `json:"qtype,omitempty"`
	Action   string `json:"action,omitempty"`
	Category string `json:"category,omitempty"`
	Rcode    string `json:"rcode,omitempty"`
}

// Match reports whether e passes the filter.
func (f LiveFilter) Match(e store.QueryLogEntry) bool {
	return (f.Client == "" || strings.Contains(e.Client, f.Client)) &&
		(f.Domain == "" || strings.Contains(strings.ToLower(e.Name), f.Domain)) &&
		(f.QType == "" || e.QType == f.QType) &&
		(f.Action == "" || e.Action == f.Action) &&
		(f.Category == "" || e.Category == f.Category) &&
		(f.Rcode == "" || e.Rcode == f.Rcode)
}

// LiveState is the long-poll answer: the filters of the viewers watching the
// node (empty = nobody) and their version.
type LiveState struct {
	Version string       `json:"version"`
	Filters []LiveFilter `json:"filters"`
}

// NewLiveState dedupes and orders filters and versions the result, so the same
// set of viewers always yields the same version.
func NewLiveState(filters []LiveFilter) LiveState {
	seen := map[LiveFilter]bool{}
	out := []LiveFilter{}
	for _, f := range filters {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]) < fmt.Sprint(out[j]) })
	b, _ := json.Marshal(out)
	sum := sha256.Sum256(b)
	return LiveState{Version: hex.EncodeToString(sum[:6]), Filters: out}
}

// LiveTap receives every query the resolver logs and keeps, without blocking,
// those that some live viewer wants. While nobody watches, Write is a single
// atomic load.
type LiveTap struct {
	filters atomic.Pointer[[]LiveFilter]
	ch      chan store.QueryLogEntry
}

// NewLiveTap returns a tap nobody is watching yet.
func NewLiveTap() *LiveTap { return &LiveTap{ch: make(chan store.QueryLogEntry, liveBuffer)} }

// Write offers one logged query to the live stream. Safe on the DNS path.
func (t *LiveTap) Write(e store.QueryLogEntry) {
	fs := t.filters.Load()
	if fs == nil {
		return
	}
	for _, f := range *fs {
		if f.Match(e) {
			select {
			case t.ch <- e:
			default: // the stream is slow or down: drop
			}
			return
		}
	}
}

func (t *LiveTap) setFilters(fs []LiveFilter) {
	if len(fs) == 0 {
		t.filters.Store(nil)
		return
	}
	t.filters.Store(&fs)
}

// SetLiveTap enables live query streaming from tap (nil = disabled).
func (a *Agent) SetLiveTap(tap *LiveTap) { a.live = tap }

var errLiveUnsupported = errors.New("control plane does not support live streaming")

// runLive keeps the viewer filters current and pushes tapped queries until ctx
// is cancelled.
func (a *Agent) runLive(ctx context.Context) {
	go a.pushLive(ctx)
	have := ""
	for ctx.Err() == nil {
		st, err := a.fetchLive(ctx, have)
		if err != nil {
			// Stop tapping: nothing could be delivered anyway.
			a.live.setFilters(nil)
			have = ""
			wait := liveRetry
			if errors.Is(err, errLiveUnsupported) {
				wait = liveUnsupported
			} else if ctx.Err() == nil {
				slog.Debug("cluster live: watch failed", "err", err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
			continue
		}
		if st.Version != have {
			slog.Debug("cluster live: viewers changed", "filters", len(st.Filters))
		}
		have = st.Version
		a.live.setFilters(st.Filters)
	}
}

func (a *Agent) fetchLive(ctx context.Context, have string) (LiveState, error) {
	var st LiveState
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.masterURL+"/api/cluster/live?have="+url.QueryEscape(have), nil)
	if err != nil {
		return st, err
	}
	req.Header.Set("Authorization", "Bearer "+a.key())
	resp, err := a.client.Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return st, json.NewDecoder(resp.Body).Decode(&st)
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return st, errLiveUnsupported
	default:
		return st, statusError(resp)
	}
}

// pushLive sends the tapped queries to the control plane in small batches.
func (a *Agent) pushLive(ctx context.Context) {
	t := time.NewTicker(livePushInterval)
	defer t.Stop()
	batch := make([]store.QueryLogEntry, 0, liveBatch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for len(batch) < liveBatch {
			select {
			case e := <-a.live.ch:
				batch = append(batch, e)
				continue
			default:
			}
			break
		}
		if len(batch) == 0 {
			continue
		}
		if err := a.postJSON(ctx, "/api/cluster/live", batch); err != nil && ctx.Err() == nil {
			slog.Debug("cluster live: push failed", "err", err, "dropped", len(batch))
		}
		batch = batch[:0]
	}
}
