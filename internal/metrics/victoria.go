package metrics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// VMConfig is the live VictoriaMetrics export configuration. It is re-read every
// cycle (from the DB-backed settings), so changes made in the UI take effect
// without restarting the pusher.
type VMConfig struct {
	Enabled  bool
	URL      string        // base URL, e.g. http://victoriametrics:8428
	Interval time.Duration // push interval (default 15s)
	Job      string        // job label (default "mazedns")
	Instance string        // instance label ("" = the pusher's default, e.g. hostname)
	Username string        // optional HTTP basic auth
	Password string
}

// idleRecheck is how often the pusher re-reads settings while export is disabled,
// so enabling it from the UI takes effect within this window.
const idleRecheck = 30 * time.Second

// VMPusher periodically gathers this node's Prometheus metrics and pushes them to
// VictoriaMetrics' Prometheus text import endpoint (/api/v1/import/prometheus).
// Settings come from get(), re-read each cycle so UI edits apply live.
type VMPusher struct {
	get      func() VMConfig
	instance string // default instance label when the config leaves it blank
	gatherer prometheus.Gatherer
	client   *http.Client
}

// NewVMPusher builds a pusher. get supplies the live config; instance is the
// fallback instance label (e.g. the hostname).
func NewVMPusher(get func() VMConfig, instance string, g prometheus.Gatherer) *VMPusher {
	return &VMPusher{
		get:      get,
		instance: instance,
		gatherer: g,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Run pushes on the configured interval while export is enabled, re-reading the
// config each cycle, until ctx is cancelled.
func (p *VMPusher) Run(ctx context.Context) {
	for {
		cfg := p.get()
		wait := idleRecheck
		if cfg.Enabled && strings.TrimSpace(cfg.URL) != "" {
			if err := p.push(ctx, cfg); err != nil {
				slog.Warn("victoriametrics push failed", "err", err)
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

// push gathers the registry, encodes it as Prometheus text, and POSTs it to VM.
func (p *VMPusher) push(ctx context.Context, cfg VMConfig) error {
	mfs, err := p.gatherer.Gather()
	if err != nil {
		return fmt.Errorf("gather: %w", err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.importURL(cfg), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	if cfg.Username != "" || cfg.Password != "" {
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// importURL builds VM's Prometheus import endpoint with job/instance applied
// server-side via extra_label (so the metric bodies stay unmodified).
func (p *VMPusher) importURL(cfg VMConfig) string {
	job := cfg.Job
	if job == "" {
		job = "mazedns"
	}
	instance := cfg.Instance
	if instance == "" {
		instance = p.instance
	}
	q := url.Values{}
	q.Add("extra_label", "job="+job)
	if instance != "" {
		q.Add("extra_label", "instance="+instance)
	}
	return strings.TrimRight(cfg.URL, "/") + "/api/v1/import/prometheus?" + q.Encode()
}
