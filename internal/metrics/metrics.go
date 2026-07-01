// Package metrics exposes Prometheus metrics for MazeDNS.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the MazeDNS Prometheus collectors.
type Metrics struct {
	reg              *prometheus.Registry
	Queries          *prometheus.CounterVec
	UpstreamDuration prometheus.Histogram
	// UpstreamTCPFallback counts UDP responses that were truncated and retried
	// over TCP — a useful signal of DNSSEC/large-response cost.
	UpstreamTCPFallback prometheus.Counter
	// queryByAction holds the Queries child counters pre-resolved by action, so the
	// per-query record path avoids re-hashing the label set through WithLabelValues
	// (which takes an internal lock) on every single query. Written only in New;
	// read-only afterwards, so concurrent lookups need no lock.
	queryByAction map[string]prometheus.Counter
}

// queryActions is the fixed set of actions the resolver reports, pre-resolved in
// New so the hot path is a plain map read.
var queryActions = []string{
	"authoritative", "rewrite", "blocked", "cache", "forward", "error", "refused",
}

// New creates and registers the collectors.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		Queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mazedns",
			Name:      "queries_total",
			Help:      "Total DNS queries by action (blocked, cache, forward, rewrite, error).",
		}, []string{"action"}),
		UpstreamDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "mazedns",
			Name:      "upstream_duration_seconds",
			Help:      "Upstream query round-trip time.",
			Buckets:   prometheus.DefBuckets,
		}),
		UpstreamTCPFallback: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "mazedns",
			Name:      "upstream_tcp_fallback_total",
			Help:      "UDP responses that were truncated and retried over TCP.",
		}),
	}
	reg.MustRegister(m.Queries, m.UpstreamDuration, m.UpstreamTCPFallback)
	m.queryByAction = make(map[string]prometheus.Counter, len(queryActions))
	for _, a := range queryActions {
		m.queryByAction[a] = m.Queries.WithLabelValues(a)
	}
	return m
}

// IncQuery increments the per-action query counter. For the fixed set of actions
// the resolver emits it is a plain map lookup (resolved once in New); any other
// action falls back to the labelled vector.
func (m *Metrics) IncQuery(action string) {
	if c, ok := m.queryByAction[action]; ok {
		c.Inc()
		return
	}
	m.Queries.WithLabelValues(action).Inc()
}

// RegisterQueryLogDropped registers a counter that reports how many query-log
// entries the async writer dropped (buffer full). fn is polled on each scrape.
func (m *Metrics) RegisterQueryLogDropped(fn func() float64) {
	m.reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "mazedns",
		Name:      "querylog_dropped_total",
		Help:      "Query-log entries dropped because the async writer buffer was full.",
	}, fn))
}

// Handler returns the Prometheus metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Gatherer exposes the underlying registry so collectors can be gathered for
// pushing to an external sink (e.g. the VictoriaMetrics exporter).
func (m *Metrics) Gatherer() prometheus.Gatherer { return m.reg }
