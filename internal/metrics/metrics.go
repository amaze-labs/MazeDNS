// Package metrics exposes Prometheus metrics for MazeDNS.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/IPMaze/MazeDNS/internal/categories"
)

// Metrics holds the MazeDNS Prometheus collectors.
type Metrics struct {
	reg     *prometheus.Registry
	Queries *prometheus.CounterVec
	// UpstreamDuration is labelled by the upstream that answered (as configured);
	// see ObserveUpstream.
	UpstreamDuration *prometheus.HistogramVec
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

// newRegistry is a registry with the standard Go runtime and process metrics
// (go_memstats_*, go_goroutines, process_resident_memory_bytes, …), so a node's
// memory — e.g. an agent holding a category database on a Raspberry Pi — and
// CPU can be watched alongside its own metrics.
func newRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return reg
}

// NewControlPlane returns the control plane's metrics: the runtime metrics,
// plus whatever it registers (agents, ingest, classifier, …). It has no DNS
// metrics — it answers no queries, and always-zero query counters there only
// misled (and, pushed under an agent's labels, overwrote the agent's).
func NewControlPlane() *Metrics { return &Metrics{reg: newRegistry()} }

// New creates a DNS node's metrics: the runtime metrics and the DNS collectors.
func New() *Metrics {
	reg := newRegistry()
	m := &Metrics{
		reg: reg,
		Queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mazedns",
			Name:      "queries_total",
			Help:      "Total DNS queries by action (blocked, cache, forward, rewrite, error).",
		}, []string{"action"}),
		UpstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "mazedns",
			Name:      "upstream_duration_seconds",
			Help:      "Upstream query round-trip time, by the upstream that answered.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"upstream"}),
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

// ObserveUpstream records the round-trip time of a query upstream answered.
// Upstreams are the configured few, so the label stays low-cardinality.
func (m *Metrics) ObserveUpstream(upstream string, rtt time.Duration) {
	m.UpstreamDuration.WithLabelValues(upstream).Observe(rtt.Seconds())
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

// RegisterGauge registers a gauge mazedns_<name> reporting fn on each scrape.
func (m *Metrics) RegisterGauge(name, help string, fn func() float64) {
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: "mazedns", Name: name, Help: help}, fn))
}

// RegisterCounter registers a counter mazedns_<name> reporting fn (which must
// only grow) on each scrape.
func (m *Metrics) RegisterCounter(name, help string, fn func() float64) {
	m.reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{Namespace: "mazedns", Name: name, Help: help}, fn))
}

// RegisterLabeledGauge registers a gauge mazedns_<name>{<label>=…} whose
// series come from fn on each scrape (one per map key).
func (m *Metrics) RegisterLabeledGauge(name, help, label string, fn func() map[string]float64) {
	m.reg.MustRegister(&labeledGauge{
		desc: prometheus.NewDesc("mazedns_"+name, help, []string{label}, nil),
		fn:   fn,
	})
}

type labeledGauge struct {
	desc *prometheus.Desc
	fn   func() map[string]float64
}

func (g *labeledGauge) Describe(ch chan<- *prometheus.Desc) { ch <- g.desc }

func (g *labeledGauge) Collect(ch chan<- prometheus.Metric) {
	for k, v := range g.fn() {
		ch <- prometheus.MustNewConstMetric(g.desc, prometheus.GaugeValue, v, k)
	}
}

// RegisterTimestamp registers a gauge mazedns_<name> reporting fn's time as unix
// seconds (0 = never). fn is polled on each scrape.
func (m *Metrics) RegisterTimestamp(name, help string, fn func() time.Time) {
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "mazedns",
		Name:      name,
		Help:      help,
	}, func() float64 {
		t := fn()
		if t.IsZero() {
			return 0
		}
		return float64(t.UnixMilli()) / 1000
	}))
}

// Handler returns the Prometheus metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Gatherer exposes the underlying registry so collectors can be gathered for
// pushing to an external sink (e.g. the VictoriaMetrics exporter).
func (m *Metrics) Gatherer() prometheus.Gatherer { return m.reg }

// RegisterCategoryDB exposes the category database's size and freshness — all
// of it on the control plane, the blocked categories on an agent (nothing when
// categories are off).
func (m *Metrics) RegisterCategoryDB(h *categories.Holder) {
	if h == nil {
		return
	}
	m.RegisterGauge("category_db_domains", "Domains in the loaded category database.",
		func() float64 { return float64(h.Status().Domains) })
	m.RegisterTimestamp("category_db_updated_timestamp_seconds", "When the category database last loaded.",
		func() time.Time {
			if u := h.Status().UpdatedAt; u > 0 {
				return time.Unix(u, 0)
			}
			return time.Time{}
		})
}
