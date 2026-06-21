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
	}
	reg.MustRegister(m.Queries, m.UpstreamDuration)
	return m
}

// Handler returns the Prometheus metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
