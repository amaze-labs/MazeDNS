package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/categories"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

// The control plane resolves nothing, so it exposes no DNS counters (they
// would only ever read 0 next to the agents' real ones), but it does expose
// the Go runtime and process metrics.
func TestControlPlaneMetrics(t *testing.T) {
	m := NewControlPlane()
	m.RegisterLabeledGauge("agents", "Agents by state.", "state",
		func() map[string]float64 { return map[string]float64{"online": 2, "offline": 1} })
	m.RegisterCounter("querylog_ingested_total", "Ingested.", func() float64 { return 42 })
	body := scrape(t, m)
	for _, want := range []string{
		`mazedns_agents{state="online"} 2`,
		`mazedns_agents{state="offline"} 1`,
		`mazedns_querylog_ingested_total 42`,
		"go_goroutines ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "mazedns_queries_total") || strings.Contains(body, "mazedns_upstream_duration_seconds") {
		t.Error("the control plane exposes DNS metrics")
	}
}

func TestAgentMetrics(t *testing.T) {
	m := New()
	m.IncQuery("forward")
	var b categories.Builder
	b.Add("facebook.com", "social")
	b.Add("bet365.com", "gambling")
	m.RegisterCategoryDB(categories.NewLoadedHolder(b.Build()))
	m.RegisterCategoryDB(nil) // categories off: no-op
	body := scrape(t, m)
	for _, want := range []string{
		`mazedns_queries_total{action="forward"} 1`,
		`mazedns_queries_total{action="blocked"} 0`,
		"mazedns_category_db_domains 2",
		"mazedns_category_db_updated_timestamp_seconds ",
		"go_goroutines ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}
