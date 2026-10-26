package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// Insights break forwarded queries down by the upstream that answered them,
// honouring the node filter, and the query log filters by upstream.
func TestInsightsAndQueryLogByUpstream(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}

	now := time.Now().UnixMilli()
	fwd := func(up, fw string) store.QueryLogEntry {
		return store.QueryLogEntry{TS: now, Client: "c", Name: "x.", QType: "A", Action: "forward", Rcode: "NOERROR",
			Upstream: up, Forwarder: fw, ElapsedMS: 10}
	}
	if err := st.InsertNodeQueryLog("dns1", []store.QueryLogEntry{fwd("1.1.1.1", ""), fwd("1.1.1.1", ""), fwd("10.0.0.53", "corp.internal")}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertNodeQueryLog("dns2", []store.QueryLogEntry{fwd("9.9.9.9", "")}); err != nil {
		t.Fatal(err)
	}
	for more := true; more; {
		if more, err = st.RollupAdvance(0); err != nil {
			t.Fatal(err)
		}
	}

	var ins struct {
		ByUpstream []store.UpstreamStat `json:"by_upstream"`
	}
	rr := call(t, s.getInsights, http.MethodGet, "/api/stats/insights?hours=1&nodes=dns1", "")
	if err := json.Unmarshal(rr.Body.Bytes(), &ins); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("insights: %d %s", rr.Code, rr.Body)
	}
	if len(ins.ByUpstream) != 2 || ins.ByUpstream[0] != (store.UpstreamStat{Upstream: "1.1.1.1", Count: 2, AvgLatencyMS: 10}) ||
		ins.ByUpstream[1] != (store.UpstreamStat{Forwarder: "corp.internal", Upstream: "10.0.0.53", Count: 1, AvgLatencyMS: 10}) {
		t.Errorf("by_upstream = %+v", ins.ByUpstream)
	}

	var log struct {
		Entries []store.QueryLogEntry `json:"entries"`
		Total   int64                 `json:"total"`
	}
	rr = call(t, s.getQueryLog, http.MethodGet, "/api/querylog?upstream=10.0.0.53&forwarder=corp.internal", "")
	if err := json.Unmarshal(rr.Body.Bytes(), &log); err != nil || log.Total != 1 || log.Entries[0].Upstream != "10.0.0.53" {
		t.Errorf("querylog by upstream: %d %s", rr.Code, rr.Body)
	}
}
