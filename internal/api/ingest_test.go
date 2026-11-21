package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// With an ingest buffer set, shipped query logs are acknowledged at once and
// written with the buffer's next flush, together with other resolvers'.
func TestClusterLogUsesIngestBuffer(t *testing.T) {
	s, st := newEnrollServer(t, "", false)
	if _, err := st.CreateNode("agent-a", hashKey("node-key"), "node"); err != nil {
		t.Fatal(err)
	}
	buf := store.NewIngestBuffer(st, time.Hour)
	t.Cleanup(buf.Close)
	s.SetIngestBuffer(buf)
	r := httptest.NewRequest(http.MethodPost, "/api/cluster/log",
		strings.NewReader(`[{"ts":1,"name":"a.example.","action":"forward"},{"ts":2,"name":"b.example.","action":"forward"}]`))
	r.Header.Set("Authorization", "Bearer node-key")
	rr := httptest.NewRecorder()
	s.clusterLog(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rr.Code, rr.Body.String())
	}
	if n, _ := st.CountQueryLog(); n != 0 || buf.Pending() != 2 {
		t.Fatalf("before flush: %d rows, %d pending; want 0 and 2", n, buf.Pending())
	}
	if err := buf.Flush(); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountQueryLog(); n != 2 {
		t.Fatalf("after flush: %d rows, want 2", n)
	}
}
