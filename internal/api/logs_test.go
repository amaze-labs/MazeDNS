package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/logbuf"
)

// enrollLogNode enrolls one agent and returns its id and node key.
func enrollLogNode(t *testing.T, s *Server) (id, key string) {
	t.Helper()
	rr := enroll(s, `{"name":"log-node","token":"s3cr3t"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("enroll: %d (%s)", rr.Code, rr.Body.String())
	}
	id, key = jsonField(rr.Body.String(), "id"), jsonField(rr.Body.String(), "key")
	if id == "" || key == "" {
		t.Fatalf("enroll response missing id/key: %s", rr.Body.String())
	}
	return id, key
}

func postProcLog(s *Server, key, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/proclog", strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	s.clusterProcLog(rr, req)
	return rr
}

func getLogEntries(t *testing.T, s *Server, query string) []logbuf.Entry {
	t.Helper()
	rr := httptest.NewRecorder()
	s.getLogs(rr, httptest.NewRequest(http.MethodGet, "/api/logs"+query, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/logs%s: %d (%s)", query, rr.Code, rr.Body.String())
	}
	var out struct {
		Entries []logbuf.Entry `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.Entries
}

func TestClusterProcLogIngestAndServe(t *testing.T) {
	s, _ := newEnrollServer(t, "s3cr3t", false)
	s.procLogs = newProcLogStore()
	id, key := enrollLogNode(t, s)

	// Bad/absent keys are rejected.
	if rr := postProcLog(s, "", `{}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no key: %d, want 401", rr.Code)
	}
	if rr := postProcLog(s, "wrong", `{}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d, want 401", rr.Code)
	}

	batch := `{"boot_id":"boot1","entries":[
		{"seq":1,"ts":1000,"level":"info","msg":"started"},
		{"seq":2,"ts":2000,"level":"warn","msg":"forward failed err=timeout"}]}`
	if rr := postProcLog(s, key, batch); rr.Code != http.StatusOK {
		t.Fatalf("ingest: %d (%s)", rr.Code, rr.Body.String())
	}
	// Re-shipping the same batch (lost response) must not duplicate.
	if rr := postProcLog(s, key, batch); rr.Code != http.StatusOK {
		t.Fatalf("re-ingest: %d", rr.Code)
	}
	got := getLogEntries(t, s, "?source="+id)
	if len(got) != 2 {
		t.Fatalf("entries = %d, want 2 (dedupe on re-ship)", len(got))
	}
	// Newest first.
	if got[0].Msg != "forward failed err=timeout" || got[1].Msg != "started" {
		t.Fatalf("order wrong: %+v", got)
	}

	// A new boot restarts seqs: same seq numbers are fresh lines now.
	reboot := `{"boot_id":"boot2","entries":[{"seq":1,"ts":3000,"level":"info","msg":"restarted"}]}`
	if rr := postProcLog(s, key, reboot); rr.Code != http.StatusOK {
		t.Fatalf("reboot ingest: %d", rr.Code)
	}
	if got := getLogEntries(t, s, "?source="+id); len(got) != 3 || got[0].Msg != "restarted" {
		t.Fatalf("after reboot: %+v", got)
	}

	// Level and search filters.
	if got := getLogEntries(t, s, "?source="+id+"&level=warn"); len(got) != 1 || got[0].Level != "warn" {
		t.Fatalf("level filter: %+v", got)
	}
	if got := getLogEntries(t, s, "?source="+id+"&search=TIMEOUT"); len(got) != 1 {
		t.Fatalf("search filter (case-insensitive): %+v", got)
	}
}

func TestGetLogsControlPlaneSource(t *testing.T) {
	s, _ := newEnrollServer(t, "", false)
	ring := logbuf.New(10)
	s.SetProcessLogs(ring)
	base := time.UnixMilli(1000)
	ring.Append(base, "info", "one")
	ring.Append(base, "error", "two")
	ring.Append(base, "info", "three")

	// Default source is the control plane, newest first.
	got := getLogEntries(t, s, "")
	if len(got) != 3 || got[0].Msg != "three" || got[2].Msg != "one" {
		t.Fatalf("cp logs: %+v", got)
	}
	// The limit keeps the newest lines.
	if got := getLogEntries(t, s, "?limit=2"); len(got) != 2 || got[1].Msg != "two" {
		t.Fatalf("limit: %+v", got)
	}
	// An unknown source serves no entries rather than erroring.
	if got := getLogEntries(t, s, "?source=nope"); len(got) != 0 {
		t.Fatalf("unknown source: %+v", got)
	}
}

// TestDeleteRevokedForever: ?forever=true removes the tombstone permanently and
// audits the action as a purge, distinct from an un-revoke.
func TestDeleteRevokedForever(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)
	id, _ := enrollLogNode(t, s)
	if err := st.DeleteNode(id, true, "admin"); err != nil {
		t.Fatal(err)
	}
	if revoked, _ := st.ListRevokedNodes(); len(revoked) != 1 {
		t.Fatalf("expected 1 tombstone, got %d", len(revoked))
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/cluster/revoked/"+id+"?forever=true", nil)
	req.SetPathValue("id", id)
	s.unrevokeNode(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete forever: %d (%s)", rr.Code, rr.Body.String())
	}
	if revoked, _ := st.ListRevokedNodes(); len(revoked) != 0 {
		t.Fatalf("tombstone should be gone, got %+v", revoked)
	}
	entries, _ := st.ListAudit()
	found := false
	for _, e := range entries {
		if e.Action == "cluster.node.purge" {
			found = true
		}
		if e.Action == "cluster.node.unrevoke" {
			t.Fatalf("purge must not be audited as un-revoke: %+v", e)
		}
	}
	if !found {
		t.Fatal("missing cluster.node.purge audit entry")
	}

	// Purging a non-existent tombstone is a 404.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/cluster/revoked/"+id+"?forever=true", nil)
	req.SetPathValue("id", id)
	s.unrevokeNode(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("second purge: %d, want 404", rr.Code)
	}
}
