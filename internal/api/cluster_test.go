package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func newEnrollServer(t *testing.T, joinToken string, requireApproval bool) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}
	s.SetClusterEnrollment(joinToken, requireApproval)
	return s, st
}

func TestClusterEnroll(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)

	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.clusterEnroll(rr, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll", strings.NewReader(body)))
		return rr
	}

	// Wrong token is rejected.
	if rr := post(`{"name":"agent-a","token":"nope"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rr.Code)
	}
	// Missing name is rejected.
	if rr := post(`{"token":"s3cr3t"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("missing name: status = %d, want 400", rr.Code)
	}
	// Valid enrollment issues a key and admits the node (auto-approve).
	rr := post(`{"name":"agent-a","token":"s3cr3t"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("valid enroll: status = %d, want 201 (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"key"`) {
		t.Fatalf("enroll response missing key: %s", rr.Body.String())
	}
	// The issued key authenticates and the node is approved.
	nodes, _ := st.ListNodes()
	if len(nodes) != 1 || nodes[0].Name != "agent-a" || !nodes[0].Approved {
		t.Fatalf("node not enrolled+approved: %+v", nodes)
	}
}

func TestClusterEnrollRequireApproval(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", true)
	rr := httptest.NewRecorder()
	s.clusterEnroll(rr, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll", strings.NewReader(`{"name":"agent-b","token":"s3cr3t"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rr.Code)
	}
	nodes, _ := st.ListNodes()
	if len(nodes) != 1 || nodes[0].Approved {
		t.Fatalf("require_approval: node should be pending: %+v", nodes)
	}
}

func TestClusterEnrollDisabled(t *testing.T) {
	s, _ := newEnrollServer(t, "", false) // no join token configured
	rr := httptest.NewRecorder()
	s.clusterEnroll(rr, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll", strings.NewReader(`{"name":"x","token":"anything"}`)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("self-enroll disabled: status = %d, want 403", rr.Code)
	}
}

// A pending (unapproved) node cannot pull the config snapshot until an admin
// approves it.
func TestClusterSnapshotGatedOnApproval(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", true)
	enroll := httptest.NewRecorder()
	s.clusterEnroll(enroll, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll", strings.NewReader(`{"name":"agent-c","token":"s3cr3t"}`)))
	// Extract the issued key from the JSON body.
	body := enroll.Body.String()
	key := jsonField(body, "key")
	if key == "" {
		t.Fatalf("no key issued: %s", body)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rr := httptest.NewRecorder()
	s.clusterSnapshot(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("pending node snapshot: status = %d, want 403", rr.Code)
	}

	// Approve, then the snapshot is served.
	if err := st.SetNodeApproved("agent-c", true); err != nil {
		t.Fatal(err)
	}
	rr2 := httptest.NewRecorder()
	s.clusterSnapshot(rr2, req)
	if rr2.Code != http.StatusOK {
		t.Fatalf("approved node snapshot: status = %d, want 200 (%s)", rr2.Code, rr2.Body.String())
	}
}

// jsonField is a tiny extractor for `"field":"value"` in a flat JSON object —
// enough for these tests without pulling in a decoder.
func jsonField(body, field string) string {
	marker := `"` + field + `":"`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}
