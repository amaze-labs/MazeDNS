package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/cluster"
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

// Two enrolled nodes in different sites receive different filtered snapshots,
// each self-consistent with its per-node version hash.
func TestClusterSnapshotPerNodeScoping(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)

	enroll := func(name string) string {
		rr := httptest.NewRecorder()
		s.clusterEnroll(rr, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll",
			strings.NewReader(`{"name":"`+name+`","token":"s3cr3t"}`)))
		if rr.Code != http.StatusCreated {
			t.Fatalf("enroll %s: %d %s", name, rr.Code, rr.Body.String())
		}
		var out struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Key
	}
	keyA, keyB := enroll("node-a"), enroll("node-b")
	if err := st.SetNodeSite("node-a", "office", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := st.AddRewriteScoped("nas.home", "A", "1.1.1.1", store.ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRewriteScoped("nas.home", "A", "2.2.2.2", store.ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddForwarder("corp.internal", []string{"10.0.0.2:53"}, store.ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}

	fetch := func(key string) cluster.Snapshot {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/cluster/snapshot", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		s.clusterSnapshot(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("snapshot: %d %s", rr.Code, rr.Body.String())
		}
		var snap cluster.Snapshot
		if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
			t.Fatal(err)
		}
		return snap
	}

	a, b := fetch(keyA), fetch(keyB)
	if len(a.Rewrites) != 1 || a.Rewrites[0].Value != "2.2.2.2" {
		t.Fatalf("node-a must get the site override: %+v", a.Rewrites)
	}
	if len(b.Rewrites) != 1 || b.Rewrites[0].Value != "1.1.1.1" {
		t.Fatalf("node-b must get the global value: %+v", b.Rewrites)
	}
	if len(a.Forwarders) != 1 || len(b.Forwarders) != 0 {
		t.Fatalf("forwarder scoping wrong: a=%+v b=%+v", a.Forwarders, b.Forwarders)
	}
	if a.Version == b.Version {
		t.Fatal("nodes with different content must advertise different versions")
	}
	if wantA, _ := st.ConfigVersionForNode("node-a", "office"); a.Version != wantA {
		t.Fatalf("snapshot version %q != per-node hash %q", a.Version, wantA)
	}
}

// The nodes listing carries each node's expected (per-node) config version so
// the UI can flag drift individually.
func TestClusterNodesExpectedVersion(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)
	rr := httptest.NewRecorder()
	s.clusterEnroll(rr, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll",
		strings.NewReader(`{"name":"node-a","token":"s3cr3t"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	if _, err := st.AddRewrite("nas.lan", "A", "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	nrr := httptest.NewRecorder()
	s.clusterNodes(nrr, httptest.NewRequest(http.MethodGet, "/api/cluster/nodes", nil))
	if nrr.Code != http.StatusOK {
		t.Fatal(nrr.Body.String())
	}
	var nodes []struct {
		Name            string `json:"name"`
		ExpectedVersion string `json:"expected_version"`
	}
	if err := json.Unmarshal(nrr.Body.Bytes(), &nodes); err != nil {
		t.Fatal(err)
	}
	want, _ := st.ConfigVersionForNode("node-a", "")
	if len(nodes) != 1 || nodes[0].ExpectedVersion != want || want == "" {
		t.Fatalf("expected_version missing/wrong: %+v (want %q)", nodes, want)
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
