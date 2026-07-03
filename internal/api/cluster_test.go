package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// newEnrollServer builds a control-plane API server with periodic key rotation
// disabled, and (when secret != "") an unlimited, never-expiring enrollment key
// whose value is secret — so existing tests can enroll by presenting secret as the
// token.
func newEnrollServer(t *testing.T, secret string, requireApproval bool) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}
	s.SetClusterEnrollment(requireApproval, 0, 0) // rotation off for enrollment tests
	if secret != "" {
		if err := st.CreateEnrollKey(uuid.NewString(), "test", hashKey(secret), keyPrefix(secret), "test", 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	return s, st
}

// mustNode fetches a node by name, failing the test if it is missing.
func mustNode(t *testing.T, st *store.Store, name string) *store.Node {
	t.Helper()
	n, err := st.NodeByName(name)
	if err != nil || n == nil {
		t.Fatalf("node %q not found: %v", name, err)
	}
	return n
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

func TestClusterEnrollNoValidKey(t *testing.T) {
	s, _ := newEnrollServer(t, "", false) // no enrollment keys exist
	rr := httptest.NewRecorder()
	s.clusterEnroll(rr, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll", strings.NewReader(`{"name":"x","token":"anything"}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no valid enrollment key: status = %d, want 401", rr.Code)
	}
}

// An expired enrollment key cannot enroll a new node.
func TestEnrollKeyExpiry(t *testing.T) {
	s, st := newEnrollServer(t, "", false)
	// Key that expired an hour ago.
	if err := st.CreateEnrollKey(uuid.NewString(), "old", hashKey("expired-secret"), keyPrefix("expired-secret"), "test",
		time.Now().Add(-time.Hour).Unix(), 0); err != nil {
		t.Fatal(err)
	}
	rr := enroll(s, `{"name":"n","token":"expired-secret"}`)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expired key enroll: status = %d, want 401 (%s)", rr.Code, rr.Body.String())
	}
	if nodes, _ := st.ListNodes(); len(nodes) != 0 {
		t.Fatalf("expired key must not create a node: %d nodes", len(nodes))
	}
}

// A revoked enrollment key cannot enroll a new node.
func TestEnrollKeyRevocation(t *testing.T) {
	s, st := newEnrollServer(t, "", false)
	id := uuid.NewString()
	if err := st.CreateEnrollKey(id, "k", hashKey("live-secret"), keyPrefix("live-secret"), "test", 0, 0); err != nil {
		t.Fatal(err)
	}
	// Works before revocation.
	if rr := enroll(s, `{"name":"n1","token":"live-secret"}`); rr.Code != http.StatusCreated {
		t.Fatalf("pre-revoke enroll: status = %d, want 201", rr.Code)
	}
	if err := st.RevokeEnrollKey(id); err != nil {
		t.Fatal(err)
	}
	if rr := enroll(s, `{"name":"n2","token":"live-secret"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke enroll: status = %d, want 401", rr.Code)
	}
	if nodes, _ := st.ListNodes(); len(nodes) != 1 {
		t.Fatalf("revoked key must not create a second node: %d nodes", len(nodes))
	}
}

// max_uses is enforced atomically: with many concurrent enrollments, no more than
// max_uses succeed and use_count never exceeds it.
func TestEnrollKeyMaxUsesRace(t *testing.T) {
	s, st := newEnrollServer(t, "", false)
	const maxUses = 5
	const attempts = 40
	if err := st.CreateEnrollKey(uuid.NewString(), "limited", hashKey("cap-secret"), keyPrefix("cap-secret"), "test", 0, maxUses); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct names so this exercises max_uses, not name-uniqueness races.
			rr := enroll(s, fmt.Sprintf(`{"name":"race-%d","token":"cap-secret"}`, i))
			if rr.Code == http.StatusCreated {
				mu.Lock()
				created++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if created != maxUses {
		t.Fatalf("concurrent enrolls: %d succeeded, want exactly %d", created, maxUses)
	}
	nodes, _ := st.ListNodes()
	if len(nodes) != maxUses {
		t.Fatalf("max_uses breached: %d nodes created, want %d", len(nodes), maxUses)
	}
	keys, _ := st.ListEnrollKeys()
	if len(keys) != 1 || keys[0].UseCount != maxUses || keys[0].Status != "exhausted" {
		t.Fatalf("use_count/status wrong after race: %+v", keys)
	}
}

// An enrollment key is single-purpose: it authenticates ONLY /api/cluster/enroll,
// never the snapshot (node-key) endpoint.
func TestEnrollKeyCannotAuthenticateSnapshot(t *testing.T) {
	s, _ := newEnrollServer(t, "enroll-secret", false)
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/snapshot", nil)
	req.Header.Set("Authorization", "Bearer enroll-secret") // the enrollment secret, not a node key
	rr := httptest.NewRecorder()
	s.clusterSnapshot(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("enrollment key on snapshot: status = %d, want 401 (%s)", rr.Code, rr.Body.String())
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

	// Approve (by immutable id), then the snapshot is served.
	node, _ := st.NodeByName("agent-c")
	if node == nil {
		t.Fatal("enrolled node not found")
	}
	if err := st.SetNodeApproved(node.ID, true); err != nil {
		t.Fatal(err)
	}
	rr2 := httptest.NewRecorder()
	s.clusterSnapshot(rr2, req)
	if rr2.Code != http.StatusOK {
		t.Fatalf("approved node snapshot: status = %d, want 200 (%s)", rr2.Code, rr2.Body.String())
	}
	// The snapshot carries the node's id so an id-less (upgraded) agent can learn it.
	if !strings.Contains(rr2.Body.String(), `"node_id":"`+node.ID+`"`) {
		t.Fatalf("snapshot should report node_id: %s", rr2.Body.String())
	}
}

// enrollOnce drives a single enroll request with the given JSON body and returns
// the recorder.
func enroll(s *Server, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	s.clusterEnroll(rr, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll", strings.NewReader(body)))
	return rr
}

// A join-token holder must NOT be able to steal an existing node's identity by
// enrolling under its name, or by presenting its (public) id without the current
// key. This is the core security fix.
func TestClusterEnrollCannotHijackExistingNode(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)

	// Victim enrolls first.
	first := enroll(s, `{"name":"victim","token":"s3cr3t"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first enroll: %d (%s)", first.Code, first.Body.String())
	}
	victim, _ := st.NodeByName("victim")
	if victim == nil {
		t.Fatal("victim not enrolled")
	}
	victimKeyHash := victim.KeyHash

	// (1) Enrolling under the SAME name with only the join token must create a NEW,
	// separate node (de-duplicated name) — never rotate the victim's key.
	attack := enroll(s, `{"name":"victim","token":"s3cr3t"}`)
	if attack.Code != http.StatusCreated {
		t.Fatalf("name-collision enroll: %d (%s)", attack.Code, attack.Body.String())
	}
	if got := mustNode(t, st, "victim").KeyHash; got != victimKeyHash {
		t.Fatal("victim's key was rotated by a name-collision enroll — hijack!")
	}
	nodes, _ := st.ListNodes()
	if len(nodes) != 2 {
		t.Fatalf("name-collision enroll should create a distinct node: %d nodes", len(nodes))
	}

	// (2) Presenting the victim's (public) id but NO current key must be rejected.
	noProof := enroll(s, `{"name":"victim","token":"s3cr3t","node_id":"`+victim.ID+`"}`)
	if noProof.Code != http.StatusForbidden {
		t.Fatalf("id without ownership proof: status = %d, want 403 (%s)", noProof.Code, noProof.Body.String())
	}

	// (3) Presenting the id with a WRONG current key must be rejected.
	wrongProof := enroll(s, `{"name":"victim","token":"s3cr3t","node_id":"`+victim.ID+`","node_key":"not-the-key"}`)
	if wrongProof.Code != http.StatusForbidden {
		t.Fatalf("id with wrong key: status = %d, want 403", wrongProof.Code)
	}
	if got := mustNode(t, st, "victim").KeyHash; got != victimKeyHash {
		t.Fatal("victim's key changed despite failed ownership proof")
	}
}

// An owner proving possession (id + current key) re-attaches to the SAME node and
// rotates its key in place — the legitimate recovery path (hostname change / lost
// or rejected key).
func TestClusterEnrollReenrollWithOwnershipRotatesSameNode(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)

	first := enroll(s, `{"name":"host-a","token":"s3cr3t"}`)
	id := jsonField(first.Body.String(), "id")
	key := jsonField(first.Body.String(), "key")
	if id == "" || key == "" {
		t.Fatalf("first enroll missing id/key: %s", first.Body.String())
	}

	// Re-enroll with a DIFFERENT name (simulating a hostname change) but proving
	// ownership. Same id comes back, name is preserved, exactly one node exists.
	re := enroll(s, `{"name":"host-a-new-hostname","token":"s3cr3t","node_id":"`+id+`","node_key":"`+key+`"}`)
	if re.Code != http.StatusOK {
		t.Fatalf("ownership re-enroll: status = %d, want 200 (%s)", re.Code, re.Body.String())
	}
	if got := jsonField(re.Body.String(), "id"); got != id {
		t.Fatalf("re-enroll should return the same id: got %q want %q", got, id)
	}
	if got := jsonField(re.Body.String(), "name"); got != "host-a" {
		t.Fatalf("re-enroll must not overwrite the (possibly operator-set) label: got %q", got)
	}
	newKey := jsonField(re.Body.String(), "key")
	if newKey == key {
		t.Fatal("re-enroll should rotate the key")
	}
	nodes, _ := st.ListNodes()
	if len(nodes) != 1 {
		t.Fatalf("hostname change must map to the same node: %d nodes", len(nodes))
	}
	// The rotated key authenticates; the old one no longer does.
	if n, _ := st.NodeByKeyHash(hashKey(newKey)); n == nil || n.ID != id {
		t.Fatal("rotated key should authenticate as the same node")
	}
	if n, _ := st.NodeByKeyHash(hashKey(key)); n != nil {
		t.Fatal("old key must stop working after rotation")
	}
}

// An agent upgraded from a pre-UUID build has a key but no stored id. It keeps
// working (authenticates by key) and learns its id from the snapshot without
// re-enrolling or creating a duplicate.
func TestOldAgentUpgradeLearnsIDFromSnapshot(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)
	first := enroll(s, `{"name":"legacy","token":"s3cr3t"}`)
	key := jsonField(first.Body.String(), "key")
	node, _ := st.NodeByName("legacy")

	// Old agent polls with only its key (no node_id anywhere) — it just works, and
	// the response carries the id it should persist.
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rr := httptest.NewRecorder()
	s.clusterSnapshot(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("old agent snapshot: status = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	if got := jsonField(rr.Body.String(), "node_id"); got != node.ID {
		t.Fatalf("snapshot should expose node_id for transparent learning: got %q want %q", got, node.ID)
	}
	nodes, _ := st.ListNodes()
	if len(nodes) != 1 {
		t.Fatalf("old agent must not create a duplicate: %d nodes", len(nodes))
	}
}

// snapshotPoll drives one authenticated snapshot request with the given node key.
func snapshotPoll(s *Server, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rr := httptest.NewRecorder()
	s.clusterSnapshot(rr, req)
	return rr
}

// Server-driven rotation issues a new key on the authenticated poll once the key
// is older than keyMaxAge, keeps the old key valid during the grace window (zero
// downtime), and retires the old key once the agent is seen using the new one.
func TestNodeKeyRotationWithOverlap(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}
	s.SetClusterEnrollment(false, time.Nanosecond, time.Hour) // always due, 1h grace
	if err := st.CreateEnrollKey(uuid.NewString(), "k", hashKey("s3cr3t"), keyPrefix("s3cr3t"), "test", 0, 0); err != nil {
		t.Fatal(err)
	}

	first := enroll(s, `{"name":"n","token":"s3cr3t"}`)
	id := jsonField(first.Body.String(), "id")
	k0 := jsonField(first.Body.String(), "key")

	// Poll with K0 → rotation due → a new key is issued in the snapshot.
	rr := snapshotPoll(s, k0)
	if rr.Code != http.StatusOK {
		t.Fatalf("poll: status = %d (%s)", rr.Code, rr.Body.String())
	}
	k1 := jsonField(rr.Body.String(), "new_node_key")
	if k1 == "" || k1 == k0 {
		t.Fatalf("expected a rotated key, got %q (old %q)", k1, k0)
	}
	// Zero-downtime overlap: the OLD key still authenticates (via grace); the new key
	// authenticates as the current key.
	if n, viaCur, _ := st.NodeByAnyKeyHash(hashKey(k0)); n == nil || viaCur {
		t.Fatal("old key should still authenticate during grace (as the previous key)")
	}
	if n, viaCur, _ := st.NodeByAnyKeyHash(hashKey(k1)); n == nil || !viaCur || n.ID != id {
		t.Fatal("new key should authenticate as the current key")
	}

	// Agent adopts the new key: stop forcing rotation, then poll with K1. The old key
	// is retired on first use of the new one.
	s.keyMaxAge = time.Hour
	if rr := snapshotPoll(s, k1); rr.Code != http.StatusOK {
		t.Fatalf("adopt poll: status = %d", rr.Code)
	}
	if jsonField(snapshotPoll(s, k1).Body.String(), "new_node_key") != "" {
		t.Fatal("no further rotation expected once the key is fresh")
	}
	if n, _, _ := st.NodeByAnyKeyHash(hashKey(k0)); n != nil {
		t.Fatal("old key must be retired once the agent uses the new key")
	}
}

// If the agent never persists an issued key (crash/lost response), it keeps polling
// with the old key during grace; the control plane re-issues and the old key keeps
// working until the agent finally adopts one — never a lockout mid-window.
func TestNodeKeyRotationCrashRecovery(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}
	s.SetClusterEnrollment(false, time.Nanosecond, time.Hour)
	if err := st.CreateEnrollKey(uuid.NewString(), "k", hashKey("s3cr3t"), keyPrefix("s3cr3t"), "test", 0, 0); err != nil {
		t.Fatal(err)
	}
	first := enroll(s, `{"name":"n","token":"s3cr3t"}`)
	k0 := jsonField(first.Body.String(), "key")

	// Rotation issues K1, but the agent "crashes" before persisting it.
	k1 := jsonField(snapshotPoll(s, k0).Body.String(), "new_node_key")
	if k1 == "" {
		t.Fatal("expected first rotation to issue a key")
	}
	// Agent polls again with the OLD key (still has it): control plane re-issues K2,
	// and the old key is still valid throughout.
	rr := snapshotPoll(s, k0)
	k2 := jsonField(rr.Body.String(), "new_node_key")
	if k2 == "" || k2 == k1 {
		t.Fatalf("expected a re-issued key distinct from the un-adopted one: k1=%q k2=%q", k1, k2)
	}
	if n, _, _ := st.NodeByAnyKeyHash(hashKey(k0)); n == nil {
		t.Fatal("old key must remain valid through the grace window (no lockout)")
	}
	// The previously-issued-but-unadopted K1 is no longer current (superseded by K2).
	if n, viaCur, _ := st.NodeByAnyKeyHash(hashKey(k1)); n != nil && viaCur {
		t.Fatal("the un-adopted K1 should have been superseded by K2")
	}
	// Agent finally adopts K2.
	s.keyMaxAge = time.Hour
	if rr := snapshotPoll(s, k2); rr.Code != http.StatusOK {
		t.Fatalf("adopt K2: status = %d", rr.Code)
	}
	if n, viaCur, _ := st.NodeByAnyKeyHash(hashKey(k2)); n == nil || !viaCur {
		t.Fatal("K2 should authenticate as the current key after adoption")
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

// TestClusterEnrollRevokedNodeRejected reproduces the bug: deleting a node with
// revocation must actually keep a still-running agent out. Its re-enroll attempts
// are refused (403 revoked), create no node, and — crucially — consume no
// enrollment-key uses no matter how many times it retries.
func TestClusterEnrollRevokedNodeRejected(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)

	first := enroll(s, `{"name":"host-a","token":"s3cr3t"}`)
	id := jsonField(first.Body.String(), "id")
	key := jsonField(first.Body.String(), "key")
	if id == "" || key == "" {
		t.Fatalf("first enroll missing id/key: %s", first.Body.String())
	}
	useCount := func() int64 {
		keys, _ := st.ListEnrollKeys()
		if len(keys) != 1 {
			t.Fatalf("want exactly 1 enrollment key, got %d", len(keys))
		}
		return keys[0].UseCount
	}
	if uc := useCount(); uc != 1 {
		t.Fatalf("use_count after the one real join = %d, want 1", uc)
	}

	// Admin removes the node WITH revocation.
	if err := st.DeleteNode(id, true, "admin"); err != nil {
		t.Fatal(err)
	}

	// The still-running agent re-enrolls presenting its id + key, many times.
	body := `{"name":"host-a","token":"s3cr3t","node_id":"` + id + `","node_key":"` + key + `"}`
	for i := 0; i < 5; i++ {
		rr := enroll(s, body)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("revoked re-enroll #%d: status = %d, want 403 (%s)", i, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"revoked":true`) {
			t.Fatalf("revoked re-enroll missing machine-readable flag: %s", rr.Body.String())
		}
	}
	if nodes, _ := st.ListNodes(); len(nodes) != 0 {
		t.Fatalf("a revoked re-enroll must not create a node, got %d", len(nodes))
	}
	if uc := useCount(); uc != 1 {
		t.Fatalf("revoked attempts must not consume key uses: use_count = %d, want 1", uc)
	}
}

// TestClusterEnrollUnrevokeAllowsRejoin: after un-revoke, the same agent's next
// attempt succeeds and re-attaches as a NEW node id (the old row is gone, so it
// falls through to a fresh enrollment).
func TestClusterEnrollUnrevokeAllowsRejoin(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)
	first := enroll(s, `{"name":"host-a","token":"s3cr3t"}`)
	id := jsonField(first.Body.String(), "id")
	key := jsonField(first.Body.String(), "key")
	body := `{"name":"host-a","token":"s3cr3t","node_id":"` + id + `","node_key":"` + key + `"}`

	if err := st.DeleteNode(id, true, "admin"); err != nil {
		t.Fatal(err)
	}
	if rr := enroll(s, body); rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 while revoked, got %d", rr.Code)
	}
	if removed, err := st.UnrevokeNode(id); err != nil || !removed {
		t.Fatalf("un-revoke should remove the tombstone: removed=%v err=%v", removed, err)
	}
	rr := enroll(s, body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("after un-revoke the agent should re-enroll as a new node: %d (%s)", rr.Code, rr.Body.String())
	}
	newID := jsonField(rr.Body.String(), "id")
	if newID == "" || newID == id {
		t.Fatalf("re-join should mint a NEW node id, got %q (old %q)", newID, id)
	}
}

// TestClusterEnrollRemoveOnlySelfHeals: "remove only" (no tombstone) — the same
// path a control-plane DB reset takes — lets the agent self-heal as a new node.
func TestClusterEnrollRemoveOnlySelfHeals(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)
	first := enroll(s, `{"name":"host-a","token":"s3cr3t"}`)
	id := jsonField(first.Body.String(), "id")
	key := jsonField(first.Body.String(), "key")

	if err := st.DeleteNode(id, false, ""); err != nil { // remove-only
		t.Fatal(err)
	}
	if revoked, _ := st.IsNodeRevoked(id); revoked {
		t.Fatal("remove-only must not write a tombstone")
	}
	body := `{"name":"host-a","token":"s3cr3t","node_id":"` + id + `","node_key":"` + key + `"}`
	rr := enroll(s, body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("remove-only should re-enroll as a new node (self-heal): %d (%s)", rr.Code, rr.Body.String())
	}
	if newID := jsonField(rr.Body.String(), "id"); newID == "" || newID == id {
		t.Fatalf("self-heal should mint a NEW node id, got %q (old %q)", newID, id)
	}
}
