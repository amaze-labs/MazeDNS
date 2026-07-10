package store

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func uuidLike(t *testing.T) string {
	t.Helper()
	return uuid.NewString()
}

// rollupAll drains the rollup cursor so every query_log row is materialized.
func rollupAll(t *testing.T, s *Store) {
	t.Helper()
	for {
		more, err := s.RollupAdvance(1000)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			return
		}
	}
}

// scanInt runs a single-int query for test assertions.
func scanInt(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.read.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return n
}

// TestRenameMergesOrphanedRollupHistory reproduces the real "replace an agent" flow:
// delete a node (leaving its history), then rename the survivor to the deleted
// node's name. The survivor's rollup rows share PK buckets with the orphaned rows,
// so the old blind UPDATE hit a primary-key violation. The rename must instead MERGE
// the counters. (Finding regression test #1.)
func TestRenameMergesOrphanedRollupHistory(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Node A ("dns1"): 2 forwards + 1 blocked from client c1, all in bucket/hour 0.
	idA, err := s.CreateNode("dns1", "hashA", "prefA")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertNodeQueryLog("dns1", []QueryLogEntry{
		{TS: 1000, Client: "c1", Name: "a.test", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 1},
		{TS: 1000, Client: "c1", Name: "b.test", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 1},
		{TS: 1000, Client: "c1", Name: "x.test", QType: "A", Action: "blocked", Rcode: "NXDOMAIN", ElapsedMS: 1},
	}); err != nil {
		t.Fatal(err)
	}
	rollupAll(t, s)

	// Replace A: delete it (remove-only; history stays, orphaned under "dns1").
	if err := s.DeleteNode(idA, false, ""); err != nil {
		t.Fatal(err)
	}

	// Node B ("dns1-new"): 3 forwards + 1 blocked from c1 in the SAME buckets.
	idB, err := s.CreateNode("dns1-new", "hashB", "prefB")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertNodeQueryLog("dns1-new", []QueryLogEntry{
		{TS: 1000, Client: "c1", Name: "a.test", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 1},
		{TS: 1000, Client: "c1", Name: "b.test", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 1},
		{TS: 1000, Client: "c1", Name: "c.test", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 1},
		{TS: 1000, Client: "c1", Name: "x.test", QType: "A", Action: "blocked", Rcode: "NXDOMAIN", ElapsedMS: 1},
	}); err != nil {
		t.Fatal(err)
	}
	rollupAll(t, s)

	// The rename that used to fail with a PK constraint error.
	if err := s.RenameNode(idB, "dns1"); err != nil {
		t.Fatalf("rename onto a deleted node's name should merge history, got: %v", err)
	}

	// No history remains under B's old label.
	for _, tbl := range []string{"query_log", "query_rollup", "client_rollup"} {
		if n := scanInt(t, s, `SELECT COUNT(*) FROM `+tbl+` WHERE node='dns1-new'`); n != 0 {
			t.Errorf("%s still has rows under the old name: %d", tbl, n)
		}
	}

	// Rollup counters are the SUM of both nodes' rows, folded into one label.
	if n := scanInt(t, s, `SELECT cnt FROM query_rollup WHERE node='dns1' AND action='forward'`); n != 5 {
		t.Errorf("query_rollup forward cnt = %d, want 5 (2+3)", n)
	}
	if n := scanInt(t, s, `SELECT cnt FROM query_rollup WHERE node='dns1' AND action='blocked'`); n != 2 {
		t.Errorf("query_rollup blocked cnt = %d, want 2 (1+1)", n)
	}
	cnt := scanInt(t, s, `SELECT cnt FROM client_rollup WHERE node='dns1' AND client='c1'`)
	blocked := scanInt(t, s, `SELECT blocked FROM client_rollup WHERE node='dns1' AND client='c1'`)
	if cnt != 7 || blocked != 2 {
		t.Errorf("client_rollup c1 cnt/blocked = %d/%d, want 7/2", cnt, blocked)
	}

	// query_log rows all live under the new name (3 from A + 4 from B).
	if n := scanInt(t, s, `SELECT COUNT(*) FROM query_log WHERE node='dns1'`); n != 7 {
		t.Errorf("query_log under 'dns1' = %d, want 7", n)
	}

	// The survivor keeps its identity.
	if nb, _ := s.NodeByID(idB); nb == nil || nb.Name != "dns1" {
		t.Errorf("renamed node should keep id %s with name dns1: %+v", idB, nb)
	}
}

// TestRenameToLiveNodeNameRollsBack verifies renaming onto a LIVE node's name fails
// cleanly ("name in use by another node") and migrates no history — the transaction
// rolls back. (Finding regression test #2.)
func TestRenameToLiveNodeNameRollsBack(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.CreateNode("dns1", "hashA", "prefA"); err != nil {
		t.Fatal(err)
	}
	idB, err := s.CreateNode("dns2", "hashB", "prefB")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertNodeQueryLog("dns2", []QueryLogEntry{
		{TS: 1000, Client: "c1", Name: "a.test", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 1},
	}); err != nil {
		t.Fatal(err)
	}
	rollupAll(t, s)

	err = s.RenameNode(idB, "dns1")
	if err == nil {
		t.Fatal("renaming onto a live node's name must fail")
	}
	if err.Error() != "name in use by another node" {
		t.Errorf("want a friendly 'name in use' error, got: %v", err)
	}

	// Nothing migrated: B keeps its name and its history stays under 'dns2'.
	nb, _ := s.NodeByID(idB)
	if nb == nil || nb.Name != "dns2" {
		t.Fatalf("failed rename must leave the node untouched: %+v", nb)
	}
	if n := scanInt(t, s, `SELECT COUNT(*) FROM query_log WHERE node='dns2'`); n != 1 {
		t.Errorf("history should stay under 'dns2', got %d", n)
	}
	if n := scanInt(t, s, `SELECT COUNT(*) FROM query_log WHERE node='dns1'`); n != 0 {
		t.Errorf("no history should have migrated to 'dns1', got %d", n)
	}
	if n := scanInt(t, s, `SELECT COUNT(*) FROM query_rollup WHERE node='dns2'`); n == 0 {
		t.Error("rollup history should remain under 'dns2' after a rolled-back rename")
	}
}

// TestRenameFastPathNoOrphans confirms the common no-collision rename still moves
// history cleanly when no orphaned rows exist. (Finding regression test #3.)
func TestRenameFastPathNoOrphans(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, err := s.CreateNode("dns1", "hashA", "prefA")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertNodeQueryLog("dns1", []QueryLogEntry{
		{TS: 1000, Client: "c1", Name: "a.test", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 1},
		{TS: 1000, Client: "c1", Name: "x.test", QType: "A", Action: "blocked", Rcode: "NXDOMAIN", ElapsedMS: 1},
	}); err != nil {
		t.Fatal(err)
	}
	rollupAll(t, s)

	if err := s.RenameNode(id, "fresh-name"); err != nil {
		t.Fatalf("fast-path rename should succeed: %v", err)
	}
	if n := scanInt(t, s, `SELECT COUNT(*) FROM query_log WHERE node='dns1'`); n != 0 {
		t.Errorf("old-name query_log should be empty, got %d", n)
	}
	if n := scanInt(t, s, `SELECT COUNT(*) FROM query_log WHERE node='fresh-name'`); n != 2 {
		t.Errorf("query_log should follow the rename, got %d", n)
	}
	if n := scanInt(t, s, `SELECT COUNT(*) FROM query_rollup WHERE node='fresh-name'`); n == 0 {
		t.Error("rollups should follow the rename")
	}
	if n := scanInt(t, s, `SELECT COUNT(*) FROM query_rollup WHERE node='dns1'`); n != 0 {
		t.Errorf("no rollup rows should remain under the old name, got %d", n)
	}
}

func TestUpsertOIDCUserAvatar(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	u, err := s.UpsertOIDCUser("sub-1", "alice", "admin", "https://idp/pic.png")
	if err != nil {
		t.Fatal(err)
	}
	if u.Source != "oidc" || u.AvatarURL != "https://idp/pic.png" {
		t.Fatalf("first upsert: %+v", u)
	}
	// A later login refreshes the avatar (and role).
	u2, err := s.UpsertOIDCUser("sub-1", "alice", "readonly", "https://idp/new.png")
	if err != nil {
		t.Fatal(err)
	}
	if u2.ID != u.ID || u2.AvatarURL != "https://idp/new.png" || u2.Role != "readonly" {
		t.Fatalf("re-upsert should update avatar+role in place: %+v", u2)
	}
	// GetUserByID surfaces source + avatar (used by /api/me).
	got, _ := s.GetUserByID(u.ID)
	if got == nil || got.Source != "oidc" || got.AvatarURL != "https://idp/new.png" {
		t.Fatalf("GetUserByID: %+v", got)
	}
}

func TestUpdateNodeKeyRotation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, err := s.CreateNode("w1", "hashA", "prefA")
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("CreateNode should return a generated id")
	}
	if n, _ := s.NodeByKeyHash("hashA"); n == nil || n.Name != "w1" || n.ID != id {
		t.Fatalf("node not found by original key: %+v", n)
	}

	if err := s.UpdateNodeKey(id, "hashB", "prefB"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.NodeByKeyHash("hashA"); n != nil {
		t.Error("old key must stop working after rotation")
	}
	if n, _ := s.NodeByKeyHash("hashB"); n == nil || n.Name != "w1" || n.ID != id {
		t.Fatalf("new key must work after rotation: %+v", n)
	}

	if err := s.UpdateNodeKey("does-not-exist", "x", "y"); err == nil {
		t.Error("rotating a missing node should error")
	}
}

func TestNodeApproval(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create pending (require_approval): the key authenticates but the node is held.
	idA := uuidLike(t)
	if err := s.CreateNodeWithID(idA, "agent-a", "hashA", "prefA", false); err != nil {
		t.Fatal(err)
	}
	n, _ := s.NodeByKeyHash("hashA")
	if n == nil || n.Name != "agent-a" || n.Approved || n.ID != idA {
		t.Fatalf("pending node: %+v", n)
	}
	// Approve it (by id).
	if err := s.SetNodeApproved(idA, true); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.NodeByKeyHash("hashA"); n == nil || !n.Approved {
		t.Fatalf("node should be approved: %+v", n)
	}

	// Ownership-proven re-enroll: rotating the key by id preserves identity+approval.
	if err := s.RotateNodeKeyByID(idA, "hashB", "prefB"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.NodeByKeyHash("hashA"); n != nil {
		t.Error("old key must stop working after rotation")
	}
	if n, _ := s.NodeByKeyHash("hashB"); n == nil || !n.Approved || n.ID != idA {
		t.Fatalf("rotated key must work with identity+approval preserved: %+v", n)
	}
	if err := s.SetNodeApproved("missing", true); err == nil {
		t.Error("approving a missing node should error")
	}
}

func TestNodeMaintenanceFlag(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, err := s.CreateNode("w1", "hashA", "prefA")
	if err != nil {
		t.Fatal(err)
	}
	// New nodes are not in maintenance.
	if n, _ := s.NodeByKeyHash("hashA"); n == nil || n.Maintenance {
		t.Fatalf("new node should not be in maintenance: %+v", n)
	}

	if err := s.SetNodeMaintenance(id, true); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.NodeByKeyHash("hashA"); n == nil || !n.Maintenance {
		t.Fatalf("maintenance flag not set: %+v", n)
	}
	// ListNodes surfaces it too (the master reads it for the snapshot/UI).
	nodes, _ := s.ListNodes()
	if len(nodes) != 1 || !nodes[0].Maintenance {
		t.Fatalf("ListNodes should reflect maintenance: %+v", nodes)
	}
	if err := s.SetNodeMaintenance(id, false); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.NodeByKeyHash("hashA"); n == nil || n.Maintenance {
		t.Fatalf("maintenance flag not cleared: %+v", n)
	}
	if err := s.SetNodeMaintenance("missing", true); err == nil {
		t.Error("toggling a missing node should error")
	}

	// Master flag round-trips via app_meta.
	if s.MasterMaintenance() {
		t.Error("master should default to not in maintenance")
	}
	if err := s.SetMasterMaintenance(true); err != nil {
		t.Fatal(err)
	}
	if !s.MasterMaintenance() {
		t.Error("master maintenance flag should persist")
	}
}

// TestRenameNodePreservesIdentityAndHistory verifies a rename keeps the node's
// immutable id, moves its history (query_log + rollups) to the new label so
// nothing splits, and is enforced-unique.
func TestRenameNodePreservesIdentityAndHistory(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, err := s.CreateNode("dns1", "hashA", "prefA")
	if err != nil {
		t.Fatal(err)
	}
	// Some history tagged with the old name, in both the raw log and the rollups.
	if err := s.InsertNodeQueryLog("dns1", []QueryLogEntry{
		{TS: 1000, Client: "c1", Name: "a.test", QType: "A", Action: "forward", Rcode: "NOERROR", ElapsedMS: 1},
		{TS: 2000, Client: "c1", Name: "b.test", QType: "A", Action: "blocked", Rcode: "NXDOMAIN", ElapsedMS: 2},
	}); err != nil {
		t.Fatal(err)
	}
	for {
		more, err := s.RollupAdvance(1000)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
	}

	if err := s.RenameNode(id, "dns1-renamed"); err != nil {
		t.Fatal(err)
	}

	// Identity is unchanged; the label moved.
	n, _ := s.NodeByKeyHash("hashA")
	if n == nil || n.ID != id || n.Name != "dns1-renamed" {
		t.Fatalf("rename should keep id, change name: %+v", n)
	}
	// History follows the rename — no rows left under the old label.
	var oldLog, newLog int
	s.read.QueryRow(`SELECT COUNT(*) FROM query_log WHERE node='dns1'`).Scan(&oldLog)
	s.read.QueryRow(`SELECT COUNT(*) FROM query_log WHERE node='dns1-renamed'`).Scan(&newLog)
	if oldLog != 0 || newLog != 2 {
		t.Fatalf("query_log history should follow rename: old=%d new=%d", oldLog, newLog)
	}
	var oldRoll, newRoll int
	s.read.QueryRow(`SELECT COUNT(*) FROM query_rollup WHERE node='dns1'`).Scan(&oldRoll)
	s.read.QueryRow(`SELECT COUNT(*) FROM query_rollup WHERE node='dns1-renamed'`).Scan(&newRoll)
	if oldRoll != 0 || newRoll == 0 {
		t.Fatalf("query_rollup history should follow rename: old=%d new=%d", oldRoll, newRoll)
	}

	// Renaming a missing node errors; a no-op rename to the same name is fine.
	if err := s.RenameNode("missing", "x"); err == nil {
		t.Error("renaming a missing node should error")
	}
	if err := s.RenameNode(id, "dns1-renamed"); err != nil {
		t.Errorf("no-op rename should succeed: %v", err)
	}

	// Names are unique: renaming onto another live node's label fails.
	other, _ := s.CreateNode("dns2", "hashB", "prefB")
	_ = other
	if err := s.RenameNode(id, "dns2"); err == nil {
		t.Error("renaming onto an existing name should fail (unique)")
	}
}

// TestNodeIdentityStableAcrossKeyRotation models a hostname change / key-loss
// recovery: the node keeps the SAME id across a key rotation, so re-attaching maps
// to one node rather than creating a duplicate.
func TestNodeIdentityStableAcrossKeyRotation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, err := s.CreateNode("host-a", "hashA", "prefA")
	if err != nil {
		t.Fatal(err)
	}
	// Re-enroll (proven owner) rotates the key by id — identity and label stick.
	if err := s.RotateNodeKeyByID(id, "hashA2", "prefA2"); err != nil {
		t.Fatal(err)
	}
	byID, _ := s.NodeByID(id)
	if byID == nil || byID.Name != "host-a" {
		t.Fatalf("node id should remain the identity: %+v", byID)
	}
	nodes, _ := s.ListNodes()
	if len(nodes) != 1 {
		t.Fatalf("re-attach must not create a duplicate node: %d nodes", len(nodes))
	}
}

// TestBackfillNodeIDsIsIdempotent verifies the pre-UUID migration assigns a unique
// id to a legacy row (no id) and that re-running the backfill is a no-op.
func TestBackfillNodeIDsIsIdempotent(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Simulate a legacy row that predates the id column (id='').
	if _, err := s.db.Exec(
		`INSERT INTO nodes(id, name, key_hash, key_prefix, created_at) VALUES('', 'legacy', 'hashL', 'prefL', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillNodeIDs(); err != nil {
		t.Fatal(err)
	}
	n, _ := s.NodeByName("legacy")
	if n == nil || n.ID == "" {
		t.Fatalf("legacy row should get a backfilled id: %+v", n)
	}
	first := n.ID
	// Re-running must not change the assigned id (idempotent across restarts).
	if err := s.backfillNodeIDs(); err != nil {
		t.Fatal(err)
	}
	n2, _ := s.NodeByName("legacy")
	if n2 == nil || n2.ID != first {
		t.Fatalf("backfill should be idempotent: was %q now %q", first, n2.ID)
	}
}

// TestDeleteNodeRevocationLifecycle covers the tombstone store methods: revoke on
// delete, remove-only leaves no tombstone, list, and un-revoke.
func TestDeleteNodeRevocationLifecycle(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	idA, err := s.CreateNode("a", "hA", "pA")
	if err != nil {
		t.Fatal(err)
	}
	idB, err := s.CreateNode("b", "hB", "pB")
	if err != nil {
		t.Fatal(err)
	}

	// Remove-and-revoke A.
	if err := s.DeleteNode(idA, true, "admin"); err != nil {
		t.Fatal(err)
	}
	if rev, _ := s.IsNodeRevoked(idA); !rev {
		t.Error("A should be revoked")
	}
	rn, _ := s.RevokedNodeByID(idA)
	if rn == nil || rn.Name != "a" || rn.RevokedBy != "admin" || rn.RevokedAt == 0 {
		t.Errorf("tombstone not populated: %+v", rn)
	}

	// Remove-only B → no tombstone.
	if err := s.DeleteNode(idB, false, ""); err != nil {
		t.Fatal(err)
	}
	if rev, _ := s.IsNodeRevoked(idB); rev {
		t.Error("remove-only B must not be revoked")
	}

	list, _ := s.ListRevokedNodes()
	if len(list) != 1 || list[0].ID != idA {
		t.Errorf("ListRevokedNodes = %+v, want only A", list)
	}

	// Un-revoke A.
	removed, err := s.UnrevokeNode(idA)
	if err != nil || !removed {
		t.Fatalf("un-revoke A: removed=%v err=%v", removed, err)
	}
	if rev, _ := s.IsNodeRevoked(idA); rev {
		t.Error("A should not be revoked after un-revoke")
	}
	if removed, _ := s.UnrevokeNode(idA); removed {
		t.Error("second un-revoke should report nothing removed")
	}
}
