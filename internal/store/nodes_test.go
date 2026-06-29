package store

import (
	"path/filepath"
	"testing"
)

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

	if err := s.CreateNode("w1", "hashA", "prefA"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.NodeByKeyHash("hashA"); n == nil || n.Name != "w1" {
		t.Fatalf("node not found by original key: %+v", n)
	}

	if err := s.UpdateNodeKey("w1", "hashB", "prefB"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.NodeByKeyHash("hashA"); n != nil {
		t.Error("old key must stop working after rotation")
	}
	if n, _ := s.NodeByKeyHash("hashB"); n == nil || n.Name != "w1" {
		t.Fatalf("new key must work after rotation: %+v", n)
	}

	if err := s.UpdateNodeKey("does-not-exist", "x", "y"); err == nil {
		t.Error("rotating a missing node should error")
	}
}

func TestNodeMaintenanceFlag(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreateNode("w1", "hashA", "prefA"); err != nil {
		t.Fatal(err)
	}
	// New nodes are not in maintenance.
	if n, _ := s.NodeByKeyHash("hashA"); n == nil || n.Maintenance {
		t.Fatalf("new node should not be in maintenance: %+v", n)
	}

	if err := s.SetNodeMaintenance("w1", true); err != nil {
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
	if err := s.SetNodeMaintenance("w1", false); err != nil {
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
