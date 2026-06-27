package store

import (
	"path/filepath"
	"testing"
)

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
