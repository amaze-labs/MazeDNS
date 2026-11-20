package store

import (
	"path/filepath"
	"testing"
	"time"
)

// A node's heartbeat (last seen + counters, every sync) is held in memory and
// written at most every heartbeatFlush, or at once when what the node reports
// about itself changes; readers see the latest values either way.
func TestTouchNodeWritesThroughRarely(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hb.db")
	s, wal := openMeasuredAt(t, path)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	id, err := s.CreateNode("r1", "hash", "pfx")
	if err != nil {
		t.Fatal(err)
	}

	touch := func(addr, ver string, total int64) int64 {
		return wal(func() {
			if err := s.TouchNode(id, addr, ver, "app1", NodeStats{Total: total}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if p := touch("a1", "v1", 1); p == 0 {
		t.Fatal("the first heartbeat must be written")
	}
	now = now.Add(30 * time.Second)
	if p := touch("a1", "v1", 2); p != 0 {
		t.Fatalf("a routine heartbeat wrote %d pages, want 0", p)
	}
	assertNode(t, s, id, now.Unix(), 2)

	now = now.Add(30 * time.Second)
	if p := touch("a1", "v2", 3); p == 0 {
		t.Fatal("a new config version must be written at once")
	}
	now = now.Add(heartbeatFlush)
	if p := touch("a1", "v2", 4); p == 0 {
		t.Fatalf("a heartbeat %v after the last write must be written", heartbeatFlush)
	}
	now = now.Add(30 * time.Second)
	touch("a1", "v2", 5) // held in memory

	// Close writes what is held; a reopened store reads it back.
	_ = s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	assertNode(t, s2, id, now.Unix(), 5)

	// A deleted node's held heartbeat is forgotten.
	s2.now = func() time.Time { return now }
	_ = s2.TouchNode(id, "a1", "v2", "app1", NodeStats{Total: 6})
	now = now.Add(30 * time.Second)
	_ = s2.TouchNode(id, "a1", "v2", "app1", NodeStats{Total: 7})
	if err := s2.DeleteNode(id, false, ""); err != nil {
		t.Fatal(err)
	}
	if err := s2.CreateNodeWithID(id, "r1", "hash", "pfx", true); err != nil {
		t.Fatal(err)
	}
	if n, _ := s2.NodeByID(id); n == nil || n.LastSeen == now.Unix() {
		t.Fatalf("re-created node shows the deleted node's heartbeat: %+v", n)
	}
}

func assertNode(t *testing.T, s *Store, id string, lastSeen, total int64) {
	t.Helper()
	n, err := s.NodeByID(id)
	if err != nil || n == nil {
		t.Fatalf("NodeByID: %v, %v", n, err)
	}
	if n.LastSeen != lastSeen {
		t.Errorf("NodeByID last_seen = %d, want %d", n.LastSeen, lastSeen)
	}
	nodes, err := s.ListNodes()
	if err != nil || len(nodes) != 1 {
		t.Fatalf("ListNodes: %v, %v", nodes, err)
	}
	if nodes[0].LastSeen != lastSeen || nodes[0].Total != total {
		t.Errorf("ListNodes last_seen = %d total = %d, want %d and %d", nodes[0].LastSeen, nodes[0].Total, lastSeen, total)
	}
}
