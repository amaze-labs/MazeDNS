package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// The agent authenticates (i.e. runs, not standalone) whenever a credential is
// resolvable: an explicit node_key, a self-enrolled key, or a persisted one.
// Clustering is derived from configuration, not an enable flag.
func TestResolveNodeKey(t *testing.T) {
	noReenroll := func(context.Context) (string, error) { return "", errors.New("no join token") }

	t.Run("explicit node_key runs and is persisted", func(t *testing.T) {
		st := testStore(t)
		cfg := config.Config{}
		cfg.Cluster.NodeKey = "explicit-key"
		got := resolveNodeKey(context.Background(), st, cfg, "n1", "http://cp", "", noReenroll)
		if got != "explicit-key" {
			t.Fatalf("node_key path: got %q", got)
		}
		if k, _ := st.GetMeta(nodeKeyMeta); k != "explicit-key" {
			t.Fatalf("node_key should be persisted, got %q", k)
		}
	})

	t.Run("persisted key wins", func(t *testing.T) {
		st := testStore(t)
		_ = st.SetMeta(nodeKeyMeta, "persisted")
		got := resolveNodeKey(context.Background(), st, config.Config{}, "n1", "http://cp", "", noReenroll)
		if got != "persisted" {
			t.Fatalf("persisted path: got %q", got)
		}
	})

	t.Run("join token self-enrolls", func(t *testing.T) {
		st := testStore(t)
		cfg := config.Config{}
		cfg.Cluster.JoinToken = "join-tok"
		reenroll := func(context.Context) (string, error) { return "enrolled-key", nil }
		got := resolveNodeKey(context.Background(), st, cfg, "n1", "http://cp", "", reenroll)
		if got != "enrolled-key" {
			t.Fatalf("join-token path: got %q", got)
		}
	})

	t.Run("no credential -> standalone (empty key)", func(t *testing.T) {
		st := testStore(t)
		got := resolveNodeKey(context.Background(), st, config.Config{}, "n1", "http://cp", "", noReenroll)
		if got != "" {
			t.Fatalf("no credential should yield empty key, got %q", got)
		}
	})
}

// The cluster agent gate is cp_url alone: no cp_url means standalone, regardless of
// any legacy flag (which no longer exists). This mirrors startAgent's guard.
func TestControlPlaneGate(t *testing.T) {
	var cfg config.Config
	if cfg.Cluster.ControlPlaneURL() != "" {
		t.Fatal("no cp_url should be standalone")
	}
	cfg.Cluster.CPURL = "http://cp:8080"
	if cfg.Cluster.ControlPlaneURL() == "" {
		t.Fatal("cp_url set should be clustered")
	}
}
