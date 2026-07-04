package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/cluster"
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
func TestLocalNodeKey(t *testing.T) {
	t.Run("explicit node_key runs and is persisted", func(t *testing.T) {
		st := testStore(t)
		if got := localNodeKey(st, "", "explicit-key"); got != "explicit-key" {
			t.Fatalf("node_key path: got %q", got)
		}
		if k, _ := st.GetMeta(nodeKeyMeta); k != "explicit-key" {
			t.Fatalf("node_key should be persisted, got %q", k)
		}
	})

	t.Run("persisted key wins", func(t *testing.T) {
		st := testStore(t)
		_ = st.SetMeta(nodeKeyMeta, "persisted")
		if got := localNodeKey(st, "", "explicit-key"); got != "persisted" {
			t.Fatalf("persisted path: got %q", got)
		}
	})

	t.Run("join token defers to enrollment", func(t *testing.T) {
		st := testStore(t)
		if got := localNodeKey(st, "join-tok", "explicit-key"); got != "" {
			t.Fatalf("with a join token enrollment must run first, got %q", got)
		}
	})

	t.Run("no credential -> standalone (empty key)", func(t *testing.T) {
		st := testStore(t)
		if got := localNodeKey(st, "", ""); got != "" {
			t.Fatalf("no credential should yield empty key, got %q", got)
		}
	})
}

// enrollLoop retries until enrollment succeeds, stops for a revoked node, and
// falls back to an explicit key when one is configured.
func TestEnrollLoop(t *testing.T) {
	noop := func(string) {}

	t.Run("success returns the enrolled key", func(t *testing.T) {
		reenroll := func(context.Context) (string, error) { return "enrolled-key", nil }
		if got := enrollLoop(context.Background(), reenroll, "", noop, ""); got != "enrolled-key" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("transient failure keeps looping until ctx ends", func(t *testing.T) {
		calls := 0
		ctx, cancel := context.WithCancel(context.Background())
		reenroll := func(context.Context) (string, error) {
			calls++
			cancel() // end the loop instead of sleeping 30s in the test
			return "", errors.New("cp unreachable")
		}
		if got := enrollLoop(ctx, reenroll, "", noop, ""); got != "" {
			t.Fatalf("cancelled loop must return empty, got %q", got)
		}
		if calls != 1 {
			t.Fatalf("expected exactly one attempt before ctx end, got %d", calls)
		}
	})

	t.Run("revoked is terminal", func(t *testing.T) {
		reenroll := func(context.Context) (string, error) { return "", cluster.ErrNodeRevoked }
		if got := enrollLoop(context.Background(), reenroll, "fallback-key", noop, ""); got != "" {
			t.Fatalf("revoked node must not fall back or retry, got %q", got)
		}
	})

	t.Run("explicit key is the failure fallback", func(t *testing.T) {
		var persisted string
		reenroll := func(context.Context) (string, error) { return "", errors.New("enrollment broken") }
		got := enrollLoop(context.Background(), reenroll, "fallback-key", func(k string) { persisted = k }, "")
		if got != "fallback-key" || persisted != "fallback-key" {
			t.Fatalf("fallback: got %q persisted %q", got, persisted)
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
