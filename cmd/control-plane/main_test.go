package main

import (
	"path/filepath"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// The removed MAZEDNS_CLUSTER_BOOTSTRAP_NODES env var must not fail startup or
// provision anything: it only logs a one-line deprecation notice when set.
func TestWarnRemovedBootstrapNodes(t *testing.T) {
	if warnRemovedBootstrapNodes("") {
		t.Error("unset env should not warn")
	}
	if warnRemovedBootstrapNodes("   ") {
		t.Error("blank env should not warn")
	}
	if !warnRemovedBootstrapNodes("agent-a=key1,agent-b=key2") {
		t.Error("set env should warn")
	}
}

// Even with the env var set, the startup bootstrap path provisions no node — node
// pre-provisioning was removed entirely (no EnsureNode call remains).
func TestBootstrapNodesProvisionsNothing(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	warnRemovedBootstrapNodes("agent-a=key1,agent-b=key2")

	nodes, err := st.ListNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("bootstrap must create no nodes, got %d", len(nodes))
	}
}
