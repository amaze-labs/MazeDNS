// Package cluster provides master->worker configuration replication.
package cluster

import "github.com/IPMaze/MazeDNS/internal/store"

// Snapshot is the full replicated configuration the master serves to workers.
type Snapshot struct {
	NodeID      string          `json:"node_id"`      // this node's immutable id (so an id-less agent can learn+persist it)
	NewNodeKey  string          `json:"new_node_key"` // set when the control plane rotated this node's key on this poll ('' otherwise)
	Version     string          `json:"version"`
	Rules       []store.Rule    `json:"rules"`
	Rewrites    []store.Rewrite `json:"rewrites"`
	PausedUntil int64           `json:"paused_until"` // cluster-wide block pause deadline (unix)
	Maintenance bool            `json:"maintenance"`  // this node is drained (answers SERVFAIL)
}
