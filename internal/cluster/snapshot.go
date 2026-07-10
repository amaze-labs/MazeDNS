// Package cluster provides master->worker configuration replication.
package cluster

import "github.com/IPMaze/MazeDNS/internal/store"

// Snapshot is the replicated configuration the master serves to a worker.
// It is computed PER NODE: rewrites and forwarders are pre-filtered to the
// entries that apply to the requesting node (scope metadata never leaves the
// control plane), and Version is the content hash of exactly this payload.
type Snapshot struct {
	Version     string              `json:"version"`
	Rules       []store.Rule        `json:"rules"`
	Rewrites    []store.Rewrite     `json:"rewrites"`
	Forwarders  []store.ForwardSpec `json:"forwarders,omitempty"`
	PausedUntil int64               `json:"paused_until"` // cluster-wide block pause deadline (unix)
	Maintenance bool                `json:"maintenance"`  // this node is drained (answers SERVFAIL)
	NodeID      string          `json:"node_id"`      // this node's immutable id (so an id-less agent can learn+persist it)
	NewNodeKey  string          `json:"new_node_key"` // set when the control plane rotated this node's key on this poll ('' otherwise)
	Version     string          `json:"version"`
	Rules       []store.Rule    `json:"rules"`
	Rewrites    []store.Rewrite `json:"rewrites"`
	PausedUntil int64           `json:"paused_until"` // cluster-wide block pause deadline (unix)
	Maintenance bool            `json:"maintenance"`  // this node is drained (answers SERVFAIL)
}
