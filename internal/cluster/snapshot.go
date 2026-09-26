// Package cluster provides master->worker configuration replication.
package cluster

import "github.com/IPMaze/MazeDNS/internal/store"

// Snapshot is the replicated configuration the master serves to a worker.
// It is computed PER NODE: rewrites and forwarders are pre-filtered to the
// entries that apply to the requesting node (scope metadata never leaves the
// control plane), and Version is the content hash of exactly this payload.
type Snapshot struct {
	NodeID      string              `json:"node_id"`      // this node's immutable id (so an id-less agent can learn+persist it)
	NewNodeKey  string              `json:"new_node_key"` // set when the control plane rotated this node's key on this poll ('' otherwise)
	Version     string              `json:"version"`
	Rules       []store.Rule        `json:"rules"`
	Rewrites    []store.Rewrite     `json:"rewrites"`
	Forwarders  []store.ForwardSpec `json:"forwarders,omitempty"`
	PausedUntil int64               `json:"paused_until"` // cluster-wide block pause deadline (unix)
	Maintenance bool                `json:"maintenance"`  // this node is drained (answers SERVFAIL)
}

// Snapshot-poll request headers (agent -> control plane).
//
// Every agent sends HeaderNodeVersion (the replicated-config hash it has
// applied). An agent that understands "304 Not Modified" also sends
// HeaderAcceptNotModified plus the rest of the state a snapshot would carry
// — its node id, the block-pause deadline and maintenance flag it has
// applied — so the control plane can skip the payload only when the agent
// provably holds everything the snapshot would deliver. Agents that don't
// send HeaderAcceptNotModified (older builds) always get the full 200: they
// would treat an empty rule set as authoritative and stop blocking.
const (
	HeaderNodeVersion       = "X-MazeDNS-Node-Version"
	HeaderAcceptNotModified = "X-MazeDNS-Accept-Not-Modified" // "1" = the agent handles 304
	HeaderNodeID            = "X-MazeDNS-Node-ID"
	HeaderPausedUntil       = "X-MazeDNS-Paused-Until" // decimal unix seconds the agent has applied
	HeaderMaintenance       = "X-MazeDNS-Maintenance"  // "1" | "0", as the agent has applied it
)
