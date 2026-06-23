// Package cluster provides master->worker configuration replication.
package cluster

import "github.com/IPMaze/MazeDNS/internal/store"

// Snapshot is the full replicated configuration the master serves to workers.
type Snapshot struct {
	Version     string          `json:"version"`
	Rules       []store.Rule    `json:"rules"`
	Rewrites    []store.Rewrite `json:"rewrites"`
	PausedUntil int64           `json:"paused_until"` // cluster-wide block pause deadline (unix)
}
