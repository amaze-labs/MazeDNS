package resolver

import (
	"sync"
	"time"
)

// rlShards is the number of independent lock-striped buckets, mirroring the
// cache's sharding (internal/cache/cache.go): allow() runs on every single
// query, so a lone global lock/map would serialize rate-limit checks across
// every client under load. A power of two so the hash maps cheaply with a mask.
const rlShards = 16

type rlShard struct {
	mu     sync.Mutex
	counts map[string]*rlEntry
}

// rateLimiter enforces a per-client fixed-window queries-per-minute limit.
type rateLimiter struct {
	limit  int
	window time.Duration
	shards [rlShards]rlShard
}

type rlEntry struct {
	start time.Time
	count int
}

func newRateLimiter(qpm int) *rateLimiter {
	rl := &rateLimiter{limit: qpm, window: time.Minute}
	for i := range rl.shards {
		rl.shards[i].counts = make(map[string]*rlEntry)
	}
	return rl
}

// shardFor picks a shard by an inline, allocation-free FNV-1a hash of client.
func (rl *rateLimiter) shardFor(client string) *rlShard {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(client); i++ {
		h ^= uint32(client[i])
		h *= prime32
	}
	return &rl.shards[h&(rlShards-1)]
}

// allow reports whether the client may make another query right now.
func (rl *rateLimiter) allow(client string) bool {
	if rl == nil || rl.limit <= 0 || client == "" {
		return true
	}
	now := time.Now()
	s := rl.shardFor(client)
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.counts[client]
	if e == nil || now.Sub(e.start) >= rl.window {
		s.counts[client] = &rlEntry{start: now, count: 1}
		if len(s.counts) > 10000/rlShards {
			// Opportunistic cleanup of stale windows, bounded so we never hold the
			// shard's lock scanning its whole map (which would stall other clients
			// hashing to the same shard). Each triggering call sweeps a slice; steady
			// churn keeps the shard bounded over time.
			scanned := 0
			for k, v := range s.counts {
				if now.Sub(v.start) >= rl.window {
					delete(s.counts, k)
				}
				if scanned++; scanned >= 256 {
					break
				}
			}
		}
		return true
	}
	if e.count >= rl.limit {
		return false
	}
	e.count++
	return true
}
