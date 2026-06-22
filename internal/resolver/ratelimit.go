package resolver

import (
	"sync"
	"time"
)

// rateLimiter enforces a per-client fixed-window queries-per-minute limit.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	counts map[string]*rlEntry
}

type rlEntry struct {
	start time.Time
	count int
}

func newRateLimiter(qpm int) *rateLimiter {
	return &rateLimiter{limit: qpm, window: time.Minute, counts: make(map[string]*rlEntry)}
}

// allow reports whether the client may make another query right now.
func (rl *rateLimiter) allow(client string) bool {
	if rl == nil || rl.limit <= 0 || client == "" {
		return true
	}
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e := rl.counts[client]
	if e == nil || now.Sub(e.start) >= rl.window {
		rl.counts[client] = &rlEntry{start: now, count: 1}
		if len(rl.counts) > 10000 { // opportunistic cleanup of stale windows
			for k, v := range rl.counts {
				if now.Sub(v.start) >= rl.window {
					delete(rl.counts, k)
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
