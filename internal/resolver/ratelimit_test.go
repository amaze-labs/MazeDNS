package resolver

import (
	"strconv"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(2)
	if !rl.allow("a") || !rl.allow("a") {
		t.Fatal("first two queries from a client should be allowed")
	}
	if rl.allow("a") {
		t.Fatal("third query should be rate-limited")
	}
	if !rl.allow("b") {
		t.Fatal("a different client should not be limited")
	}

	var unlimited *rateLimiter
	if !unlimited.allow("x") {
		t.Fatal("nil limiter should allow everything")
	}
}

// rlTotal sums entry counts across all shards.
func rlTotal(rl *rateLimiter) int {
	n := 0
	for i := range rl.shards {
		n += len(rl.shards[i].counts)
	}
	return n
}

// Past the cleanup threshold, allow() sweeps stale windows but only a bounded
// number per call (so it never scans a whole shard's map under its lock), and
// still enforces limits.
func TestRateLimiterBoundedCleanup(t *testing.T) {
	rl := newRateLimiter(5)
	stale := time.Now().Add(-2 * time.Minute) // older than the 1-minute window
	for i := 0; i < 11000; i++ {
		key := "stale" + strconv.Itoa(i)
		s := rl.shardFor(key)
		s.counts[key] = &rlEntry{start: stale, count: 1}
	}
	before := rlTotal(rl)

	// A fresh client crosses the fresh client's shard threshold and triggers one
	// bounded sweep of that shard.
	if !rl.allow("fresh") {
		t.Fatal("fresh client should be allowed")
	}
	after := rlTotal(rl)

	if after >= before {
		t.Errorf("expected stale entries to be swept; before=%d after=%d", before, after)
	}
	if removed := before - after; removed > 256 {
		t.Errorf("sweep removed %d entries; should be bounded to ~256", removed)
	}

	// Enforcement still works for a repeat client.
	for i := 0; i < 5; i++ {
		rl.allow("steady")
	}
	if rl.allow("steady") {
		t.Error("6th query from a steady client should be limited")
	}
}
