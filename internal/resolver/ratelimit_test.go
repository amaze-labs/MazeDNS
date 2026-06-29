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

// Past the cleanup threshold, allow() sweeps stale windows but only a bounded
// number per call (so it never scans the whole map under the lock), and still
// enforces limits.
func TestRateLimiterBoundedCleanup(t *testing.T) {
	rl := newRateLimiter(5)
	stale := time.Now().Add(-2 * time.Minute) // older than the 1-minute window
	for i := 0; i < 11000; i++ {
		rl.counts["stale"+strconv.Itoa(i)] = &rlEntry{start: stale, count: 1}
	}
	before := len(rl.counts)

	// A fresh client crosses the >10000 threshold and triggers one bounded sweep.
	if !rl.allow("fresh") {
		t.Fatal("fresh client should be allowed")
	}
	after := len(rl.counts)

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
