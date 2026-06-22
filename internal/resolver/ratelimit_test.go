package resolver

import "testing"

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
