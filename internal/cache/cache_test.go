package cache

import (
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func makeReply(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   []byte{93, 184, 216, 34},
	}}
	return m
}

// forceExpiry rewrites a cached entry's expiry time so tests can exercise the
// stale / hard-miss boundaries without sleeping.
func forceExpiry(c *Cache, q dns.Question, do bool, at time.Time) {
	k := keyFor(q, do)
	s := c.shardFor(k)
	s.mu.Lock()
	if e, ok := s.items[k]; ok {
		e.expiresAt = at
		s.items[k] = e
	}
	s.mu.Unlock()
}

func TestCacheHitMiss(t *testing.T) {
	c := New(100, 5*time.Second, time.Hour)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}

	if _, ok, _ := c.Get(q, false); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.Set(q, false, makeReply("example.com", 300))
	got, ok, stale := c.Get(q, false)
	if !ok {
		t.Fatal("expected hit after set")
	}
	if stale {
		t.Error("a fresh entry should not be stale")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(got.Answer))
	}

	q2 := q
	q2.Qtype = dns.TypeAAAA
	if _, ok, _ := c.Get(q2, false); ok {
		t.Error("expected miss for a different qtype")
	}

	// The DNSSEC-signed variant is a separate cache entry.
	if _, ok, _ := c.Get(q, true); ok {
		t.Error("expected miss for the signed variant of an unsigned entry")
	}
}

func TestCacheTTLClamp(t *testing.T) {
	c := New(100, 30*time.Second, time.Hour)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, false, makeReply("example.com", 5)) // 5s is below the 30s min
	got, ok, _ := c.Get(q, false)
	if !ok {
		t.Fatal("expected hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl < 25 || ttl > 30 {
		t.Errorf("ttl=%d, expected it clamped to ~30s", ttl)
	}
}

// Get must return an independent copy: mutating the returned message (as the
// resolver does via finalize/Truncate) must not corrupt the cached entry, which
// matters now that the copy is done outside the lock.
func TestCacheGetReturnsIndependentCopy(t *testing.T) {
	c := New(100, time.Second, time.Hour)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, false, makeReply("example.com", 300))

	got1, ok, _ := c.Get(q, false)
	if !ok {
		t.Fatal("expected hit")
	}
	got1.Answer = nil // mutate the returned message
	got1.Id = 1234
	got2, ok, _ := c.Get(q, false)
	if !ok || len(got2.Answer) != 1 {
		t.Fatalf("cached entry was corrupted by a caller mutation: ok=%v answers=%d", ok, len(got2.Answer))
	}
}

// Within the serve-stale window an expired entry is still served, flagged stale,
// with a small TTL; a fresh Set clears the staleness.
func TestCacheServeStale(t *testing.T) {
	c := New(100, 0, 0)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, false, makeReply("example.com", 60))

	// Expired a moment ago — still inside the grace window.
	forceExpiry(c, q, false, time.Now().Add(-time.Second))
	got, ok, stale := c.Get(q, false)
	if !ok || !stale {
		t.Fatalf("expected a stale hit; ok=%v stale=%v", ok, stale)
	}
	if ttl := got.Answer[0].Header().Ttl; ttl == 0 || ttl > staleTTL {
		t.Errorf("stale ttl=%d, want ~%d", ttl, staleTTL)
	}

	// A fresh Set makes it a normal hit again.
	c.Set(q, false, makeReply("example.com", 60))
	if _, ok, stale := c.Get(q, false); !ok || stale {
		t.Errorf("after refresh expected a fresh hit; ok=%v stale=%v", ok, stale)
	}
}

// Past the serve-stale grace window an entry is a real miss and is evicted on Get.
func TestCacheHardMiss(t *testing.T) {
	c := New(100, 0, 0)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, false, makeReply("example.com", 60))

	// Expired well beyond the grace window.
	forceExpiry(c, q, false, time.Now().Add(-2*staleGrace))
	if _, ok, _ := c.Get(q, false); ok {
		t.Error("expected a miss past the serve-stale window")
	}
	if c.Len() != 0 {
		t.Errorf("dead entry should have been evicted on Get, Len=%d", c.Len())
	}
}

// The cache never exceeds maxItems; sampled eviction makes room for new entries.
func TestCacheEvictionStaysAtCapacity(t *testing.T) {
	const max = 800 // comfortably above cacheShards so the per-shard cap is >= 1
	c := New(max, time.Minute, time.Hour)
	for i := 0; i < max*4; i++ {
		name := "host" + strconv.Itoa(i) + ".example.com"
		q := dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}
		c.Set(q, false, makeReply(name, 300))
	}
	// Allow the rounding-up of the per-shard cap across all shards.
	if n := c.Len(); n > max+cacheShards {
		t.Errorf("cache exceeded capacity: Len=%d > ~max=%d", n, max)
	}
}

func BenchmarkCacheGetParallel(b *testing.B) {
	c := New(1000, time.Second, time.Hour)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, false, makeReply("example.com", 300))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok, _ := c.Get(q, false); !ok {
				b.Fatal("expected hit")
			}
		}
	})
}
