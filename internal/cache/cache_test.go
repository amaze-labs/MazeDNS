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

func TestCacheHitMiss(t *testing.T) {
	c := New(100, 5*time.Second, time.Hour)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}

	if _, ok := c.Get(q, false); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.Set(q, false, makeReply("example.com", 300))
	got, ok := c.Get(q, false)
	if !ok {
		t.Fatal("expected hit after set")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(got.Answer))
	}

	q2 := q
	q2.Qtype = dns.TypeAAAA
	if _, ok := c.Get(q2, false); ok {
		t.Error("expected miss for a different qtype")
	}

	// The DNSSEC-signed variant is a separate cache entry.
	if _, ok := c.Get(q, true); ok {
		t.Error("expected miss for the signed variant of an unsigned entry")
	}
}

func TestCacheTTLClamp(t *testing.T) {
	c := New(100, 30*time.Second, time.Hour)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, false, makeReply("example.com", 5)) // 5s is below the 30s min
	got, ok := c.Get(q, false)
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

	got1, ok := c.Get(q, false)
	if !ok {
		t.Fatal("expected hit")
	}
	got1.Answer = nil       // mutate the returned message
	got1.Id = 1234          //
	got2, ok := c.Get(q, false)
	if !ok || len(got2.Answer) != 1 {
		t.Fatalf("cached entry was corrupted by a caller mutation: ok=%v answers=%d", ok, len(got2.Answer))
	}
}

// An expired entry is a miss and is evicted from the map on access.
func TestCacheExpiry(t *testing.T) {
	c := New(100, 0, 0) // no clamps: honor the record's own (tiny) TTL
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, false, makeReply("example.com", 1))
	if c.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", c.Len())
	}
	time.Sleep(1100 * time.Millisecond)
	if _, ok := c.Get(q, false); ok {
		t.Error("expected miss for an expired entry")
	}
	if c.Len() != 0 {
		t.Errorf("expired entry should have been evicted on Get, Len=%d", c.Len())
	}
}

// The cache never exceeds maxItems; sampled eviction makes room for new entries.
func TestCacheEvictionStaysAtCapacity(t *testing.T) {
	const max = 50
	c := New(max, time.Minute, time.Hour)
	for i := 0; i < max*4; i++ {
		name := "host" + strconv.Itoa(i) + ".example.com"
		q := dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}
		c.Set(q, false, makeReply(name, 300))
	}
	if n := c.Len(); n > max {
		t.Errorf("cache exceeded capacity: Len=%d > max=%d", n, max)
	}
}

func BenchmarkCacheGetParallel(b *testing.B) {
	c := New(1000, time.Second, time.Hour)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, false, makeReply("example.com", 300))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := c.Get(q, false); !ok {
				b.Fatal("expected hit")
			}
		}
	})
}
