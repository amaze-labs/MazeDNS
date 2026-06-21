package cache

import (
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

	if _, ok := c.Get(q); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.Set(q, makeReply("example.com", 300))
	got, ok := c.Get(q)
	if !ok {
		t.Fatal("expected hit after set")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(got.Answer))
	}

	q2 := q
	q2.Qtype = dns.TypeAAAA
	if _, ok := c.Get(q2); ok {
		t.Error("expected miss for a different qtype")
	}
}

func TestCacheTTLClamp(t *testing.T) {
	c := New(100, 30*time.Second, time.Hour)
	q := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, makeReply("example.com", 5)) // 5s is below the 30s min
	got, ok := c.Get(q)
	if !ok {
		t.Fatal("expected hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl < 25 || ttl > 30 {
		t.Errorf("ttl=%d, expected it clamped to ~30s", ttl)
	}
}
