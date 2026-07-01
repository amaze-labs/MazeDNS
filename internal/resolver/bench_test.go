package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/cache"
	"github.com/IPMaze/MazeDNS/internal/filter"
)

// benchUpstream is a stub Upstream that returns a canned answer without any
// network I/O, so resolver benchmarks measure the pipeline (cache/filter/
// singleflight/copy) rather than upstream latency.
type benchUpstream struct{ resp *dns.Msg }

func (u benchUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	m := u.resp.Copy()
	m.Id = req.Id
	return m, time.Millisecond, nil
}
func (u benchUpstream) String() string { return "bench" }

func benchAnswer(name string) *dns.Msg {
	m := new(dns.Msg)
	m.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{93, 184, 216, 34},
	}}
	m.Response = true
	return m
}

func benchQuery(name string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return req
}

// BenchmarkResolveCacheHit measures the highest-volume path: rate-limit check,
// zone/rewrite/block/allow lookups, and a cache hit (get + deep copy).
func BenchmarkResolveCacheHit(b *testing.B) {
	r := New(Options{})
	c := cache.New(1000, time.Second, time.Hour)
	r.rt.Store(&runtime{blockMode: "nxdomain", cache: c})
	r.SetPolicy(sealedPolicy(nil))

	req := benchQuery("example.com")
	c.Set(req.Question[0], false, benchAnswer("example.com"))

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, action, _ := r.Resolve(req, "10.0.0.1")
			if action != "cache" || resp == nil {
				b.Fatalf("expected cache hit, got %q", action)
			}
		}
	})
}

// BenchmarkResolveBlocked measures the block path (sealed, lock-free matcher).
func BenchmarkResolveBlocked(b *testing.B) {
	r := New(Options{})
	r.rt.Store(&runtime{blockMode: "nxdomain"})
	block := filter.New()
	block.Add("doubleclick.net", "ads")
	r.SetPolicy(sealedPolicy(block))

	req := benchQuery("ads.g.doubleclick.net")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, action, _ := r.Resolve(req, "10.0.0.1"); action != "blocked" {
				b.Fatalf("expected blocked, got %q", action)
			}
		}
	})
}

// BenchmarkResolveForward measures a cache miss: singleflight + stub upstream
// exchange + response copy (cache disabled so every iteration is a real miss).
func BenchmarkResolveForward(b *testing.B) {
	r := New(Options{})
	r.rt.Store(&runtime{
		blockMode:        "nxdomain",
		defaultUpstreams: []Upstream{benchUpstream{resp: benchAnswer("example.com")}},
	})
	r.SetPolicy(sealedPolicy(nil))

	req := benchQuery("example.com")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, action, _ := r.Resolve(req, "10.0.0.1"); action != "forward" {
			b.Fatalf("expected forward, got %q", action)
		}
	}
}

// sealedPolicy builds a Policy with sealed (lock-free) block/allow engines.
func sealedPolicy(block *filter.Engine) *Policy {
	if block == nil {
		block = filter.New()
	}
	block.Seal()
	allow := filter.New()
	allow.Seal()
	return &Policy{Block: block, Allow: allow, Rewrites: map[string][]RewriteRR{}, Wildcards: map[string][]RewriteRR{}}
}
