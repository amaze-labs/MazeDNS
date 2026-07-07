package resolver

import (
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// singleflight coalesces concurrent forwards for the same question: the first
// caller for a key runs the upstream exchange while the rest wait and share its
// result. This prevents a thundering herd to the upstream when many clients ask
// for the same uncached name at once (e.g. a popular record's TTL just expired).
//
// It is the classic WaitGroup-based pattern (same idea as golang.org/x/sync/
// singleflight), kept in-package to avoid a new dependency. Sharded the same way
// as the cache (internal/cache/cache.go) and the rate limiter (ratelimit.go): a
// single global lock/map would serialize every cache-miss forward's in-flight
// bookkeeping across all distinct names, not just genuinely-colliding ones.
type singleflight struct {
	shards [sfShards]sfShard
}

// sfShards mirrors cacheShards/rlShards — a power of two so the hash maps
// cheaply with a mask.
const sfShards = 16

type sfShard struct {
	mu sync.Mutex
	m  map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	msg *dns.Msg
	rtt time.Duration
	err error
}

// shardFor picks a shard by an inline, allocation-free FNV-1a hash of key.
func (g *singleflight) shardFor(key string) *sfShard {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= prime32
	}
	return &g.shards[h&(sfShards-1)]
}

// Do runs fn for key, deduplicating concurrent calls. The returned *dns.Msg is
// shared with other waiters, so callers MUST treat it as read-only (copy before
// mutating).
func (g *singleflight) Do(key string, fn func() (*dns.Msg, time.Duration, error)) (*dns.Msg, time.Duration, error) {
	s := g.shardFor(key)
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[string]*sfCall)
	}
	if c, ok := s.m[key]; ok {
		s.mu.Unlock()
		c.wg.Wait()
		return c.msg, c.rtt, c.err
	}
	c := &sfCall{}
	c.wg.Add(1)
	s.m[key] = c
	s.mu.Unlock()

	c.msg, c.rtt, c.err = fn()
	c.wg.Done()

	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
	return c.msg, c.rtt, c.err
}

// forwardKey identifies a forward request the same way the cache keys an entry
// (class/type/name + DNSSEC variant), so coalescing matches caching semantics.
// Built into one pre-sized buffer with inline ASCII lowercasing to avoid the
// per-call allocations of a strings.Builder + FormatUint + ToLower.
func forwardKey(q dns.Question, do bool) string {
	buf := make([]byte, 0, len(q.Name)+13)
	if do {
		buf = append(buf, '+')
	}
	buf = strconv.AppendUint(buf, uint64(q.Qclass), 10)
	buf = append(buf, '/')
	buf = strconv.AppendUint(buf, uint64(q.Qtype), 10)
	buf = append(buf, '/')
	for i := 0; i < len(q.Name); i++ {
		c := q.Name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf = append(buf, c)
	}
	return string(buf)
}
