// Package cache implements a TTL-aware DNS response cache.
package cache

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// cacheShards is the number of independent lock-striped buckets. Writes (every
// cache miss) and expiry deletes take a bucket's write lock, so sharding keeps
// those from serializing across the whole cache under load. A power of two so the
// hash maps cheaply with a mask.
const cacheShards = 16

// evictionSample is how many entries we look at when a shard is full to pick a
// victim — the one nearest expiry. Sampling a handful approximates LRU/TTL
// eviction at O(1) cost, and keeps hot entries far better than random eviction.
const evictionSample = 8

// staleGrace is how long past expiry an entry may still be served (RFC 8767
// serve-stale): a stale answer is returned immediately while a fresh one is
// fetched in the background, so the first client after a TTL lapse never eats the
// full upstream round-trip.
const staleGrace = 30 * time.Second

// staleTTL is the (small) TTL stamped on a stale answer, so clients re-query soon
// and pick up the refreshed record.
const staleTTL = 30

type entry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

type shard struct {
	mu    sync.RWMutex
	items map[string]entry
}

// Cache stores DNS replies keyed by question, honoring TTLs, with serve-stale.
type Cache struct {
	shards   [cacheShards]shard
	maxItems int // per shard
	minTTL   time.Duration
	maxTTL   time.Duration
}

// New creates a cache holding up to maxItems entries (split across shards),
// clamping cached TTLs to [minTTL, maxTTL].
func New(maxItems int, minTTL, maxTTL time.Duration) *Cache {
	if maxItems <= 0 {
		maxItems = 10000
	}
	c := &Cache{
		maxItems: (maxItems + cacheShards - 1) / cacheShards, // per-shard cap, rounded up
		minTTL:   minTTL,
		maxTTL:   maxTTL,
	}
	for i := range c.shards {
		c.shards[i].items = make(map[string]entry)
	}
	return c
}

// keyFor keys an entry by question AND whether it's the DNSSEC-signed variant, so
// a signed (DO) answer and an unsigned one are never served to the wrong client.
func keyFor(q dns.Question, do bool) string {
	var b strings.Builder
	if do {
		b.WriteByte('+') // signed variant
	}
	b.WriteString(strconv.FormatUint(uint64(q.Qclass), 10))
	b.WriteByte('/')
	b.WriteString(strconv.FormatUint(uint64(q.Qtype), 10))
	b.WriteByte('/')
	b.WriteString(strings.ToLower(q.Name))
	return b.String()
}

// shardFor picks a shard by an inline, allocation-free FNV-1a hash of the key.
func (c *Cache) shardFor(key string) *shard {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= prime32
	}
	return &c.shards[h&(cacheShards-1)]
}

// Get returns a cached reply for q (a copy, with TTLs decremented by the elapsed
// time) and whether it was a hit. The third return reports whether the hit is
// stale — expired but within the serve-stale grace window — in which case the
// caller should serve it now and refresh in the background. do selects the
// DNSSEC-signed variant.
func (c *Cache) Get(q dns.Question, do bool) (*dns.Msg, bool, bool) {
	k := keyFor(q, do)
	s := c.shardFor(k)
	s.mu.RLock()
	e, ok := s.items[k]
	s.mu.RUnlock()
	if !ok {
		return nil, false, false
	}
	now := time.Now()
	if now.After(e.expiresAt.Add(staleGrace)) {
		// Past the serve-stale window: a real miss. Drop it (re-check under the
		// write lock so we don't delete an entry another goroutine just refreshed).
		s.mu.Lock()
		if e2, ok := s.items[k]; ok && now.After(e2.expiresAt.Add(staleGrace)) {
			delete(s.items, k)
		}
		s.mu.Unlock()
		return nil, false, false
	}
	// e.msg is immutable once stored (Set keeps a Copy), so the deep copy that
	// every caller needs is done outside the lock — concurrent hits don't serialize.
	msg := e.msg.Copy()
	if now.After(e.expiresAt) {
		// Stale: serve a short TTL so the client re-queries soon, and tell the
		// caller to refresh in the background.
		adjustTTL(msg, staleTTL)
		return msg, true, true
	}
	remaining := uint32(e.expiresAt.Sub(now).Seconds())
	adjustTTL(msg, remaining)
	return msg, true, false
}

// Set stores msg as the cached reply for q (do = the DNSSEC-signed variant).
// Empty/NXDOMAIN answers are negative-cached using the SOA minimum when present.
func (c *Cache) Set(q dns.Question, do bool, msg *dns.Msg) {
	if msg == nil {
		return
	}
	ttl := c.ttlFor(msg)
	if ttl <= 0 {
		return
	}
	k := keyFor(q, do)
	s := c.shardFor(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[k]; !exists && len(s.items) >= c.maxItems {
		evictLocked(s)
	}
	s.items[k] = entry{
		msg:       msg.Copy(),
		expiresAt: time.Now().Add(ttl),
	}
}

// evictLocked removes the entry nearest expiry among a small random sample (map
// iteration order is random), preferring an already-expired one. Caller holds the
// shard's write lock.
func evictLocked(s *shard) {
	var victim string
	var soonest time.Time
	n := 0
	for k, e := range s.items {
		if victim == "" || e.expiresAt.Before(soonest) {
			victim, soonest = k, e.expiresAt
		}
		if n++; n >= evictionSample {
			break
		}
	}
	if victim != "" {
		delete(s.items, victim)
	}
}

// Len returns the current number of cached entries across all shards.
func (c *Cache) Len() int {
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		n += len(s.items)
		s.mu.RUnlock()
	}
	return n
}

func (c *Cache) ttlFor(msg *dns.Msg) time.Duration {
	min := ^uint32(0)
	found := false
	for _, rr := range msg.Answer {
		if t := rr.Header().Ttl; t < min {
			min, found = t, true
		}
	}
	if !found { // negative caching from the SOA in the authority section
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < min {
				min, found = soa.Minttl, true
			}
		}
	}
	if !found {
		return 0
	}
	d := time.Duration(min) * time.Second
	if d < c.minTTL {
		d = c.minTTL
	}
	if c.maxTTL > 0 && d > c.maxTTL {
		d = c.maxTTL
	}
	return d
}

func adjustTTL(msg *dns.Msg, ttl uint32) {
	for _, rr := range msg.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT { // OPT TTL encodes flags, leave it
			rr.Header().Ttl = ttl
		}
	}
}
