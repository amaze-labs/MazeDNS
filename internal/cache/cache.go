// Package cache implements a TTL-aware DNS response cache.
package cache

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

// Cache stores DNS replies keyed by question, honoring TTLs.
type Cache struct {
	mu       sync.RWMutex
	items    map[string]entry
	maxItems int
	minTTL   time.Duration
	maxTTL   time.Duration
}

// evictionSample is how many entries we look at when the cache is full to pick a
// victim — the one nearest expiry. Sampling a handful approximates LRU/TTL
// eviction at O(1) cost, and keeps hot entries far better than random eviction.
const evictionSample = 8

// New creates a cache holding up to maxItems entries, clamping cached TTLs to
// [minTTL, maxTTL].
func New(maxItems int, minTTL, maxTTL time.Duration) *Cache {
	if maxItems <= 0 {
		maxItems = 10000
	}
	return &Cache{
		items:    make(map[string]entry, maxItems),
		maxItems: maxItems,
		minTTL:   minTTL,
		maxTTL:   maxTTL,
	}
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

// Get returns a cached reply for q (a copy, with TTLs decremented by the elapsed
// time) and true on a hit, or nil/false on a miss or expiry. do selects the
// DNSSEC-signed variant.
func (c *Cache) Get(q dns.Question, do bool) (*dns.Msg, bool) {
	k := keyFor(q, do)
	c.mu.RLock()
	e, ok := c.items[k]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	now := time.Now()
	if now.After(e.expiresAt) {
		// Expired: drop it under the write lock, but re-check first so we don't
		// delete an entry another goroutine just refreshed.
		c.mu.Lock()
		if e2, ok := c.items[k]; ok && now.After(e2.expiresAt) {
			delete(c.items, k)
		}
		c.mu.Unlock()
		return nil, false
	}
	// e.msg is immutable once stored (Set keeps a Copy), so the deep copy that
	// every caller needs is done outside the lock — concurrent hits don't serialize.
	remaining := uint32(e.expiresAt.Sub(now).Seconds())
	msg := e.msg.Copy()
	adjustTTL(msg, remaining)
	return msg, true
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[k]; !exists && len(c.items) >= c.maxItems {
		c.evictLocked()
	}
	c.items[k] = entry{
		msg:       msg.Copy(),
		expiresAt: time.Now().Add(ttl),
	}
}

// evictLocked removes the entry nearest expiry among a small random sample (map
// iteration order is random), preferring an already-expired one. Caller holds mu.
func (c *Cache) evictLocked() {
	var victim string
	var soonest time.Time
	n := 0
	for k, e := range c.items {
		if victim == "" || e.expiresAt.Before(soonest) {
			victim, soonest = k, e.expiresAt
		}
		if n++; n >= evictionSample {
			break
		}
	}
	if victim != "" {
		delete(c.items, victim)
	}
}

// Len returns the current number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
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
