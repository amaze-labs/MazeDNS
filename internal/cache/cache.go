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
	mu       sync.Mutex
	items    map[string]entry
	maxItems int
	minTTL   time.Duration
	maxTTL   time.Duration
}

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

func keyFor(q dns.Question) string {
	var b strings.Builder
	b.WriteString(strconv.FormatUint(uint64(q.Qclass), 10))
	b.WriteByte('/')
	b.WriteString(strconv.FormatUint(uint64(q.Qtype), 10))
	b.WriteByte('/')
	b.WriteString(strings.ToLower(q.Name))
	return b.String()
}

// Get returns a cached reply for q (a copy, with TTLs decremented by the elapsed
// time) and true on a hit, or nil/false on a miss or expiry.
func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	k := keyFor(q)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[k]
	if !ok {
		return nil, false
	}
	now := time.Now()
	if now.After(e.expiresAt) {
		delete(c.items, k)
		return nil, false
	}
	remaining := uint32(e.expiresAt.Sub(now).Seconds())
	msg := e.msg.Copy()
	adjustTTL(msg, remaining)
	return msg, true
}

// Set stores msg as the cached reply for q. Empty/NXDOMAIN answers are
// negative-cached using the SOA minimum when present.
func (c *Cache) Set(q dns.Question, msg *dns.Msg) {
	if msg == nil {
		return
	}
	ttl := c.ttlFor(msg)
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[keyFor(q)]; !exists && len(c.items) >= c.maxItems {
		for k := range c.items { // simple eviction: drop one arbitrary entry
			delete(c.items, k)
			break
		}
	}
	c.items[keyFor(q)] = entry{
		msg:       msg.Copy(),
		expiresAt: time.Now().Add(ttl),
	}
}

// Len returns the current number of cached entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
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
