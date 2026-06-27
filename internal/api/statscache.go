package api

import (
	"net/http"
	"sync"
	"time"
)

// statsTTL is how long windowed dashboard aggregations are cached. The dashboard
// polls every few seconds and several widgets request the same (window, nodes)
// slice; caching the computed JSON for this long coalesces that load and keeps a
// busy resolver's query_log aggregations from being recomputed on every poll,
// while staying fresh enough for a live dashboard.
const statsTTL = 10 * time.Second

// ttlCache is a tiny in-memory cache of marshaled JSON responses, keyed by the
// full request URI (which encodes hours + node filter).
type ttlCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cacheEntry
}

type cacheEntry struct {
	body []byte
	exp  time.Time
}

func newTTLCache(ttl time.Duration) *ttlCache {
	return &ttlCache{ttl: ttl, m: make(map[string]cacheEntry)}
}

func (c *ttlCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.body, true
}

func (c *ttlCache) set(key string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Drop expired entries opportunistically so the map can't grow unbounded as
	// node-filter combinations come and go.
	now := time.Now()
	if len(c.m) > 256 {
		for k, e := range c.m {
			if now.After(e.exp) {
				delete(c.m, k)
			}
		}
	}
	c.m[key] = cacheEntry{body: body, exp: now.Add(c.ttl)}
}

// cached wraps a JSON GET handler so identical (URI) requests within the TTL are
// served from memory. Only 200 responses are cached.
func (s *Server) cached(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.RequestURI()
		if body, ok := s.statsCache.get(key); ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "hit")
			_, _ = w.Write(body)
			return
		}
		rec := &bufferingWriter{header: make(http.Header), status: http.StatusOK}
		next(rec, r)
		// Mirror captured headers, then the body, to the real writer.
		for k, vs := range rec.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rec.status)
		_, _ = w.Write(rec.buf)
		if rec.status == http.StatusOK {
			s.statsCache.set(key, rec.buf)
		}
	}
}

// bufferingWriter captures a handler's response so it can be cached and replayed.
type bufferingWriter struct {
	header http.Header
	status int
	buf    []byte
}

func (b *bufferingWriter) Header() http.Header  { return b.header }
func (b *bufferingWriter) WriteHeader(code int) { b.status = code }
func (b *bufferingWriter) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}
