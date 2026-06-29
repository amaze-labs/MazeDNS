package resolver

import (
	"strconv"
	"strings"
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
// singleflight), kept in-package to avoid a new dependency.
type singleflight struct {
	mu sync.Mutex
	m  map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	msg *dns.Msg
	rtt time.Duration
	err error
}

// Do runs fn for key, deduplicating concurrent calls. The returned *dns.Msg is
// shared with other waiters, so callers MUST treat it as read-only (copy before
// mutating).
func (g *singleflight) Do(key string, fn func() (*dns.Msg, time.Duration, error)) (*dns.Msg, time.Duration, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*sfCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.msg, c.rtt, c.err
	}
	c := &sfCall{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.msg, c.rtt, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.msg, c.rtt, c.err
}

// forwardKey identifies a forward request the same way the cache keys an entry
// (class/type/name + DNSSEC variant), so coalescing matches caching semantics.
func forwardKey(q dns.Question, do bool) string {
	var b strings.Builder
	if do {
		b.WriteByte('+')
	}
	b.WriteString(strconv.FormatUint(uint64(q.Qclass), 10))
	b.WriteByte('/')
	b.WriteString(strconv.FormatUint(uint64(q.Qtype), 10))
	b.WriteByte('/')
	b.WriteString(strings.ToLower(q.Name))
	return b.String()
}
