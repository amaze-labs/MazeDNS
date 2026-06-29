package resolver

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Concurrent Do calls for one key collapse into a single fn invocation, and every
// caller receives that shared result.
func TestSingleflightCoalesces(t *testing.T) {
	var g singleflight
	var calls atomic.Int32
	const n = 50

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*dns.Msg, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			msg, _, _ := g.Do("k", func() (*dns.Msg, time.Duration, error) {
				calls.Add(1)
				time.Sleep(40 * time.Millisecond) // hold the slot so the others pile up
				return new(dns.Msg), 0, nil
			})
			results[i] = msg
		}(i)
	}
	close(start)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("fn called %d times, want 1 (coalesced)", got)
	}
	for i, m := range results {
		if m == nil {
			t.Fatalf("caller %d got a nil result", i)
		}
	}
}

// After a call completes, its key is released so a later call runs fn again.
func TestSingleflightReleasesKey(t *testing.T) {
	var g singleflight
	var calls atomic.Int32
	fn := func() (*dns.Msg, time.Duration, error) { calls.Add(1); return new(dns.Msg), 0, nil }
	g.Do("k", fn)
	g.Do("k", fn)
	if got := calls.Load(); got != 2 {
		t.Fatalf("sequential calls invoked fn %d times, want 2", got)
	}
}

// countingUpstream records how many times it is exchanged against.
type countingUpstream struct {
	fakeUpstream
	calls atomic.Int32
}

func (c *countingUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	c.calls.Add(1)
	return c.fakeUpstream.Exchange(req)
}

// Concurrent cache-miss resolves for the same question hit the upstream once, and
// each caller still gets its own response (correct Id from its own request).
func TestResolveCoalescesForwards(t *testing.T) {
	r := New(Options{})
	up := &countingUpstream{fakeUpstream: fakeUpstream{name: "up", delay: 40 * time.Millisecond}}
	r.rt.Store(&runtime{defaultUpstreams: []Upstream{up}, blockMode: "nxdomain"}) // no cache: every call forwards

	const n = 30
	start := make(chan struct{})
	var wg sync.WaitGroup
	ids := make([]uint16, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeA)
			req.Id = uint16(i + 1)
			<-start
			resp, action, _ := r.Resolve(req, "10.0.0.1")
			if action != "forward" {
				t.Errorf("action = %q, want forward", action)
				return
			}
			ids[i] = resp.Id
		}(i)
	}
	close(start)
	wg.Wait()

	if got := up.calls.Load(); got != 1 {
		t.Fatalf("upstream exchanged %d times, want 1 (coalesced)", got)
	}
	for i := 0; i < n; i++ {
		if ids[i] != uint16(i+1) {
			t.Fatalf("caller %d got Id %d; coalesced callers must get their own copy", i, ids[i])
		}
	}
}
