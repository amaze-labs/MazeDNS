package resolver

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/cache"
)

// stalingUpstream returns an A answer with a fixed (short) TTL and counts calls.
// The small delay makes a refresh hold its per-name guard long enough that a
// burst of concurrent stale hits deterministically collapses to one refresh.
type stalingUpstream struct {
	calls atomic.Int32
	ttl   uint32
	delay time.Duration
}

func (u *stalingUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	u.calls.Add(1)
	if u.delay > 0 {
		time.Sleep(u.delay)
	}
	m := new(dns.Msg)
	m.SetReply(req)
	q := req.Question[0]
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: u.ttl},
		A:   net.IP{1, 2, 3, 4},
	})
	return m, time.Millisecond, nil
}
func (u *stalingUpstream) String() string { return "staling" }

// A stale cache hit is served immediately (action "cache") while exactly one
// background refresh hits the upstream — even under a burst of concurrent stale
// hits (the per-name refresh guard collapses them into one).
func TestServeStaleRefresh(t *testing.T) {
	r := New(Options{})
	ca := cache.New(100, 0, 0) // honor the record's own 1s TTL, no clamps
	up := &stalingUpstream{ttl: 1, delay: 50 * time.Millisecond}
	r.rt.Store(&runtime{defaultUpstreams: []Upstream{up}, blockMode: "nxdomain", cache: ca})

	query := func() string {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		_, action, _ := r.Resolve(req, "10.0.0.1")
		return action
	}
	waitForCalls := func(want int32) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for up.calls.Load() < want && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if got := up.calls.Load(); got != want {
			t.Fatalf("upstream calls=%d, want %d", got, want)
		}
	}
	// A refresh bumps the call counter mid-flight (in Exchange) but only releases
	// its per-name guard once fully done; wait for that before the next stale cycle
	// so a follow-up refresh isn't (correctly) suppressed by a still-running one.
	waitRefreshDone := func() {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			empty := true
			r.refreshing.Range(func(_, _ any) bool { empty = false; return false })
			if empty {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("background refresh did not release its guard")
	}

	// 1st query: miss -> forward -> cache.
	if a := query(); a != "forward" {
		t.Fatalf("first query action=%q, want forward", a)
	}
	waitForCalls(1)

	// Let it lapse into the serve-stale window.
	time.Sleep(1100 * time.Millisecond)

	// 2nd query: stale hit, served from cache immediately, triggers ONE refresh.
	if a := query(); a != "cache" {
		t.Fatalf("stale query action=%q, want cache", a)
	}
	waitForCalls(2)
	waitRefreshDone() // let the refresh fully settle before the next stale cycle

	// A burst of concurrent stale hits must cause only ONE more refresh.
	time.Sleep(1100 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); query() }()
	}
	wg.Wait()
	waitForCalls(3)
}
