package resolver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// pipeAction is what the test server does with one query.
type pipeAction int

const (
	pipeAnswer    pipeAction = iota // answer (after the given delay)
	pipeClose                       // close the connection
	pipeIgnore                      // read it, never answer
	pipeCloseSoon                   // never answer; close the connection after the delay
)

// pipeServer is a DNS-over-TCP server that answers concurrently and out of
// order on each connection. decide picks, per query, what to do; conn is the
// 1-based connection number. It returns the address and the connection count.
func pipeServer(t *testing.T, decide func(conn int, q *dns.Msg) (pipeAction, time.Duration)) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return servePipe(t, ln, decide)
}

// pipeTLSServer is pipeServer over TLS (DoT), with a self-signed certificate.
func pipeTLSServer(t *testing.T, decide func(conn int, q *dns.Msg) (pipeAction, time.Duration)) (string, *atomic.Int32) {
	t.Helper()
	cert, _, err := TLSCert("", "")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	return servePipe(t, ln, decide)
}

func servePipe(t *testing.T, ln net.Listener, decide func(conn int, q *dns.Msg) (pipeAction, time.Duration)) (string, *atomic.Int32) {
	t.Cleanup(func() { ln.Close() })
	var conns atomic.Int32
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			n := int(conns.Add(1))
			go func(nc net.Conn) {
				defer nc.Close()
				dc := &dns.Conn{Conn: nc}
				var wmu sync.Mutex
				for {
					q, err := dc.ReadMsg()
					if err != nil {
						return
					}
					act, delay := decide(n, q)
					switch act {
					case pipeClose:
						nc.Close()
						return
					case pipeIgnore:
						continue
					case pipeCloseSoon:
						go func() { time.Sleep(delay); nc.Close() }()
						continue
					}
					go func(q *dns.Msg) {
						time.Sleep(delay)
						m := new(dns.Msg)
						m.SetReply(q)
						// Echo the name in the answer so a mixed-up reply is caught.
						rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN TXT \"" + q.Question[0].Name + "\"")
						m.Answer = append(m.Answer, rr)
						wmu.Lock()
						_ = dc.WriteMsg(m)
						wmu.Unlock()
					}(q)
				}
			}(nc)
		}
	}()
	return ln.Addr().String(), &conns
}

func pipeQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	return m
}

// checkAnswer fails unless resp is the answer to req (same ID, own name echoed).
func checkAnswer(t *testing.T, req, resp *dns.Msg) {
	t.Helper()
	if resp.Id != req.Id {
		t.Errorf("answer ID %d, want the query's %d", resp.Id, req.Id)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answer for %s: %v", req.Question[0].Name, resp.Answer)
	}
	if txt := resp.Answer[0].(*dns.TXT).Txt[0]; txt != req.Question[0].Name {
		t.Errorf("query %s got the answer for %s", req.Question[0].Name, txt)
	}
}

// burst sends n concurrent queries through u and returns how many failed. Every
// answer is checked against its own query.
func burst(t *testing.T, u Upstream, tag string, n int) int {
	t.Helper()
	var wg sync.WaitGroup
	var fails atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := pipeQuery(fmt.Sprintf("%s%d.example.", tag, i))
			req.Id = 7 // the same client ID on every query: the pool must not rely on it
			resp, _, err := u.Exchange(req)
			if err != nil {
				fails.Add(1)
				return
			}
			checkAnswer(t, req, resp)
		}(i)
	}
	wg.Wait()
	return int(fails.Load())
}

// Against a server that handles any amount of pipelining, the per-connection
// limit grows, so bursts end up sharing the existing connections: no new
// connection (no handshake) per query, and every query gets its own answer
// although the server replies out of order.
func TestPipelineLearnsToShareConnections(t *testing.T) {
	addr, conns := pipeServer(t, func(int, *dns.Msg) (pipeAction, time.Duration) {
		return pipeAnswer, time.Duration(rand.IntN(10)) * time.Millisecond
	})
	u := newPlain(addr, "tcp", 2*time.Second)
	for round := 0; round < 4; round++ {
		if f := burst(t, u, fmt.Sprintf("w%d-", round), 30); f != 0 {
			t.Fatalf("warm-up round %d: %d failed", round, f)
		}
	}
	before := conns.Load()
	if f := burst(t, u, "final-", 30); f != 0 {
		t.Fatalf("%d failed", f)
	}
	if n := conns.Load(); n != before {
		t.Errorf("connections: %d before the last burst, %d after; want no new ones", before, n)
	}
	u.pipe.mu.Lock()
	limit := u.pipe.limit
	u.pipe.mu.Unlock()
	if limit <= pipeStartInflight {
		t.Errorf("learned limit = %d, want it grown past the start (%d)", limit, pipeStartInflight)
	}
}

// Like Quad9: the server closes a connection that has more than two queries
// waiting at once. The pool learns to stay at or under that, after which a
// burst goes through without a single failure.
func TestPipelineLearnsServerLimit(t *testing.T) {
	var mu sync.Mutex
	waiting := map[int]int{} // per connection: read, not yet answered
	addr, _ := pipeServer(t, func(conn int, _ *dns.Msg) (pipeAction, time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		if waiting[conn] >= 2 {
			return pipeClose, 0
		}
		waiting[conn]++
		go func() {
			time.Sleep(4 * time.Millisecond) // answered at 5ms: the counter drops just before
			mu.Lock()
			waiting[conn]--
			mu.Unlock()
		}()
		return pipeAnswer, 5 * time.Millisecond
	})
	u := newPlain(addr, "tcp", 2*time.Second)
	for round := 0; round < 4; round++ {
		burst(t, u, fmt.Sprintf("l%d-", round), 30) // learning: a few may fail twice
	}
	for round := 0; round < 3; round++ {
		if f := burst(t, u, fmt.Sprintf("s%d-", round), 30); f != 0 {
			t.Errorf("after learning, round %d: %d of 30 failed", round, f)
		}
	}
}

// A burst larger than all connections can carry waits for free slots instead of
// failing or overloading the server.
func TestPipelineWaitsForFreeSlot(t *testing.T) {
	addr, conns := pipeServer(t, func(int, *dns.Msg) (pipeAction, time.Duration) {
		return pipeAnswer, 30 * time.Millisecond
	})
	u := newPlain(addr, "tcp", 2*time.Second)
	if f := burst(t, u, "big-", pipeCapacity*3); f != 0 {
		t.Fatalf("%d failed", f)
	}
	if n := int(conns.Load()); n > pipeCapacity {
		t.Errorf("connections = %d, want at most %d", n, pipeCapacity)
	}
}

// When the server closes a connection with queries in flight, each is retried
// once on a new connection and still answered.
func TestPipelineServerClosesWithQueriesInFlight(t *testing.T) {
	addr, conns := pipeServer(t, func(conn int, _ *dns.Msg) (pipeAction, time.Duration) {
		if conn == 1 {
			// Hold every query sent on the first connection, then drop it with
			// them all in flight.
			return pipeCloseSoon, 50 * time.Millisecond
		}
		return pipeAnswer, 0
	})
	u := newPlain(addr, "tcp", 2*time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := pipeQuery(fmt.Sprintf("c%d.example.", i))
			resp, _, err := u.Exchange(req)
			if err != nil {
				t.Errorf("c%d: %v", i, err)
				return
			}
			checkAnswer(t, req, resp)
		}(i)
	}
	wg.Wait()
	if n := conns.Load(); n < 2 {
		t.Errorf("connections = %d, want the dropped one replaced", n)
	}
}

// A connection that went quiet and no longer answers is given only the short
// probe timeout, then replaced: the query is answered on a new connection well
// before the full timeout.
func TestPipelineSilentConnReplaced(t *testing.T) {
	addr, conns := pipeServer(t, func(conn int, q *dns.Msg) (pipeAction, time.Duration) {
		if conn == 1 && q.Question[0].Name != "first.example." {
			return pipeIgnore, 0 // silently dead after the first answer
		}
		return pipeAnswer, 0
	})
	u := newPlain(addr, "tcp", 5*time.Second)
	u.pipe.probe = 100 * time.Millisecond
	if _, _, err := u.Exchange(pipeQuery("first.example.")); err != nil {
		t.Fatal(err)
	}

	old := pipeSuspectAfter
	pipeSuspectAfter = 0 // treat the connection as quiet right away
	t.Cleanup(func() { pipeSuspectAfter = old })

	start := time.Now()
	req := pipeQuery("second.example.")
	resp, _, err := u.Exchange(req)
	if err != nil {
		t.Fatal(err)
	}
	checkAnswer(t, req, resp)
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v: waited for the full timeout instead of the probe timeout", d)
	}
	if n := conns.Load(); n != 2 {
		t.Errorf("connections = %d, want 2", n)
	}
}

// A late answer (after its query timed out) is ignored, and the connection stays
// in use for the next query.
func TestPipelineLateAnswerIgnored(t *testing.T) {
	addr, conns := pipeServer(t, func(_ int, q *dns.Msg) (pipeAction, time.Duration) {
		if q.Question[0].Name == "slow.example." {
			return pipeAnswer, 300 * time.Millisecond
		}
		return pipeAnswer, 0
	})
	u := newPlain(addr, "tcp", 100*time.Millisecond)
	if _, _, err := u.Exchange(pipeQuery("slow.example.")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("slow query: err = %v, want a timeout", err)
	}
	time.Sleep(350 * time.Millisecond) // the late answer arrives meanwhile
	req := pipeQuery("next.example.")
	resp, _, err := u.Exchange(req)
	if err != nil {
		t.Fatal(err)
	}
	checkAnswer(t, req, resp)
	if n := conns.Load(); n != 1 {
		t.Errorf("connections = %d, want 1", n)
	}
}

// When the upstream can't be reached, a burst fails fast on the one shared dial
// instead of each query dialling (and waiting) in turn.
func TestPipelineDialFailureShared(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens: connection refused
	u := newPlain(addr, "tcp", time.Second)
	start := time.Now()
	var wg sync.WaitGroup
	var fails atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, _, err := u.Exchange(pipeQuery(fmt.Sprintf("d%d.example.", i))); err != nil {
				fails.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if fails.Load() != 20 {
		t.Errorf("failures = %d, want 20", fails.Load())
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("burst against a dead upstream took %v", d)
	}
}

// The query passed in is never modified (it can be shared by hedged upstreams).
func TestPipelineDoesNotModifyQuery(t *testing.T) {
	addr, _ := pipeServer(t, func(int, *dns.Msg) (pipeAction, time.Duration) { return pipeAnswer, 0 })
	u := newPlain(addr, "tcp", time.Second)
	req := pipeQuery("same.example.")
	req.Id = 4242
	before := req.String()
	if _, _, err := u.Exchange(req); err != nil {
		t.Fatal(err)
	}
	if req.Id != 4242 || req.String() != before {
		t.Errorf("query modified: %s", req)
	}
}

// DoT pipelines the same way: a burst shares a few TLS sessions (handshakes)
// instead of opening one per query.
func TestPipelineDoTBurstSharesOneSession(t *testing.T) {
	addr, conns := pipeTLSServer(t, func(int, *dns.Msg) (pipeAction, time.Duration) {
		return pipeAnswer, time.Duration(rand.IntN(10)) * time.Millisecond
	})
	up, err := ParseUpstream("tls://"+addr+"#mazedns", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	up.(*dotUpstream).pipe.client.TLSConfig.InsecureSkipVerify = true // self-signed test cert
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := pipeQuery(fmt.Sprintf("t%d.example.", i))
			resp, _, err := up.Exchange(req)
			if err != nil {
				t.Errorf("t%d: %v", i, err)
				return
			}
			checkAnswer(t, req, resp)
		}(i)
	}
	wg.Wait()
	if n := conns.Load(); n >= 30 {
		t.Errorf("TLS sessions = %d for 30 queries, want them shared", n)
	}
}

// The learned limit: doubles while the server keeps up, halves when it drops a
// connection that had several queries in flight, then only grows one step at a
// time and stays below the level that failed until the ceiling expires.
func TestPipelineLimitAdjusts(t *testing.T) {
	p := newPipePool("127.0.0.1:1", &dns.Client{Net: "tcp", Timeout: time.Second})
	c := &pipeConn{}
	succeedAtLimit := func(n int) {
		for i := 0; i < n; i++ {
			p.mu.Lock()
			c.load++
			p.mu.Unlock()
			p.release(c, true, true, false)
		}
	}
	limit := func() int {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.limitLocked()
	}

	if got := limit(); got != pipeStartInflight {
		t.Fatalf("start limit = %d, want %d", got, pipeStartInflight)
	}
	succeedAtLimit(2)
	if got := limit(); got != 4 {
		t.Fatalf("after 2 successes at the limit: %d, want doubled to 4", got)
	}

	// The server drops a connection carrying 4 queries.
	p.mu.Lock()
	c.load = 4
	p.mu.Unlock()
	p.release(c, false, false, true)
	if got := limit(); got != 2 {
		t.Fatalf("after a drop with 4 in flight: %d, want halved to 2", got)
	}
	c = &pipeConn{}
	succeedAtLimit(2)
	if got := limit(); got != 3 {
		t.Fatalf("after the drop, growth: %d, want +1 to 3", got)
	}
	succeedAtLimit(10)
	if got := limit(); got != 3 {
		t.Fatalf("ceiling: limit %d, want held at 3 (below the 4 that failed)", got)
	}

	// Once the ceiling expires it may grow again, one step at a time.
	p.mu.Lock()
	p.ceilingUntil = time.Now().Add(-time.Second)
	p.mu.Unlock()
	succeedAtLimit(3)
	if got := limit(); got != 4 {
		t.Fatalf("after the ceiling expired: %d, want +1 to 4", got)
	}

	// A connection dropped with a single query (a server refusing new
	// connections, not pipelining) doesn't lower the limit.
	p.mu.Lock()
	c2 := &pipeConn{load: 1}
	p.mu.Unlock()
	p.release(c2, false, false, true)
	if got := limit(); got != 4 {
		t.Fatalf("single-query drop changed the limit to %d", got)
	}
}
