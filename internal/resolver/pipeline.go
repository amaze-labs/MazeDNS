package resolver

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Stream upstreams (DoT, plain TCP) pipeline their queries: several are in
// flight on one connection at once, each under its own message ID, and a reader
// goroutine hands every answer to the query that asked (RFC 7766 §6.2.1.1,
// RFC 7858 §3.3).
//
// Before, a connection carried one query at a time, so a burst of cache misses
// opened a new connection — a TLS handshake, two or three extra round trips —
// for every query beyond the few warm ones: a 30-query burst to Cloudflare over
// DoT took 63ms (median) instead of 14ms. And opening many connections at once
// is what some resolvers (Quad9) answer by dropping a share of them, which
// surfaced as "forward failed … EOF" and a SERVFAIL to the client.
//
// How much a server lets share a connection varies: Cloudflare took 30 queries
// at once, while Quad9 closes the connection when more than two or three
// arrive together. So each upstream LEARNS its limit, like TCP congestion
// control: start at pipeStartInflight, double it while the server keeps up,
// then grow it by one; when the server drops a connection that had several
// queries in flight, halve it and stay below that level for pipeCeilingTTL.
// Connections are added as the open ones fill up — enough for about
// pipeCapacity queries in flight, so a server that won't share (Quad9 settles
// at one query per connection) gets as many connections as the old one-query
// pool had — opening at most pipeMaxDials at once. Past that, a query waits for
// a free slot rather than overloading the server.

const (
	pipeStartInflight = 2                // per-connection limit for a new upstream
	pipeMaxInflight   = 64               // the most a limit can grow to
	pipeCapacity      = 64               // queries in flight to aim for, per upstream
	pipeMinConns      = 8                // connections allowed whatever the limit
	pipeMaxDials      = 8                // connections being opened at once
	pipeDialBackoff   = time.Second      // after a failed dial with none open, fail fast this long
	pipeCeilingTTL    = 10 * time.Minute // how long a limit that failed is avoided
	// pipeDefaultTimeout is the per-query timeout when the upstream has none.
	pipeDefaultTimeout = 5 * time.Second
)

// pipeSuspectAfter is how long a connection may go without reading anything
// before a query on it gets only the short probe timeout: a server or NAT may
// have dropped it silently, and a query must not wait the full timeout to find
// out. The keep-warm query (every dotKeepaliveInterval) keeps a healthy idle
// connection under it. A variable for tests.
var pipeSuspectAfter = dotKeepaliveInterval + time.Second

// pipeAttempts bounds the tries for one query whose connection keeps being
// dropped. Quad9 drops reused connections as well as new ones now and then; the
// one-query pool before this got up to three tries (the pooled connection, then
// two fresh ones), and two measurably failed more queries.
const pipeAttempts = 3

var (
	errPipeClosed  = errors.New("connection closed")
	errPipeTimeout = fmt.Errorf("read: %w", os.ErrDeadlineExceeded) // "read: i/o timeout"
	errPipeBusy    = fmt.Errorf("upstream busy: %w", os.ErrDeadlineExceeded)
)

// pipePool holds the pipelined connections to one stream upstream.
type pipePool struct {
	addr   string
	client *dns.Client // dials (Net, TLS config); its Timeout is the per-query timeout
	probe  time.Duration

	mu        sync.Mutex
	conns     []*pipeConn
	dialing   int           // connections being opened
	dialErr   error         // the last dial's error, if it failed …
	dialErrAt time.Time     // … and when
	freed     chan struct{} // closed (and replaced) whenever a slot or connection frees up

	// The learned per-connection limit (see the file comment).
	limit        int
	learned      bool      // a drop was seen: grow by one, never double again
	grown        int       // successes at the limit since it last changed
	ceiling      int       // stay at or below this until ceilingUntil
	ceilingUntil time.Time //
}

func newPipePool(addr string, client *dns.Client) *pipePool {
	probe := dotProbeTimeout
	if t := client.Timeout; t > 0 && t < probe {
		probe = t
	}
	return &pipePool{addr: addr, client: client, probe: probe, freed: make(chan struct{}), limit: pipeStartInflight}
}

func (p *pipePool) timeout() time.Duration {
	if p.client.Timeout > 0 {
		return p.client.Timeout
	}
	return pipeDefaultTimeout
}

// exchange runs one query. A query whose connection is closed under it (EOF,
// reset — e.g. a server dropping connections under load) or that times out on a
// connection that had gone quiet is retried, up to pipeAttempts in all, on a
// live or new connection.
func (p *pipePool) exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	start := time.Now()
	deadline := start.Add(p.timeout())
	var err error
	for attempt := 0; attempt < pipeAttempts; attempt++ {
		c, fresh, atLimit, gerr := p.get(deadline)
		if gerr != nil {
			return nil, time.Since(start), gerr
		}
		timeout := time.Until(deadline)
		if attempt > 0 || timeout <= 0 {
			timeout = p.timeout() // a retry gets a full budget of its own
		}
		suspect := !fresh && c.quietFor() > pipeSuspectAfter
		if suspect && p.probe < timeout {
			timeout = p.probe
		}
		var resp *dns.Msg
		resp, err = c.exchange(req, timeout)
		timedOut := errors.Is(err, os.ErrDeadlineExceeded)
		if suspect && timedOut {
			c.fail(err) // silently dead: replace it
		}
		p.release(c, err == nil, atLimit, connDropped(err))
		if err == nil {
			return resp, time.Since(start), nil
		}
		if !(connDropped(err) || errors.Is(err, errPipeClosed) || (suspect && timedOut)) {
			break
		}
	}
	return nil, time.Since(start), err
}

// get reserves a slot for one query and returns its connection, whether that
// connection was just opened, and whether the query fills it to the limit. It
// prefers the least-loaded live connection, opens another only when all are at
// the limit, and when no more may be opened waits for a free slot until
// deadline.
func (p *pipePool) get(deadline time.Time) (*pipeConn, bool, bool, error) {
	for {
		p.mu.Lock()
		limit := p.limitLocked()
		best := p.leastLoadedLocked()
		if best != nil && best.load < limit {
			best.load++
			atLimit := best.load >= limit
			p.mu.Unlock()
			return best, false, atLimit, nil
		}
		if best == nil && p.dialErr != nil && p.dialing == 0 && time.Since(p.dialErrAt) < pipeDialBackoff {
			err := p.dialErr // unreachable just now: don't make every query wait on its own dial
			p.mu.Unlock()
			return nil, false, false, err
		}
		if len(p.conns)+p.dialing < p.maxConnsLocked(limit) && p.dialing < pipeMaxDials {
			p.dialing++
			p.mu.Unlock()
			c, err := p.dial()
			p.mu.Lock()
			p.dialing--
			p.signalLocked()
			if err == nil {
				p.dialErr = nil
				c.load = 1
				p.conns = append(p.conns, c)
				p.mu.Unlock()
				return c, true, limit <= 1, nil
			}
			p.dialErr, p.dialErrAt = err, time.Now()
			if len(p.conns) == 0 {
				p.mu.Unlock()
				return nil, false, false, err
			}
		}
		freed := p.freed
		p.mu.Unlock()
		wait := time.Until(deadline)
		if wait <= 0 {
			return nil, false, false, errPipeBusy
		}
		t := time.NewTimer(wait)
		select {
		case <-freed:
			t.Stop()
		case <-t.C:
			return nil, false, false, errPipeBusy
		}
	}
}

// maxConnsLocked is how many connections the upstream may have at this limit.
func (p *pipePool) maxConnsLocked(limit int) int {
	return max(pipeMinConns, min(pipeCapacity, pipeCapacity/max(1, limit)))
}

// signalLocked wakes the queries waiting for a slot.
func (p *pipePool) signalLocked() {
	close(p.freed)
	p.freed = make(chan struct{})
}

// release frees the query's slot and adjusts the learned limit: a success that
// filled a connection to the limit counts toward raising it; the server
// dropping a connection that had several queries in flight lowers it.
func (p *pipePool) release(c *pipeConn, ok, atLimit, dropped bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inflight := c.load
	c.load--
	p.signalLocked()

	if dropped && inflight >= 2 && !c.counted {
		c.counted = true // one adjustment per dropped connection
		p.learned = true
		p.limit = max(1, inflight/2)
		p.ceiling = max(1, inflight-1)
		p.ceilingUntil = time.Now().Add(pipeCeilingTTL)
		p.grown = 0
		return
	}
	if !ok || !atLimit {
		return
	}
	if p.grown++; p.grown < p.limit {
		return
	}
	p.grown = 0
	next := p.limit + 1
	if !p.learned {
		next = p.limit * 2
	}
	p.limit = min(next, p.maxLimitLocked())
}

// limitLocked is the current per-connection limit, within any active ceiling.
func (p *pipePool) limitLocked() int {
	return min(p.limit, p.maxLimitLocked())
}

func (p *pipePool) maxLimitLocked() int {
	if time.Now().Before(p.ceilingUntil) {
		return p.ceiling
	}
	return pipeMaxInflight
}

// leastLoadedLocked drops dead connections and closes idle ones that went quiet
// past dotIdleTimeout (likely dropped by the server or a NAT), then returns the
// live connection with the fewest queries in flight, or nil.
func (p *pipePool) leastLoadedLocked() *pipeConn {
	live := p.conns[:0]
	var best *pipeConn
	for _, c := range p.conns {
		if c.isDead() {
			continue
		}
		if c.load == 0 && c.quietFor() > dotIdleTimeout {
			c.fail(errPipeClosed)
			continue
		}
		live = append(live, c)
		if best == nil || c.load < best.load {
			best = c
		}
	}
	for i := len(live); i < len(p.conns); i++ {
		p.conns[i] = nil
	}
	p.conns = live
	return best
}

func (p *pipePool) dial() (*pipeConn, error) {
	conn, err := p.client.Dial(p.addr)
	if err != nil {
		return nil, err
	}
	c := &pipeConn{conn: conn, pending: make(map[uint16]chan *dns.Msg), nextID: uint16(rand.Uint32()), lastRead: time.Now()}
	go c.readLoop()
	return c, nil
}

// keepWarm keeps a live connection ready with a cheap query (also keeping the
// server's and any NAT's idle timers from closing it), opening one if needed.
func (p *pipePool) keepWarm() {
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeNS)
	_, _, _ = p.exchange(m)
}

// pipeConn is one pipelined stream connection.
type pipeConn struct {
	conn *dns.Conn
	wmu  sync.Mutex // serializes writes

	// Guarded by the pool's mu.
	load    int  // queries holding a slot on this connection
	counted bool // its drop already lowered the pool's limit

	mu       sync.Mutex
	pending  map[uint16]chan *dns.Msg // by wire message ID
	nextID   uint16
	dead     bool
	err      error
	lastRead time.Time // last answer read (or when opened)
}

func (c *pipeConn) isDead() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dead
}

func (c *pipeConn) quietFor() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.lastRead)
}

// exchange sends req under a message ID unique on this connection and waits for
// its answer. req is not modified; the answer carries req's original ID.
func (c *pipeConn) exchange(req *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	ch := make(chan *dns.Msg, 1)
	c.mu.Lock()
	if c.dead {
		err := c.err
		c.mu.Unlock()
		return nil, err
	}
	id := c.nextID
	for {
		if _, used := c.pending[id]; !used {
			break
		}
		id++
	}
	c.nextID = id + 1
	c.pending[id] = ch
	c.mu.Unlock()

	out := *req // shallow: packing doesn't modify a query
	out.Id = id
	c.wmu.Lock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(timeout))
	err := c.conn.WriteMsg(&out)
	c.wmu.Unlock()
	if err != nil {
		// Report why the connection failed (EOF, reset, closed by us), which may
		// predate this write, so the caller can tell a drop worth retrying.
		c.fail(err)
		c.mu.Lock()
		err = c.err
		c.mu.Unlock()
		return nil, err
	}

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case resp := <-ch:
		if resp == nil {
			c.mu.Lock()
			err := c.err
			c.mu.Unlock()
			return nil, err
		}
		resp.Id = req.Id
		return resp, nil
	case <-t.C:
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, errPipeTimeout
	}
}

// readLoop delivers each answer to the query waiting on its ID, until the
// connection fails or is closed.
func (c *pipeConn) readLoop() {
	for {
		m, err := c.conn.ReadMsg()
		if err != nil {
			c.fail(err)
			return
		}
		c.mu.Lock()
		ch, ok := c.pending[m.Id]
		delete(c.pending, m.Id)
		c.lastRead = time.Now()
		c.mu.Unlock()
		if ok {
			ch <- m // buffered: never blocks
		}
	}
}

// fail closes the connection and fails every query still waiting on it with err.
func (c *pipeConn) fail(err error) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		err = errPipeClosed
	}
	c.err = err
	pending := c.pending
	c.pending = make(map[uint16]chan *dns.Msg)
	c.mu.Unlock()
	_ = c.conn.Close()
	for _, ch := range pending {
		ch <- nil
	}
}
