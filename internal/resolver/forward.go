package resolver

import (
	"errors"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Upstream selection strategies (Settings.UpstreamStrategy).
const (
	// StrategyOrdered sends every query to the first upstream and moves to the
	// next one only when the current one times out (per-upstream timeout), fails
	// with a network error, or answers SERVFAIL/REFUSED. Upstreams are never
	// queried in parallel. This is the default, and what an empty/unknown value
	// means, so settings saved before the field existed resolve to it.
	StrategyOrdered = "ordered"
	// StrategyHedged queries the first upstream and, if it has not answered
	// within hedgeDelay (or fails), queries all the remaining ones in parallel;
	// the first valid answer wins. Lowest latency, but traffic is spread across
	// upstreams and the answering server is not predictable.
	StrategyHedged = "hedged"
)

// Per-upstream failover timeout bounds, in milliseconds (Settings.UpstreamTimeoutMs).
const (
	DefaultUpstreamTimeoutMs = 1500
	MinUpstreamTimeoutMs     = 100
	MaxUpstreamTimeoutMs     = 10000
)

var errUpstreamTimeout = errors.New("upstream timeout")

// NormalizeUpstreamStrategy returns the canonical strategy name: "hedged" when
// explicitly requested, otherwise "ordered" (including the empty value found in
// settings saved before the field existed).
func NormalizeUpstreamStrategy(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), StrategyHedged) {
		return StrategyHedged
	}
	return StrategyOrdered
}

// NormalizeUpstreamTimeoutMs returns ms clamped to the allowed range, with 0
// (unset) meaning DefaultUpstreamTimeoutMs.
func NormalizeUpstreamTimeoutMs(ms int) int {
	switch {
	case ms <= 0:
		return DefaultUpstreamTimeoutMs
	case ms < MinUpstreamTimeoutMs:
		return MinUpstreamTimeoutMs
	case ms > MaxUpstreamTimeoutMs:
		return MaxUpstreamTimeoutMs
	}
	return ms
}

// NormalizeUpstreams canonicalizes the upstream strategy and per-upstream
// timeout in place, so what is persisted and shown in the UI is explicit.
func (s *Settings) NormalizeUpstreams() {
	s.UpstreamStrategy = NormalizeUpstreamStrategy(s.UpstreamStrategy)
	s.UpstreamTimeoutMs = NormalizeUpstreamTimeoutMs(s.UpstreamTimeoutMs)
}

// softFailure reports whether an upstream response should make the resolver
// try the next upstream instead of returning it. SERVFAIL means the upstream
// could not resolve the name; REFUSED means it will not serve us (ACL, not
// recursive for us, rate limited) — in both cases another upstream may well
// answer. NXDOMAIN and NODATA are real answers and are returned as-is.
func softFailure(m *dns.Msg) bool {
	return m.Rcode == dns.RcodeServerFailure || m.Rcode == dns.RcodeRefused
}

// betterSoft picks which soft-failure response to return when every upstream
// failed: a SERVFAIL is preferred over a REFUSED, because a REFUSED relayed to
// the client would read as "this resolver refuses you".
func betterSoft(cur, next *dns.Msg) *dns.Msg {
	if cur == nil || (cur.Rcode != dns.RcodeServerFailure && next.Rcode == dns.RcodeServerFailure) {
		return next
	}
	return cur
}

// forward sends req to ups using the runtime's upstream strategy.
func (r *Resolver) forward(rt *runtime, req *dns.Msg, ups []Upstream) (*dns.Msg, time.Duration, error) {
	if rt.hedged {
		return r.forwardHedged(req, ups)
	}
	return r.forwardOrdered(req, ups, rt.upstreamTimeout)
}

// forwardOrdered implements strict ordered failover: upstream i+1 is queried
// only once upstream i has timed out (after per), failed with an error, or
// answered SERVFAIL/REFUSED. The last upstream gets whatever is left of the
// overall query budget (r.timeout), and no new upstream is started once that
// budget is spent. A late answer from an upstream we already moved on from is
// still accepted if it arrives first — it costs no extra traffic.
func (r *Resolver) forwardOrdered(req *dns.Msg, ups []Upstream, per time.Duration) (*dns.Msg, time.Duration, error) {
	if len(ups) == 0 {
		return nil, 0, errNoUpstreams
	}
	if len(ups) == 1 {
		return ups[0].Exchange(req)
	}
	if per <= 0 {
		per = time.Duration(DefaultUpstreamTimeoutMs) * time.Millisecond
	}

	type result struct {
		idx int
		msg *dns.Msg
		rtt time.Duration
		err error
	}
	// Buffered for every upstream so an abandoned exchange never blocks.
	results := make(chan result, len(ups))
	deadline := time.Now().Add(r.timeout)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	next, pending := 0, 0
	// advance starts the next upstream and arms the failover timer for it. It
	// returns false when there is no upstream left or the budget is spent.
	advance := func() bool {
		remaining := time.Until(deadline)
		if next >= len(ups) || remaining <= 0 {
			return false
		}
		wait := per
		if next == len(ups)-1 || wait > remaining {
			wait = remaining
		}
		i := next
		next++
		pending++
		// Each exchange gets its own copy so an abandoned one can never race a
		// later one on packing the shared message.
		q := req.Copy()
		go func() {
			msg, rtt, err := ups[i].Exchange(q)
			results <- result{i, msg, rtt, err}
		}()
		timer.Reset(wait)
		return true
	}

	var soft *dns.Msg // best soft-failure response so far
	var softRtt time.Duration
	var lastErr error
	finish := func() (*dns.Msg, time.Duration, error) {
		if soft != nil {
			return soft, softRtt, nil // everyone SERVFAILed/REFUSED — relay it.
		}
		if lastErr == nil {
			lastErr = errUpstreamTimeout
		}
		return nil, 0, lastErr
	}

	advance()
	for {
		select {
		case res := <-results:
			pending--
			if res.err == nil && res.msg != nil {
				if !softFailure(res.msg) {
					return res.msg, res.rtt, nil // a real answer (incl. NXDOMAIN) wins.
				}
				if b := betterSoft(soft, res.msg); b != soft {
					soft, softRtt = b, res.rtt
				}
			} else {
				lastErr = res.err
				if lastErr == nil {
					lastErr = errNoUpstreams
				}
			}
			if res.idx != next-1 {
				continue // an upstream we already moved on from; the current one is still running.
			}
			// The current upstream failed: fail over right away.
			if advance() {
				continue
			}
			if pending == 0 {
				return finish()
			}
			// Nothing left to start, but an earlier upstream may still answer
			// late: wait for it until the overall budget runs out.
			timer.Reset(time.Until(deadline))
		case <-timer.C:
			// The current upstream did not answer in time: move on.
			if !advance() {
				return finish()
			}
		}
	}
}

// hedgeDelay is how long the hedged strategy waits for the primary upstream
// before also querying the remaining upstreams in parallel. A healthy primary
// answers well within this window (so only one upstream is queried), while a
// slow or dead one fails over almost immediately instead of burning the full
// per-query timeout.
const hedgeDelay = 30 * time.Millisecond

func (r *Resolver) forwardHedged(req *dns.Msg, ups []Upstream) (*dns.Msg, time.Duration, error) {
	if len(ups) == 0 {
		return nil, 0, errNoUpstreams
	}
	if len(ups) == 1 {
		return ups[0].Exchange(req)
	}

	type result struct {
		msg *dns.Msg
		rtt time.Duration
		err error
	}
	results := make(chan result, len(ups))
	// Each goroutine exchanges against its own copy of the request so concurrent
	// packing can never race on the shared message.
	launch := func(u Upstream) {
		go func() {
			msg, rtt, err := u.Exchange(req.Copy())
			results <- result{msg, rtt, err}
		}()
	}

	launch(ups[0])
	hedge := time.NewTimer(hedgeDelay)
	defer hedge.Stop()

	pending := 1
	rest := ups[1:]
	var lastErr error
	var lastResp *dns.Msg // best response so far (a SERVFAIL we'd return if nothing better arrives)
	var lastRtt time.Duration
	launchRest := func() {
		for _, u := range rest {
			launch(u)
			pending++
		}
		rest = nil
		hedge.Stop()
	}
	for {
		select {
		case <-hedge.C:
			launchRest()
		case res := <-results:
			pending--
			switch {
			case res.err == nil && res.msg != nil && !softFailure(res.msg):
				return res.msg, res.rtt, nil // a real answer (incl. NXDOMAIN) wins.
			case res.err == nil && res.msg != nil:
				// SERVFAIL/REFUSED: a soft failure. Remember it, but try the other
				// upstreams — one of them may actually resolve the name.
				if b := betterSoft(lastResp, res.msg); b != lastResp {
					lastResp, lastRtt = b, res.rtt
				}
				launchRest()
			default:
				lastErr = res.err
				launchRest() // hard error before the hedge fired — query the rest now.
			}
			if pending == 0 {
				if lastResp != nil {
					return lastResp, lastRtt, nil // everyone failed softly — return that response.
				}
				if lastErr == nil {
					lastErr = errNoUpstreams
				}
				return nil, 0, lastErr
			}
		}
	}
}
