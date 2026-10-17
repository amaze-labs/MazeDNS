package resolver

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ProbeName is the reserved name every node answers itself, ahead of the whole
// pipeline (maintenance, rate limit, policy, cache, forward): A 127.0.0.1, TTL 0.
// It is never forwarded, counted or logged, so a readiness check or an external
// watchdog can tell "this resolver answers" apart from "upstreams/WAN are down".
const ProbeName = "probe.mazedns.internal."

// isProbe reports whether req asks for ProbeName.
func isProbe(req *dns.Msg) bool {
	return len(req.Question) == 1 && strings.EqualFold(req.Question[0].Name, ProbeName)
}

// probeResponse answers a ProbeName query: 127.0.0.1 for A, an empty NOERROR
// answer for any other type.
func probeResponse(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	if req.Question[0].Qtype == dns.TypeA {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   []byte{127, 0, 0, 1},
		})
	}
	return m
}

// Health is a point-in-time view of what the resolver last did. Zero times mean
// "never since start".
type Health struct {
	LastQuery        time.Time // last query answered (any action)
	LastForwardOK    time.Time // last successful upstream forward
	LastForwardError time.Time // last failed upstream forward
	ForwardError     string    // error of the last failed forward
}

// healthState holds the resolver's activity timestamps (unix ms). The success
// timestamps are written on the hot path, so they are refreshed at most once per
// healthResolution: a load (shared cache line) is cheap, a store from every core
// on every query is not.
type healthState struct {
	lastQuery    atomic.Int64
	lastFwdOK    atomic.Int64
	lastFwdErr   atomic.Int64
	lastFwdErrTx atomic.Pointer[string]
}

const healthResolution = time.Second

func touch(a *atomic.Int64, now time.Time) {
	ms := now.UnixMilli()
	if ms-a.Load() >= healthResolution.Milliseconds() {
		a.Store(ms)
	}
}

func (h *healthState) forwardFailed(err error) {
	msg := "no answer"
	if err != nil {
		msg = err.Error()
	}
	h.lastFwdErrTx.Store(&msg)
	h.lastFwdErr.Store(time.Now().UnixMilli())
}

func msTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// Health returns what the resolver last did: when it last answered a query, and
// when forwarding last succeeded and failed.
func (r *Resolver) Health() Health {
	h := Health{
		LastQuery:        msTime(r.health.lastQuery.Load()),
		LastForwardOK:    msTime(r.health.lastFwdOK.Load()),
		LastForwardError: msTime(r.health.lastFwdErr.Load()),
	}
	if p := r.health.lastFwdErrTx.Load(); p != nil {
		h.ForwardError = *p
	}
	return h
}
