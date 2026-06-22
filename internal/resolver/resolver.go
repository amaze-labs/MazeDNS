// Package resolver handles DNS queries: rate-limit, rewrite, filter, cache, forward.
package resolver

import (
	"errors"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/cache"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/metrics"
)

var errNoUpstreams = errors.New("no upstreams available")

// RewriteRR is a single local record override.
type RewriteRR struct {
	Type  uint16
	Value string
}

// Policy is the live filtering/rewrite ruleset, swapped atomically on reload.
type Policy struct {
	Block    *filter.Engine
	Allow    *filter.Engine
	Rewrites map[string][]RewriteRR
}

// QueryEvent is emitted for every handled query (for async logging).
type QueryEvent struct {
	TS      time.Time
	Client  string
	Name    string
	QType   string
	Action  string
	Rcode   string
	Elapsed time.Duration
}

// ForwardGroup routes a domain suffix to a specific set of upstreams (split-horizon).
type ForwardGroup struct {
	Suffix    string
	Upstreams []string
}

// Options configures a Resolver. Cache may be nil to disable caching.
type Options struct {
	Upstreams     []string
	Forwarders    []ForwardGroup
	RateLimitQPM  int
	Cache         *cache.Cache
	BlockResponse string // "nxdomain" | "zeroip"
	QueryLog      bool
	Timeout       time.Duration
	Metrics       *metrics.Metrics
	OnQuery       func(QueryEvent)
}

// Stats holds atomic query counters.
type Stats struct {
	Total     atomic.Uint64
	Blocked   atomic.Uint64
	Cached    atomic.Uint64
	Forwarded atomic.Uint64
	Rewritten atomic.Uint64
	Errors    atomic.Uint64
}

type condForward struct {
	suffix string
	ups    []Upstream
}

// Resolver answers DNS queries.
type Resolver struct {
	defaultUpstreams []Upstream
	conditional      []condForward
	cache            *cache.Cache
	blockMode        string
	queryLog         bool
	metrics          *metrics.Metrics
	onQuery          func(QueryEvent)
	rate             *rateLimiter
	stats            Stats
	pol              atomic.Pointer[Policy]
}

// New builds a Resolver. Call SetPolicy before serving to install filtering rules.
func New(opts Options) *Resolver {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	parseAll := func(specs []string) []Upstream {
		out := make([]Upstream, 0, len(specs))
		for _, s := range specs {
			u, err := ParseUpstream(s, timeout)
			if err != nil {
				slog.Warn("invalid upstream", "spec", s, "err", err)
				continue
			}
			out = append(out, u)
		}
		return out
	}

	cond := make([]condForward, 0, len(opts.Forwarders))
	for _, f := range opts.Forwarders {
		suffix := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(f.Suffix), "."))
		if suffix == "" {
			continue
		}
		cond = append(cond, condForward{suffix: suffix, ups: parseAll(f.Upstreams)})
	}
	// Most-specific (longest) suffix wins.
	sort.Slice(cond, func(i, j int) bool { return len(cond[i].suffix) > len(cond[j].suffix) })

	mode := opts.BlockResponse
	if mode == "" {
		mode = "nxdomain"
	}
	var rl *rateLimiter
	if opts.RateLimitQPM > 0 {
		rl = newRateLimiter(opts.RateLimitQPM)
	}

	r := &Resolver{
		defaultUpstreams: parseAll(opts.Upstreams),
		conditional:      cond,
		cache:            opts.Cache,
		blockMode:        mode,
		queryLog:         opts.QueryLog,
		metrics:          opts.Metrics,
		onQuery:          opts.OnQuery,
		rate:             rl,
	}
	r.pol.Store(&Policy{Block: filter.New(), Allow: filter.New(), Rewrites: map[string][]RewriteRR{}})
	return r
}

// SetPolicy atomically swaps the active filtering/rewrite policy.
func (r *Resolver) SetPolicy(p *Policy) {
	if p == nil {
		return
	}
	if p.Block == nil {
		p.Block = filter.New()
	}
	if p.Allow == nil {
		p.Allow = filter.New()
	}
	if p.Rewrites == nil {
		p.Rewrites = map[string][]RewriteRR{}
	}
	r.pol.Store(p)
}

// StatsSnapshot returns the current counter values.
func (r *Resolver) StatsSnapshot() (total, blocked, cached, forwarded, rewritten, errs uint64) {
	return r.stats.Total.Load(), r.stats.Blocked.Load(), r.stats.Cached.Load(),
		r.stats.Forwarded.Load(), r.stats.Rewritten.Load(), r.stats.Errors.Load()
}

// CacheLen returns the number of cached entries (0 if caching is disabled).
func (r *Resolver) CacheLen() int {
	if r.cache == nil {
		return 0
	}
	return r.cache.Len()
}

// Handle implements dns.Handler (UDP/TCP/DoT).
func (r *Resolver) Handle(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	client := clientIP(w.RemoteAddr())
	resp, action := r.Resolve(req, client)
	_ = w.WriteMsg(resp)
	r.record(req, resp, action, client, start)
}

// Resolve runs the full pipeline and returns the response message and the action
// taken ("rewrite", "blocked", "cache", "forward", "refused", "error"). It does
// not write or log — callers (UDP/TCP, DoH) do that via record.
func (r *Resolver) Resolve(req *dns.Msg, client string) (*dns.Msg, string) {
	r.stats.Total.Add(1)
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		return m, "error"
	}
	q := req.Question[0]

	if r.rate != nil && !r.rate.allow(client) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		return m, "refused"
	}

	pol := r.pol.Load()
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	if rrs, ok := pol.Rewrites[name]; ok {
		if resp := r.rewriteResponse(req, q, rrs); resp != nil {
			r.stats.Rewritten.Add(1)
			return resp, "rewrite"
		}
	}

	if pol.Block.IsBlocked(q.Name) && !pol.Allow.IsBlocked(q.Name) {
		r.stats.Blocked.Add(1)
		return r.blockedResponse(req, q), "blocked"
	}

	if r.cache != nil {
		if cached, ok := r.cache.Get(q); ok {
			cached.Id = req.Id
			r.stats.Cached.Add(1)
			return cached, "cache"
		}
	}

	resp, rtt, err := r.forward(req, r.upstreamsFor(name))
	if err != nil || resp == nil {
		r.stats.Errors.Add(1)
		slog.Warn("forward failed", "name", q.Name, "err", err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m, "error"
	}
	r.stats.Forwarded.Add(1)
	if r.metrics != nil {
		r.metrics.UpstreamDuration.Observe(rtt.Seconds())
	}
	if r.cache != nil {
		r.cache.Set(q, resp)
	}
	resp.Id = req.Id
	return resp, "forward"
}

func (r *Resolver) record(req, resp *dns.Msg, action, client string, start time.Time) {
	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	rcode := dns.RcodeToString[resp.Rcode]
	if r.metrics != nil {
		r.metrics.Queries.WithLabelValues(action).Inc()
	}
	if r.queryLog {
		slog.Info("query", "name", q.Name, "type", dns.TypeToString[q.Qtype],
			"action", action, "rcode", rcode, "client", client)
	}
	if r.onQuery != nil {
		r.onQuery(QueryEvent{
			TS: start, Client: client, Name: q.Name, QType: dns.TypeToString[q.Qtype],
			Action: action, Rcode: rcode, Elapsed: time.Since(start),
		})
	}
}

func (r *Resolver) upstreamsFor(name string) []Upstream {
	for _, cf := range r.conditional {
		if (name == cf.suffix || strings.HasSuffix(name, "."+cf.suffix)) && len(cf.ups) > 0 {
			return cf.ups
		}
	}
	return r.defaultUpstreams
}

func (r *Resolver) forward(req *dns.Msg, ups []Upstream) (*dns.Msg, time.Duration, error) {
	if len(ups) == 0 {
		return nil, 0, errNoUpstreams
	}
	var lastErr error
	for _, u := range ups {
		resp, rtt, err := u.Exchange(req)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, rtt, nil
	}
	return nil, 0, lastErr
}

func (r *Resolver) rewriteResponse(req *dns.Msg, q dns.Question, rrs []RewriteRR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	matched := false
	for _, rr := range rrs {
		if rr.Type != q.Qtype {
			continue
		}
		switch rr.Type {
		case dns.TypeA:
			if ip := net.ParseIP(rr.Value); ip != nil && ip.To4() != nil {
				m.Answer = append(m.Answer, &dns.A{Hdr: rrHeader(q.Name, dns.TypeA), A: ip.To4()})
				matched = true
			}
		case dns.TypeAAAA:
			if ip := net.ParseIP(rr.Value); ip != nil {
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: rrHeader(q.Name, dns.TypeAAAA), AAAA: ip})
				matched = true
			}
		case dns.TypeCNAME:
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: rrHeader(q.Name, dns.TypeCNAME), Target: dns.Fqdn(rr.Value)})
			matched = true
		}
	}
	if !matched {
		return nil
	}
	return m
}

func (r *Resolver) blockedResponse(req *dns.Msg, q dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	if r.blockMode == "zeroip" {
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: rrHeader(q.Name, dns.TypeA), A: net.IPv4zero})
			return m
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: rrHeader(q.Name, dns.TypeAAAA), AAAA: net.IPv6zero})
			return m
		}
	}
	m.Rcode = dns.RcodeNameError // NXDOMAIN
	return m
}

func rrHeader(name string, t uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: 300}
}

func clientIP(a net.Addr) string {
	if a == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return host
	}
	return a.String()
}
