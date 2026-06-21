// Package resolver handles DNS queries: rewrite, then filter, then cache, then forward.
package resolver

import (
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/cache"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/metrics"
)

// RewriteRR is a single local record override.
type RewriteRR struct {
	Type  uint16
	Value string
}

// Policy is the live filtering/rewrite ruleset, swapped atomically on reload.
type Policy struct {
	Block    *filter.Engine         // domains to block (file lists + deny rules)
	Allow    *filter.Engine         // allow overrides (wins over Block)
	Rewrites map[string][]RewriteRR // normalized domain -> local records
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

// Options configures a Resolver. Cache may be nil to disable caching.
type Options struct {
	Upstreams     []string
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

// Resolver answers DNS queries.
type Resolver struct {
	upstreams []string
	cache     *cache.Cache
	blockMode string
	queryLog  bool
	metrics   *metrics.Metrics
	onQuery   func(QueryEvent)
	udp       *dns.Client
	tcp       *dns.Client
	stats     Stats
	pol       atomic.Pointer[Policy]
}

// New builds a Resolver. Call SetPolicy before serving to install filtering rules.
func New(opts Options) *Resolver {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ups := make([]string, 0, len(opts.Upstreams))
	for _, u := range opts.Upstreams {
		ups = append(ups, ensurePort(u))
	}
	mode := opts.BlockResponse
	if mode == "" {
		mode = "nxdomain"
	}
	r := &Resolver{
		upstreams: ups,
		cache:     opts.Cache,
		blockMode: mode,
		queryLog:  opts.QueryLog,
		metrics:   opts.Metrics,
		onQuery:   opts.OnQuery,
		udp:       &dns.Client{Net: "udp", Timeout: timeout},
		tcp:       &dns.Client{Net: "tcp", Timeout: timeout},
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

// Handle implements dns.Handler.
func (r *Resolver) Handle(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	r.stats.Total.Add(1)
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	client := clientIP(w.RemoteAddr())
	pol := r.pol.Load()
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// 1. Local rewrite.
	if rrs, ok := pol.Rewrites[name]; ok {
		if resp := r.rewriteResponse(req, q, rrs); resp != nil {
			r.stats.Rewritten.Add(1)
			r.finish(w, resp, q, client, "rewrite", start)
			return
		}
	}

	// 2. Block (unless explicitly allowed).
	if pol.Block.IsBlocked(q.Name) && !pol.Allow.IsBlocked(q.Name) {
		r.stats.Blocked.Add(1)
		r.finish(w, r.blockedResponse(req, q), q, client, "blocked", start)
		return
	}

	// 3. Cache.
	if r.cache != nil {
		if cached, ok := r.cache.Get(q); ok {
			cached.Id = req.Id
			r.stats.Cached.Add(1)
			r.finish(w, cached, q, client, "cache", start)
			return
		}
	}

	// 4. Forward upstream.
	resp, rtt, err := r.forward(req)
	if err != nil || resp == nil {
		r.stats.Errors.Add(1)
		slog.Warn("forward failed", "name", q.Name, "err", err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		r.finish(w, m, q, client, "error", start)
		return
	}
	r.stats.Forwarded.Add(1)
	if r.metrics != nil {
		r.metrics.UpstreamDuration.Observe(rtt.Seconds())
	}
	if r.cache != nil {
		r.cache.Set(q, resp)
	}
	resp.Id = req.Id
	r.finish(w, resp, q, client, "forward", start)
}

func (r *Resolver) finish(w dns.ResponseWriter, resp *dns.Msg, q dns.Question, client, action string, start time.Time) {
	_ = w.WriteMsg(resp)
	elapsed := time.Since(start)
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
			Action: action, Rcode: rcode, Elapsed: elapsed,
		})
	}
}

func (r *Resolver) forward(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	m := req.Copy()
	var lastErr error
	for _, up := range r.upstreams {
		resp, rtt, err := r.udp.Exchange(m, up)
		if err != nil {
			lastErr = err
			continue
		}
		if resp != nil && resp.Truncated {
			if tcpResp, trtt, terr := r.tcp.Exchange(m, up); terr == nil {
				return tcpResp, trtt, nil
			}
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

func ensurePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}
