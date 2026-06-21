// Package resolver handles DNS queries: filter, then cache, then forward upstream.
package resolver

import (
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/cache"
	"github.com/IPMaze/MazeDNS/internal/filter"
)

// Options configures a Resolver. Cache and Filter may be nil to disable them.
type Options struct {
	Upstreams     []string
	Cache         *cache.Cache
	Filter        *filter.Engine
	BlockResponse string // "nxdomain" | "zeroip"
	QueryLog      bool
	Timeout       time.Duration
}

// Stats holds atomic query counters.
type Stats struct {
	Total     atomic.Uint64
	Blocked   atomic.Uint64
	Cached    atomic.Uint64
	Forwarded atomic.Uint64
	Errors    atomic.Uint64
}

// Resolver answers DNS queries.
type Resolver struct {
	upstreams []string
	cache     *cache.Cache
	filter    *filter.Engine
	blockMode string
	queryLog  bool
	udp       *dns.Client
	tcp       *dns.Client
	stats     Stats
}

// New builds a Resolver from opts.
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
	return &Resolver{
		upstreams: ups,
		cache:     opts.Cache,
		filter:    opts.Filter,
		blockMode: mode,
		queryLog:  opts.QueryLog,
		udp:       &dns.Client{Net: "udp", Timeout: timeout},
		tcp:       &dns.Client{Net: "tcp", Timeout: timeout},
	}
}

// StatsSnapshot returns the current counter values.
func (r *Resolver) StatsSnapshot() (total, blocked, cached, forwarded, errs uint64) {
	return r.stats.Total.Load(), r.stats.Blocked.Load(), r.stats.Cached.Load(),
		r.stats.Forwarded.Load(), r.stats.Errors.Load()
}

// Handle implements dns.Handler: filter → cache → forward.
func (r *Resolver) Handle(w dns.ResponseWriter, req *dns.Msg) {
	r.stats.Total.Add(1)
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]

	if r.filter != nil && r.filter.IsBlocked(q.Name) {
		r.stats.Blocked.Add(1)
		r.logQuery(q, "blocked", "")
		_ = w.WriteMsg(r.blockedResponse(req, q))
		return
	}

	if r.cache != nil {
		if cached, ok := r.cache.Get(q); ok {
			cached.Id = req.Id
			r.stats.Cached.Add(1)
			r.logQuery(q, "cache", dns.RcodeToString[cached.Rcode])
			_ = w.WriteMsg(cached)
			return
		}
	}

	resp, err := r.forward(req)
	if err != nil || resp == nil {
		r.stats.Errors.Add(1)
		slog.Warn("forward failed", "name", q.Name, "err", err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	r.stats.Forwarded.Add(1)
	if r.cache != nil {
		r.cache.Set(q, resp)
	}
	r.logQuery(q, "forward", dns.RcodeToString[resp.Rcode])
	resp.Id = req.Id
	_ = w.WriteMsg(resp)
}

func (r *Resolver) forward(req *dns.Msg) (*dns.Msg, error) {
	m := req.Copy()
	var lastErr error
	for _, up := range r.upstreams {
		resp, _, err := r.udp.Exchange(m, up)
		if err != nil {
			lastErr = err
			continue
		}
		if resp != nil && resp.Truncated {
			if tcpResp, _, terr := r.tcp.Exchange(m, up); terr == nil {
				return tcpResp, nil
			}
		}
		return resp, nil
	}
	return nil, lastErr
}

func (r *Resolver) blockedResponse(req *dns.Msg, q dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	if r.blockMode == "zeroip" {
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
				A:   net.IPv4zero,
			})
			return m
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10},
				AAAA: net.IPv6zero,
			})
			return m
		}
	}
	m.Rcode = dns.RcodeNameError // NXDOMAIN
	return m
}

func (r *Resolver) logQuery(q dns.Question, action, rcode string) {
	if !r.queryLog {
		return
	}
	slog.Info("query",
		"name", q.Name, "type", dns.TypeToString[q.Qtype], "action", action, "rcode", rcode)
}

func ensurePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}
