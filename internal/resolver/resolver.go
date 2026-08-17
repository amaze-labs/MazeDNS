// Package resolver handles DNS queries: rate-limit, authoritative zones, rewrite,
// filter, cache, forward. Operational settings (upstreams, forwarders, cache,
// rate-limit, block mode, DNSSEC) are held in a runtime that is swapped
// atomically via ApplySettings, so they can be changed live from the UI.
package resolver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
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
	// Wildcards holds records for "*.suffix" rewrites, keyed by suffix (the part
	// after "*."). They match any strict subdomain of the suffix; the most
	// specific suffix wins. The suffix apex itself is not matched (add an exact
	// rewrite for that).
	Wildcards map[string][]RewriteRR
}

// lookupRewrite returns the rewrite records for name: an exact match first, then
// the most specific wildcard ("*.suffix") whose suffix is a parent of name. The
// returned wildSuffix is the matched wildcard's suffix, or "" for an exact match.
func (p *Policy) lookupRewrite(name string) (rrs []RewriteRR, wildSuffix string, ok bool) {
	if rrs, ok := p.Rewrites[name]; ok {
		return rrs, "", true
	}
	if len(p.Wildcards) == 0 {
		return nil, "", false
	}
	// Walk parent suffixes, most specific first: a.b.c -> b.c -> c.
	for rest := name; ; {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			break
		}
		rest = rest[i+1:]
		if rrs, ok := p.Wildcards[rest]; ok {
			return rrs, rest, true
		}
	}
	return nil, "", false
}

// QueryEvent is emitted for every handled query (for async logging).
type QueryEvent struct {
	TS       time.Time
	Client   string
	Name     string
	QType    string
	Action   string
	Category string
	Rcode    string
	Elapsed  time.Duration
}

// ForwardGroup routes a domain suffix to a specific set of upstreams (split-horizon).
type ForwardGroup struct {
	Suffix    string   `json:"suffix"`
	Upstreams []string `json:"upstreams"`
}

// CacheSettings configures the response cache.
type CacheSettings struct {
	Enabled    bool `json:"enabled"`
	MaxEntries int  `json:"max_entries"`
	MinTTLSec  int  `json:"min_ttl_sec"`
	MaxTTLSec  int  `json:"max_ttl_sec"`
}

// Settings is the operational, UI-editable configuration applied at runtime.
type Settings struct {
	Upstreams     []string       `json:"upstreams"`
	Forwarders    []ForwardGroup `json:"forwarders"`
	BlockResponse string         `json:"block_response"` // "nxdomain" | "zeroip"
	RateLimitQPM  int            `json:"rate_limit_qpm"` // 0 = off
	DNSSEC        bool           `json:"dnssec"`
	Cache         CacheSettings  `json:"cache"`
}

// Options holds the static (non-UI-editable) resolver configuration.
type Options struct {
	Timeout  time.Duration
	Zones    []ZoneSpec
	QueryLog bool
	Metrics  *metrics.Metrics
	// OnQuery is called synchronously once per handled query. The *QueryEvent is
	// pooled and reused after the call returns, so OnQuery must not retain the
	// pointer — copy out whatever fields it needs (e.g. into a queue entry) before
	// returning.
	OnQuery func(*QueryEvent)
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
	suffix    string
	dotSuffix string // "." + suffix, precomputed for subdomain matching on the hot path
	ups       []Upstream
}

// runtime is the swappable operational state derived from Settings.
type runtime struct {
	defaultUpstreams []Upstream
	conditional      []condForward
	rate             *rateLimiter
	blockMode        string
	forceDNSSEC      bool
	cache            *cache.Cache
}

// Resolver answers DNS queries.
type Resolver struct {
	timeout  time.Duration
	zones    *Zones
	queryLog bool
	metrics  *metrics.Metrics
	onQuery  func(*QueryEvent)
	stats    Stats
	rt       atomic.Pointer[runtime]
	pol      atomic.Pointer[Policy]
	// sf coalesces concurrent cache-miss forwards for the same question.
	sf singleflight
	// refreshing tracks serve-stale background refreshes in flight, keyed by the
	// forward key, so a stale name is refreshed by exactly one goroutine.
	refreshing sync.Map
	// pauseUntil is the unix time until which blocking is suspended (0 = active).
	pauseUntil atomic.Int64
	// maintenance, when set, drains this node: every query is answered SERVFAIL so
	// clients fail over to another DNS server.
	maintenance atomic.Bool
	// controlPlaneOnly, when set (master only), makes this node a control plane that
	// serves no DNS: every query is answered REFUSED. Distinct from maintenance — it
	// is a deliberate role, not a temporary drain.
	controlPlaneOnly atomic.Bool
}

// SetMaintenance toggles maintenance (drain) mode for this node. While on, every
// DNS query is answered with SERVFAIL so clients move to another server.
func (r *Resolver) SetMaintenance(on bool) { r.maintenance.Store(on) }

// InMaintenance reports whether this node is draining (answering SERVFAIL).
func (r *Resolver) InMaintenance() bool { return r.maintenance.Load() }

// SetControlPlaneOnly toggles control-plane-only mode (master only). While on,
// every DNS query is answered REFUSED so this node serves only the cluster
// control plane (config, dashboard, enrollment) and not DNS.
func (r *Resolver) SetControlPlaneOnly(on bool) { r.controlPlaneOnly.Store(on) }

// ControlPlaneOnly reports whether this node serves no DNS (answering REFUSED).
func (r *Resolver) ControlPlaneOnly() bool { return r.controlPlaneOnly.Load() }

// SetBlockPausedUntil suspends block enforcement until ts (unix seconds); 0
// resumes immediately. Allow/rewrite/cache/forward are unaffected.
func (r *Resolver) SetBlockPausedUntil(ts int64) { r.pauseUntil.Store(ts) }

// BlockPaused reports whether block enforcement is currently suspended.
func (r *Resolver) BlockPaused() bool { return r.pauseUntil.Load() > time.Now().Unix() }

// New builds a Resolver with empty operational settings — call ApplySettings to
// install upstreams/cache/etc., and SetPolicy to install filtering rules.
func New(opts Options) *Resolver {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	r := &Resolver{
		timeout:  timeout,
		zones:    NewZones(opts.Zones),
		queryLog: opts.QueryLog,
		metrics:  opts.Metrics,
		onQuery:  opts.OnQuery,
	}
	r.rt.Store(&runtime{blockMode: "nxdomain"})
	r.pol.Store(&Policy{Block: filter.New(), Allow: filter.New(), Rewrites: map[string][]RewriteRR{}})
	return r
}

func (r *Resolver) parseUpstreams(specs []string) []Upstream {
	out := make([]Upstream, 0, len(specs))
	for _, s := range specs {
		u, err := ParseUpstream(s, r.timeout)
		if err != nil {
			slog.Warn("invalid upstream", "spec", s, "err", err)
			continue
		}
		// Let plain upstreams report truncation/TCP-fallback to metrics.
		if pu, ok := u.(*plainUpstream); ok {
			pu.metrics = r.metrics
		}
		out = append(out, u)
	}
	return out
}

// ApplySettings rebuilds and atomically swaps the operational runtime.
func (r *Resolver) ApplySettings(s Settings) {
	mode := s.BlockResponse
	if mode != "zeroip" {
		mode = "nxdomain"
	}
	rt := &runtime{
		defaultUpstreams: r.parseUpstreams(s.Upstreams),
		blockMode:        mode,
		forceDNSSEC:      s.DNSSEC,
	}
	for _, f := range s.Forwarders {
		suffix := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(f.Suffix), "."))
		if suffix == "" {
			continue
		}
		rt.conditional = append(rt.conditional, condForward{suffix: suffix, dotSuffix: "." + suffix, ups: r.parseUpstreams(f.Upstreams)})
	}
	sort.Slice(rt.conditional, func(i, j int) bool { return len(rt.conditional[i].suffix) > len(rt.conditional[j].suffix) })
	if s.RateLimitQPM > 0 {
		rt.rate = newRateLimiter(s.RateLimitQPM)
	}
	if s.Cache.Enabled {
		rt.cache = cache.New(s.Cache.MaxEntries,
			time.Duration(s.Cache.MinTTLSec)*time.Second, time.Duration(s.Cache.MaxTTLSec)*time.Second)
	}
	r.rt.Store(rt)
	slog.Info("settings applied", "upstreams", len(rt.defaultUpstreams), "forwarders", len(rt.conditional),
		"block", rt.blockMode, "ratelimit", s.RateLimitQPM, "dnssec", s.DNSSEC, "cache", s.Cache.Enabled)
}

// MaintainUpstreams keeps DoT upstream connections warm so a cache miss on a
// low-traffic node doesn't pay a TLS handshake (which roughly doubles forward
// latency). It always reads the current runtime, so it follows live settings
// changes — upstreams dropped by ApplySettings simply stop being warmed and are
// garbage-collected. Runs until ctx is cancelled; start it once after New.
func (r *Resolver) MaintainUpstreams(ctx context.Context) {
	t := time.NewTicker(dotKeepaliveInterval)
	defer t.Stop()
	warm := func(ups []Upstream) {
		for _, u := range ups {
			if w, ok := u.(warmer); ok {
				go w.keepWarm() // independent so one slow/dead upstream can't delay the others
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rt := r.rt.Load()
			warm(rt.defaultUpstreams)
			for _, cf := range rt.conditional {
				warm(cf.ups)
			}
		}
	}
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
	if p.Wildcards == nil {
		p.Wildcards = map[string][]RewriteRR{}
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
	if c := r.rt.Load().cache; c != nil {
		return c.Len()
	}
	return 0
}

// Handle implements dns.Handler (UDP/TCP/DoT).
func (r *Resolver) Handle(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	client := clientIP(w.RemoteAddr())

	// Control-plane-only (master): this node serves no DNS by design, so answer
	// REFUSED — a clear "not a resolver" signal that makes clients use another server.
	if r.ControlPlaneOnly() {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	// Maintenance/drain: answer SERVFAIL so clients fail over to another DNS server.
	// Done before any pipeline work, and not logged, to keep a drained node quiet.
	if r.InMaintenance() {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	// Capture the client's DNSSEC intent BEFORE resolving, because the forward path
	// may add the DO bit to req when DNSSEC is forced upstream — which would
	// otherwise mask what the client actually asked.
	clientEDNS := req.IsEdns0() != nil
	clientDO := false
	if o := req.IsEdns0(); o != nil {
		clientDO = o.Do()
	}

	resp, action, category := r.Resolve(req, client)
	r.finalize(resp, clientEDNS, clientDO)
	// Cap UDP replies at the fragmentation-safe size (1232). Answers up to that —
	// the vast majority — go out untouched in a single datagram; only genuinely
	// large ones (e.g. DNSSEC-signed) get the TC bit so the client retries over
	// TCP, avoiding fragmented datagrams that NATs/firewalls silently drop.
	//
	// We deliberately do NOT truncate down to the client's advertised buffer: a
	// client that sends no EDNS advertises only 512, but a sub-1232 datagram is a
	// single unfragmented packet every client receives fine — TC'ing it would force
	// a needless extra TCP round-trip on every medium-sized answer (a big latency
	// hit). 1232 is also under typical VPN/tunnel MTUs, so it won't fragment there.
	if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
		resp.Truncate(largeUDPSize)
	}
	_ = w.WriteMsg(resp)
	r.record(req, resp, action, category, client, start)
}

// Resolve runs the full pipeline and returns the response, the action taken, and
// the block category (only set for "blocked").
func (r *Resolver) Resolve(req *dns.Msg, client string) (*dns.Msg, string, string) {
	r.stats.Total.Add(1)
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		return m, "error", ""
	}
	q := req.Question[0]
	rt := r.rt.Load()

	if rt.rate != nil && !rt.rate.allow(client) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		return m, "refused", ""
	}

	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// 1. Authoritative zones we own (answered locally, never forwarded).
	if z := r.zones.match(name); z != nil {
		return z.answer(req, q, name), "authoritative", ""
	}

	pol := r.pol.Load()

	// 2. Local rewrite (exact match, then "*.suffix" wildcard). A wildcard match
	// yields to a conditional forwarder whose suffix matches name more
	// specifically (e.g. forwarder "ha.corp.example" beats rewrite
	// "*.corp.example" for names under ha.corp.example); an exact rewrite always
	// wins. Both suffixes sit on label boundaries of the same name, so the longer
	// string is the more specific one.
	if rrs, wildSuffix, ok := pol.lookupRewrite(name); ok {
		override := false
		if wildSuffix != "" {
			if cf, ok := conditionalFor(rt, name); ok && len(cf.suffix) > len(wildSuffix) {
				override = true
			}
		}
		if !override {
			if resp := r.rewriteResponse(req, q, rrs); resp != nil {
				r.stats.Rewritten.Add(1)
				return resp, "rewrite", ""
			}
		}
	}

	// 3. Block (unless explicitly allowed, or block enforcement is paused). Uses the
	// already-normalized name so the matcher doesn't re-lowercase q.Name twice.
	if !r.BlockPaused() {
		if cat, blocked := pol.Block.MatchNormalized(name); blocked && !pol.Allow.IsBlockedNormalized(name) {
			r.stats.Blocked.Add(1)
			return r.blockedResponse(req, q, rt.blockMode), "blocked", cat
		}
	}

	// Whether this query wants the DNSSEC-signed answer: either the client asked
	// (DO bit) or we're forcing validation upstream. Signed and unsigned answers
	// are cached under separate keys so a client never gets the wrong variant.
	wantSigned := rt.forceDNSSEC
	if o := req.IsEdns0(); o != nil && o.Do() {
		wantSigned = true
	}

	// 4. Cache. The hit is served immediately; refresh is true when the cache wants
	// a background re-fetch — either a stale (serve-stale) hit or a still-fresh
	// entry in the last tenth of its TTL (refresh-ahead) — so hot names are renewed
	// off the client's latency path before they expire.
	if rt.cache != nil {
		if cached, ok, refresh := rt.cache.Get(q, wantSigned); ok {
			cached.Id = req.Id
			r.stats.Cached.Add(1)
			if refresh {
				r.refreshStale(rt, req, q, name, wantSigned)
			}
			return cached, "cache", ""
		}
	}

	// 5. Forward upstream (split-horizon aware; force DO for DNSSEC if configured).
	if rt.forceDNSSEC {
		ensureDO(req)
	}
	// Coalesce concurrent misses for the same question into one upstream exchange;
	// the shared result is cached once and copied per caller below.
	resp, rtt, err := r.sf.Do(forwardKey(q, wantSigned), func() (*dns.Msg, time.Duration, error) {
		m, rtt, err := r.forward(req, upstreamsFor(rt, name))
		if err == nil && m != nil && rt.cache != nil {
			rt.cache.Set(q, wantSigned, m)
		}
		return m, rtt, err
	})
	if err != nil || resp == nil {
		r.stats.Errors.Add(1)
		slog.Warn("forward failed", "name", q.Name, "err", err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m, "error", ""
	}
	r.stats.Forwarded.Add(1)
	if r.metrics != nil {
		r.metrics.UpstreamDuration.Observe(rtt.Seconds())
	}
	// The forwarded message may be shared with other coalesced callers, so copy it
	// before we (and Handle) mutate Id / EDNS / truncate it.
	resp = resp.Copy()
	resp.Id = req.Id
	return resp, "forward", ""
}

func (r *Resolver) record(req, resp *dns.Msg, action, category, client string, start time.Time) {
	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	rcode := dns.RcodeToString[resp.Rcode]
	if r.metrics != nil {
		r.metrics.IncQuery(action)
	}
	if r.queryLog {
		slog.Info("query", "name", q.Name, "type", dns.TypeToString[q.Qtype],
			"action", action, "category", category, "rcode", rcode, "client", client)
	}
	if r.onQuery != nil {
		ev := queryEventPool.Get().(*QueryEvent)
		*ev = QueryEvent{
			TS: start, Client: client, Name: q.Name, QType: dns.TypeToString[q.Qtype],
			Action: action, Category: category, Rcode: rcode, Elapsed: time.Since(start),
		}
		r.onQuery(ev)
		queryEventPool.Put(ev)
	}
}

// queryEventPool reuses QueryEvent allocations across calls to record(), which
// runs on every single handled query when logging/OnQuery is enabled. OnQuery
// implementations must copy any fields they need before returning (see Options.OnQuery).
var queryEventPool = sync.Pool{New: func() any { return new(QueryEvent) }}

// refreshStale fetches a fresh answer for a stale (expired-but-served) cache entry
// in the background, so the next query gets a current record. Exactly one refresh
// runs per name (guarded by r.refreshing), and the upstream fetch is coalesced
// through the same single-flight as normal misses. Off the client's latency path.
func (r *Resolver) refreshStale(rt *runtime, req *dns.Msg, q dns.Question, name string, wantSigned bool) {
	key := forwardKey(q, wantSigned)
	if _, busy := r.refreshing.LoadOrStore(key, struct{}{}); busy {
		return // a refresh for this name is already in flight
	}
	// Copy the request synchronously so the goroutine can't race the caller's msg.
	rc := req.Copy()
	if rt.forceDNSSEC {
		ensureDO(rc)
	}
	go func() {
		defer r.refreshing.Delete(key)
		r.sf.Do(key, func() (*dns.Msg, time.Duration, error) {
			m, rtt, err := r.forward(rc, upstreamsFor(rt, name))
			if err == nil && m != nil && rt.cache != nil {
				rt.cache.Set(q, wantSigned, m)
			}
			return m, rtt, err
		})
	}()
}

// conditionalFor returns the most specific conditional forwarder matching name
// (rt.conditional is sorted longest-suffix-first). Forwarders whose upstreams
// all failed to parse are skipped, so a match here is one that can actually
// serve the query.
func conditionalFor(rt *runtime, name string) (condForward, bool) {
	for _, cf := range rt.conditional {
		if (name == cf.suffix || strings.HasSuffix(name, cf.dotSuffix)) && len(cf.ups) > 0 {
			return cf, true
		}
	}
	return condForward{}, false
}

func upstreamsFor(rt *runtime, name string) []Upstream {
	if cf, ok := conditionalFor(rt, name); ok {
		return cf.ups
	}
	return rt.defaultUpstreams
}

// hedgeDelay is how long we wait for the primary upstream before also querying
// the remaining upstreams in parallel. A healthy primary answers well within
// this window (so only one upstream is queried), while a slow or dead one fails
// over almost immediately instead of burning the full per-query timeout.
const hedgeDelay = 30 * time.Millisecond

func (r *Resolver) forward(req *dns.Msg, ups []Upstream) (*dns.Msg, time.Duration, error) {
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
			case res.err == nil && res.msg != nil && res.msg.Rcode != dns.RcodeServerFailure:
				return res.msg, res.rtt, nil // a real answer (incl. NXDOMAIN) wins.
			case res.err == nil && res.msg != nil:
				// SERVFAIL: a soft failure. Remember it, but try the other upstreams —
				// one of them may actually resolve the name.
				lastResp, lastRtt = res.msg, res.rtt
				launchRest()
			default:
				lastErr = res.err
				launchRest() // hard error before the hedge fired — query the rest now.
			}
			if pending == 0 {
				if lastResp != nil {
					return lastResp, lastRtt, nil // everyone SERVFAILed — return the SERVFAIL.
				}
				if lastErr == nil {
					lastErr = errNoUpstreams
				}
				return nil, 0, lastErr
			}
		}
	}
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

func (r *Resolver) blockedResponse(req *dns.Msg, q dns.Question, blockMode string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	if blockMode == "zeroip" {
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

// isDNSSECType reports whether t is a DNSSEC meta record that a client which
// didn't set the DO bit has no use for.
func isDNSSECType(t uint16) bool {
	switch t {
	case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM,
		dns.TypeDNSKEY, dns.TypeDS, dns.TypeCDS, dns.TypeCDNSKEY:
		return true
	}
	return false
}

// stripDNSSEC removes DNSSEC signature/meta records from a response (preserving
// the AD flag and the OPT record, with its DO bit cleared). Used for clients that
// didn't request DNSSEC, so they aren't sent large signed answers they can't use.
func stripDNSSEC(m *dns.Msg) {
	filter := func(rrs []dns.RR) []dns.RR {
		out := rrs[:0]
		for _, rr := range rrs {
			if !isDNSSECType(rr.Header().Rrtype) {
				out = append(out, rr)
			}
		}
		return out
	}
	m.Answer = filter(m.Answer)
	m.Ns = filter(m.Ns)
	m.Extra = filter(m.Extra) // keeps OPT (not a DNSSEC type)
	if o := m.IsEdns0(); o != nil {
		o.SetDo(false)
	}
}

// finalize applies the response hygiene common to every transport before the
// reply is sent: advertise recursion, drop DNSSEC records a non-DO client can't
// use, and keep EDNS handling RFC-correct (echo an OPT to EDNS clients — incl. on
// synthesized answers like blocks/rewrites — and none to clients that sent none).
func (r *Resolver) finalize(resp *dns.Msg, clientEDNS, clientDO bool) {
	if resp == nil {
		return
	}
	resp.RecursionAvailable = true // we are a recursive resolver
	if !clientDO {
		stripDNSSEC(resp)
	}
	if clientEDNS {
		if resp.IsEdns0() == nil {
			resp.SetEdns0(largeUDPSize, clientDO)
		}
	} else {
		removeOPT(resp) // RFC 6891 §6.1.1: no OPT in the reply if the query had none
	}
}

// removeOPT drops the EDNS0 OPT record from a message — used when replying to a
// client that sent no OPT, so we don't return an unsolicited one.
func removeOPT(m *dns.Msg) {
	for i, rr := range m.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			m.Extra = append(m.Extra[:i], m.Extra[i+1:]...)
			return
		}
	}
}

func ensureDO(m *dns.Msg) {
	if o := m.IsEdns0(); o != nil {
		o.SetDo(true)
		// Advertise a large UDP buffer so signed responses fit in one datagram
		// instead of truncating and forcing a slower TCP retry.
		if o.UDPSize() < largeUDPSize {
			o.SetUDPSize(largeUDPSize)
		}
		return
	}
	m.SetEdns0(largeUDPSize, true)
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
