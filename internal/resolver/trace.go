package resolver

import (
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/categories"
)

// TraceView narrows a Trace to what one resolver runs: the local records and
// conditional forwarders scoped to it. A nil View (or nil fields) evaluates
// against this resolver's own policy and forwarders.
type TraceView struct {
	// Rewrites and Wildcards replace the policy's local records when Scoped is
	// set (an empty map then means "no local records here").
	Scoped    bool
	Rewrites  map[string][]RewriteRR
	Wildcards map[string][]RewriteRR
	// Forwarders replace the conditional forwarders when ForwardersSet is set.
	ForwardersSet bool
	Forwarders    []ForwardGroup
	// CategoryDomains, when not nil, are the per-domain category corrections
	// the resolvers receive with their settings (Settings.CategoryDomains),
	// which a control plane does not hold in its own runtime.
	CategoryDomains map[string]string
}

// TraceOptions tunes a Trace.
type TraceOptions struct {
	// CategoryDB is the category database to evaluate network-wide category
	// blocks against (nil = the resolver's own, if any).
	CategoryDB *categories.Holder
	// ForwardBlocked also forwards a blocked name upstream, so the trace shows
	// what it would have resolved to (TraceResult.Upstream*).
	ForwardBlocked bool
	// DNSSEC asks the upstream for the signed answer (DO bit).
	DNSSEC bool
}

// TraceResult says how a query was decided, step by step.
type TraceResult struct {
	// Response is what a client would get.
	Response *dns.Msg
	// Decision is the step that answered: "authoritative", "rewrite",
	// "blocked", "forward" or "error".
	Decision string
	// Zone is the authoritative zone that answered.
	Zone string
	// Rewrite is the local record that answered: the name, or "*.suffix" for a
	// wildcard. RewriteYielded is set when a wildcard matched but a more
	// specific conditional forwarder took the name.
	Rewrite        string
	RewriteYielded string
	// Category is the block category, for "blocked" and for a name an allow
	// rule or the block pause let through.
	Category string
	// CategoryBlock is set when the block came from a network-wide blocked
	// category (not a rule or list).
	CategoryBlock bool
	// Allowed is set when a block matched but an allow rule exempts the name.
	Allowed bool
	// BlockPaused is set when blocking is paused; Category then says what would
	// have blocked the name, if anything.
	BlockPaused bool
	// Forwarder is the conditional forwarder suffix that took the name ("" =
	// the default upstreams); Upstream the one that answered; RTT its latency.
	Forwarder string
	Upstream  string
	RTT       time.Duration
	// Error is why forwarding failed.
	Error string
	// UpstreamResponse is the forwarded answer for a blocked name when
	// TraceOptions.ForwardBlocked is set.
	UpstreamResponse *dns.Msg
}

// Trace runs the resolution pipeline for req in the same order as a real
// query, but for inspection: it skips the cache (and never fills it), the
// rate limit, query coalescing, stats, metrics and the query log, and records
// which step decided. The query path (Resolve/Handle) does not go through it.
func (r *Resolver) Trace(req *dns.Msg, view *TraceView, opts TraceOptions) TraceResult {
	var res TraceResult
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		res.Response, res.Decision, res.Error = m, "error", "no question"
		return res
	}
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	rt := r.traceRuntime(view)
	pol := r.tracePolicy(view)
	db := opts.CategoryDB
	if db == nil {
		db = r.catDB.Load()
	}

	// 1. Authoritative zones.
	if z := r.zones.match(name); z != nil {
		res.Response, res.Decision, res.Zone = z.answer(req, q, name), "authoritative", z.apex
		return res
	}

	// 2. Local records (exact, then wildcard yielding to a more specific
	// conditional forwarder).
	if rrs, wildSuffix, ok := pol.lookupRewrite(name); ok {
		override := false
		if wildSuffix != "" {
			if cf, ok := conditionalFor(rt, name); ok && len(cf.suffix) > len(wildSuffix) {
				override = true
				res.RewriteYielded = "*." + wildSuffix
			}
		}
		if !override {
			if resp := r.rewriteResponse(req, q, rrs); resp != nil {
				res.Response, res.Decision, res.Rewrite = resp, "rewrite", name
				if wildSuffix != "" {
					res.Rewrite = "*." + wildSuffix
				}
				return res
			}
		}
	}
	if q.Qtype == dns.TypePTR {
		if resp := r.rewritePTR(rt, pol, req, q, name); resp != nil {
			res.Response, res.Decision, res.Rewrite = resp, "rewrite", name
			return res
		}
	}

	// 3. Blocking: rules and lists, then network-wide categories.
	cat, blocked := pol.Block.MatchNormalized(name)
	if !blocked {
		cat, blocked = blockedCategoryIn(rt, db, name)
		res.CategoryBlock = blocked
	}
	if blocked {
		res.Category = cat
		switch {
		case pol.Allow.IsBlockedNormalized(name):
			res.Allowed, res.CategoryBlock = true, false
		case r.BlockPaused():
			res.BlockPaused = true
		default:
			res.Response, res.Decision = r.blockedResponse(req, q, rt.blockMode), "blocked"
			if opts.ForwardBlocked {
				fwd := r.traceForward(rt, req, name, opts)
				res.UpstreamResponse, res.Forwarder, res.Upstream, res.RTT, res.Error =
					fwd.Response, fwd.Forwarder, fwd.Upstream, fwd.RTT, fwd.Error
			}
			return res
		}
	}
	if r.BlockPaused() {
		res.BlockPaused = true
	}

	// 4. (No cache.) 5. Forward.
	fwd := r.traceForward(rt, req, name, opts)
	res.Response, res.Decision = fwd.Response, fwd.Decision
	res.Forwarder, res.Upstream, res.RTT, res.Error = fwd.Forwarder, fwd.Upstream, fwd.RTT, fwd.Error
	return res
}

// traceForward forwards a copy of req the way a cache miss would, without
// coalescing, caching or health/metrics bookkeeping.
func (r *Resolver) traceForward(rt *runtime, req *dns.Msg, name string, opts TraceOptions) TraceResult {
	var res TraceResult
	fq := req.Copy()
	if rt.forceDNSSEC || opts.DNSSEC {
		if fq.IsEdns0() == nil {
			fq.SetEdns0(largeUDPSize, true)
		}
		ensureDO(fq)
	}
	ups, labels, forwarder := upstreamsFor(rt, name)
	res.Forwarder = forwarder
	m, rtt, idx, err := r.forward(rt, fq, ups)
	res.RTT = rtt
	if idx >= 0 && idx < len(labels) {
		res.Upstream = labels[idx]
	}
	if err != nil || m == nil {
		if err == nil {
			err = errNoUpstreams
		}
		e := new(dns.Msg)
		e.SetRcode(req, dns.RcodeServerFailure)
		res.Response, res.Decision, res.Error = e, "error", err.Error()
		return res
	}
	m = m.Copy()
	m.Id = req.Id
	res.Response, res.Decision = m, "forward"
	return res
}

// tracePolicy is the policy a Trace evaluates: this resolver's block/allow
// engines with the view's local records, if it has its own.
func (r *Resolver) tracePolicy(view *TraceView) *Policy {
	pol := r.pol.Load()
	if view == nil || !view.Scoped {
		return pol
	}
	p := &Policy{Block: pol.Block, Allow: pol.Allow, Rewrites: view.Rewrites, Wildcards: view.Wildcards}
	if p.Rewrites == nil {
		p.Rewrites = map[string][]RewriteRR{}
	}
	if p.Wildcards == nil {
		p.Wildcards = map[string][]RewriteRR{}
	}
	p.reverse = buildReverse(p.Rewrites)
	return p
}

// traceRuntime is the runtime a Trace evaluates: this resolver's, with the
// view's conditional forwarders if it has its own. Upstreams the resolver
// already runs are reused (warm connections); others are kept in a separate
// map so repeated traces don't open a new pool each time.
func (r *Resolver) traceRuntime(view *TraceView) *runtime {
	rt := r.rt.Load()
	if view == nil || (!view.ForwardersSet && view.CategoryDomains == nil) {
		return rt
	}
	cp := *rt
	if view.CategoryDomains != nil {
		cp.catDomains = make(map[string]string, len(view.CategoryDomains))
		for d, c := range view.CategoryDomains {
			cp.catDomains[strings.ToLower(strings.TrimSuffix(d, "."))] = c
		}
	}
	if !view.ForwardersSet {
		return &cp
	}
	cp.conditional = nil
	var per time.Duration
	if !rt.hedged {
		per = rt.upstreamTimeout
	}
	r.upMu.Lock()
	if r.traceUps == nil {
		r.traceUps = map[string]Upstream{}
	}
	for _, f := range view.Forwarders {
		suffix := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(f.Suffix), "."))
		if suffix == "" {
			continue
		}
		ups, labels := r.traceUpstreams(f.Upstreams, per)
		cp.conditional = append(cp.conditional, condForward{suffix: suffix, dotSuffix: "." + suffix, ups: ups, labels: labels})
	}
	r.upMu.Unlock()
	sort.Slice(cp.conditional, func(i, j int) bool { return len(cp.conditional[i].suffix) > len(cp.conditional[j].suffix) })
	return &cp
}

// traceUpstreams is parseUpstreams for a Trace: it reuses the resolver's live
// upstreams and keeps any others in r.traceUps instead of r.upstreams.
// r.upMu must be held.
func (r *Resolver) traceUpstreams(specs []string, per time.Duration) ([]Upstream, []string) {
	out := make([]Upstream, 0, len(specs))
	labels := make([]string, 0, len(specs))
	for i, s := range specs {
		timeout := r.timeout
		if per > 0 && per < timeout && i < len(specs)-1 {
			timeout = per
		}
		key := s + "|" + timeout.String()
		u, ok := r.upstreams[key]
		if !ok {
			u, ok = r.traceUps[key]
		}
		if !ok {
			var err error
			if u, err = ParseUpstream(s, timeout); err != nil {
				continue
			}
			r.traceUps[key] = u
		}
		out = append(out, u)
		labels = append(labels, upstreamLabel(s))
	}
	return out, labels
}
