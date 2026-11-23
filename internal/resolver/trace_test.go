package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/filter"
)

// traceResolver is a resolver with one of everything a trace can report: a
// zone, exact and wildcard records, a conditional forwarder, rules, an allow
// rule and a blocked category. Forwards go to fake upstreams.
func traceResolver(t *testing.T) *Resolver {
	t.Helper()
	a := func(v string) []RewriteRR { return []RewriteRR{{Type: dns.TypeA, Value: v}} }
	r := New(Options{Timeout: 200 * time.Millisecond, Zones: []ZoneSpec{{Name: "zone.test"}}})
	var b categories.Builder
	b.Add("adult.example", "adult")
	r.SetCategoryDB(categories.NewLoadedHolder(b.Build()))
	block, allow := filter.New(), filter.New()
	block.Add("ads.example", "ads")
	block.Add("ok.ads.example", "ads")
	allow.Add("ok.ads.example", "")
	r.SetPolicy(&Policy{
		Block: block, Allow: allow,
		Rewrites:  map[string][]RewriteRR{"nas.lan": a("192.168.1.10")},
		Wildcards: map[string][]RewriteRR{"corp.example": a("10.1.2.3")},
	})
	r.ApplySettings(Settings{BlockedCategories: []string{"adult"}, Cache: CacheSettings{Enabled: true, MaxEntries: 100}})
	rt := *r.rt.Load()
	rt.defaultUpstreams, rt.defaultLabels = []Upstream{answerUpstream{}}, []string{"default"}
	rt.conditional = []condForward{{suffix: "ha.corp.example", dotSuffix: ".ha.corp.example",
		ups: []Upstream{&fakeUpstream{name: "cond"}}, labels: []string{"cond"}}}
	r.rt.Store(&rt)
	return r
}

// answerUpstream answers every query with A 1.2.3.4 (TTL 60), so it caches.
type answerUpstream struct{}

func (answerUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{1, 2, 3, 4},
	})
	return m, time.Millisecond, nil
}

func (answerUpstream) String() string { return "answer" }

func traceQ(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

// A trace decides every name exactly as a real query would, and says why.
func TestTraceMatchesResolve(t *testing.T) {
	r := traceResolver(t)
	cases := []struct {
		name, decision string
		check          func(t *testing.T, tr TraceResult)
	}{
		{"ns.zone.test", "authoritative", func(t *testing.T, tr TraceResult) {
			if tr.Zone != "zone.test" {
				t.Fatalf("zone = %q", tr.Zone)
			}
		}},
		{"nas.lan", "rewrite", func(t *testing.T, tr TraceResult) {
			if tr.Rewrite != "nas.lan" {
				t.Fatalf("rewrite = %q", tr.Rewrite)
			}
		}},
		{"x.corp.example", "rewrite", func(t *testing.T, tr TraceResult) {
			if tr.Rewrite != "*.corp.example" {
				t.Fatalf("rewrite = %q", tr.Rewrite)
			}
		}},
		{"a.ha.corp.example", "forward", func(t *testing.T, tr TraceResult) {
			if tr.Forwarder != "ha.corp.example" || tr.Upstream != "cond" || tr.RewriteYielded != "*.corp.example" {
				t.Fatalf("forwarder/upstream/yielded = %q/%q/%q", tr.Forwarder, tr.Upstream, tr.RewriteYielded)
			}
		}},
		{"x.ads.example", "blocked", func(t *testing.T, tr TraceResult) {
			if tr.Category != "ads" || tr.CategoryBlock {
				t.Fatalf("category = %q (category block %v)", tr.Category, tr.CategoryBlock)
			}
		}},
		{"www.adult.example", "blocked", func(t *testing.T, tr TraceResult) {
			if tr.Category != "adult" || !tr.CategoryBlock {
				t.Fatalf("category = %q (category block %v)", tr.Category, tr.CategoryBlock)
			}
		}},
		{"ok.ads.example", "forward", func(t *testing.T, tr TraceResult) {
			if !tr.Allowed || tr.Category != "ads" {
				t.Fatalf("allowed = %v, category %q", tr.Allowed, tr.Category)
			}
		}},
		{"example.com", "forward", func(t *testing.T, tr TraceResult) {
			if tr.Forwarder != "" || tr.Upstream != "default" {
				t.Fatalf("forwarder/upstream = %q/%q", tr.Forwarder, tr.Upstream)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, action, _ := r.Resolve(traceQ(tc.name), "10.0.0.1")
			if action == "cache" {
				action = "forward"
			}
			tr := r.Trace(traceQ(tc.name), nil, TraceOptions{})
			if tr.Decision != tc.decision || action != tc.decision {
				t.Fatalf("trace %q, resolve %q, want %q", tr.Decision, action, tc.decision)
			}
			tc.check(t, tr)
		})
	}
}

// A trace never answers from the cache, never fills it, and counts nothing.
func TestTraceSkipsCacheAndStats(t *testing.T) {
	r := traceResolver(t)
	r.Resolve(traceQ("example.com"), "10.0.0.1") // now cached
	if _, action, _ := r.Resolve(traceQ("example.com"), "10.0.0.1"); action != "cache" {
		t.Fatalf("second resolve = %q, want cache", action)
	}
	before := r.CacheLen()
	total, _, _, _, _, _ := r.StatsSnapshot()
	if tr := r.Trace(traceQ("example.com"), nil, TraceOptions{}); tr.Decision != "forward" || tr.Upstream != "default" {
		t.Fatalf("trace = %q via %q, want a fresh forward", tr.Decision, tr.Upstream)
	}
	r.Trace(traceQ("other.example"), nil, TraceOptions{})
	if r.CacheLen() != before {
		t.Fatal("trace filled the cache")
	}
	if t2, _, _, _, _, _ := r.StatsSnapshot(); t2 != total {
		t.Fatal("trace counted in stats")
	}
}

func TestTraceBlockPausedAndForwardBlocked(t *testing.T) {
	r := traceResolver(t)
	tr := r.Trace(traceQ("x.ads.example"), nil, TraceOptions{ForwardBlocked: true})
	if tr.Decision != "blocked" || tr.UpstreamResponse == nil || tr.Upstream != "default" {
		t.Fatalf("forward blocked: %+v", tr)
	}
	r.SetBlockPausedUntil(time.Now().Add(time.Hour).Unix())
	tr = r.Trace(traceQ("x.ads.example"), nil, TraceOptions{})
	if tr.Decision != "forward" || !tr.BlockPaused || tr.Category != "ads" {
		t.Fatalf("paused: decision %q paused %v category %q", tr.Decision, tr.BlockPaused, tr.Category)
	}
}

// A view swaps in another resolver's local records and forwarders: a record
// scoped elsewhere is gone, and its own forwarder (parsed from specs) answers.
func TestTraceView(t *testing.T) {
	r := traceResolver(t)
	up := newSwitchableUpstream(t)
	view := &TraceView{
		Scoped:        true,
		Rewrites:      map[string][]RewriteRR{"site.lan": {{Type: dns.TypeA, Value: "10.7.7.7"}}},
		ForwardersSet: true,
		Forwarders:    []ForwardGroup{{Suffix: "branch.example", Upstreams: []string{up.addr()}}},
	}
	if tr := r.Trace(traceQ("nas.lan"), view, TraceOptions{}); tr.Decision != "forward" {
		t.Fatalf("nas.lan in view = %q, want forward (record not scoped here)", tr.Decision)
	}
	if tr := r.Trace(traceQ("site.lan"), view, TraceOptions{}); tr.Decision != "rewrite" {
		t.Fatalf("site.lan in view = %q, want rewrite", tr.Decision)
	}
	tr := r.Trace(traceQ("host.branch.example"), view, TraceOptions{})
	if tr.Decision != "forward" || tr.Forwarder != "branch.example" || len(tr.Response.Answer) != 1 {
		t.Fatalf("view forwarder: %+v", tr)
	}
	// The resolver's own forwarder is not part of the view.
	if tr := r.Trace(traceQ("a.ha.corp.example"), view, TraceOptions{}); tr.Forwarder != "" {
		t.Fatalf("own forwarder leaked into view: %q", tr.Forwarder)
	}
	// Live state untouched: the real pipeline still has its own forwarder.
	if _, action, _ := r.Resolve(traceQ("site.lan"), "10.0.0.1"); action == "rewrite" {
		t.Fatal("view records leaked into the live policy")
	}
	// Upstreams parsed for views are reused, not re-created per trace.
	r.Trace(traceQ("x.branch.example"), view, TraceOptions{})
	if n := len(r.traceUps); n != 1 {
		t.Fatalf("trace upstreams = %d, want 1", n)
	}
}

func TestTraceForwardError(t *testing.T) {
	r := traceResolver(t)
	rt := *r.rt.Load()
	rt.defaultUpstreams = nil
	r.rt.Store(&rt)
	tr := r.Trace(traceQ("example.com"), nil, TraceOptions{})
	if tr.Decision != "error" || tr.Error == "" || tr.Response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("error trace: %+v", tr)
	}
}
