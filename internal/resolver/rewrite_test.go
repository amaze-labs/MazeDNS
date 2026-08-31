package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestLookupRewrite(t *testing.T) {
	a := func(v string) []RewriteRR { return []RewriteRR{{Type: dns.TypeA, Value: v}} }
	pol := &Policy{
		Rewrites: map[string][]RewriteRR{
			"corp.example":      a("10.9.9.9"), // exact apex
			"mail.corp.example": a("10.0.0.7"), // exact subdomain the wildcard also covers
			"nas.lan":           a("192.168.1.10"),
		},
		Wildcards: map[string][]RewriteRR{
			"corp.example":     a("10.1.2.3"), // *.corp.example
			"sub.corp.example": a("10.5.5.5"), // *.sub.corp.example (more specific)
		},
	}

	cases := []struct {
		name      string
		query     string
		wantHit   bool
		wantValue string
		wantWild  string
	}{
		{"exact apex beats wildcard", "corp.example", true, "10.9.9.9", ""},
		{"exact subdomain beats wildcard", "mail.corp.example", true, "10.0.0.7", ""},
		{"plain exact", "nas.lan", true, "192.168.1.10", ""},
		{"single-label subdomain", "foo.corp.example", true, "10.1.2.3", "corp.example"},
		{"multi-label subdomain", "a.b.corp.example", true, "10.1.2.3", "corp.example"},
		{"most specific wildcard wins", "x.sub.corp.example", true, "10.5.5.5", "sub.corp.example"},
		{"sibling is not matched", "notcorp.example", false, "", ""},
		{"unrelated name", "example.com", false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rrs, wild, ok := pol.lookupRewrite(tc.query)
			if ok != tc.wantHit {
				t.Fatalf("lookupRewrite(%q) hit=%v, want %v", tc.query, ok, tc.wantHit)
			}
			if !tc.wantHit {
				return
			}
			if len(rrs) != 1 || rrs[0].Value != tc.wantValue {
				t.Fatalf("lookupRewrite(%q) = %+v, want value %q", tc.query, rrs, tc.wantValue)
			}
			if wild != tc.wantWild {
				t.Fatalf("lookupRewrite(%q) wildSuffix=%q, want %q", tc.query, wild, tc.wantWild)
			}
		})
	}
}

// TestWildcardRewriteVsConditionalForwarder covers the precedence between a
// "*.suffix" rewrite and a conditional forwarder matching the same name: the
// more specific suffix wins, and on a tie (or for an exact rewrite) the rewrite
// wins.
func TestWildcardRewriteVsConditionalForwarder(t *testing.T) {
	a := func(v string) []RewriteRR { return []RewriteRR{{Type: dns.TypeA, Value: v}} }
	cf := func(suffix string, ups ...Upstream) condForward {
		return condForward{suffix: suffix, dotSuffix: "." + suffix, ups: ups}
	}
	newResolver := func(conditional ...condForward) *Resolver {
		r := New(Options{})
		r.SetPolicy(&Policy{
			Rewrites: map[string][]RewriteRR{"ha.corp.example": a("10.0.0.9")},
			Wildcards: map[string][]RewriteRR{
				"corp.example":      a("10.1.2.3"),
				"deep.corp.example": a("10.4.4.4"),
			},
		})
		// Longest-suffix-first, as ApplySettings sorts it.
		r.rt.Store(&runtime{
			defaultUpstreams: []Upstream{&fakeUpstream{name: "default"}},
			conditional:      conditional,
			blockMode:        "nxdomain",
		})
		return r
	}
	forwarder := cf("ha.corp.example", &fakeUpstream{name: "cond"})
	// Overlapping forwarders, in the longest-suffix-first order ApplySettings
	// guarantees (pinned by TestApplySettingsSortsForwardersBySpecificity).
	overlapping := []condForward{
		cf("ha.corp.example", &fakeUpstream{name: "cond-ha"}),
		cf("corp.example", &fakeUpstream{name: "cond-broad"}),
	}

	cases := []struct {
		name        string
		conditional []condForward
		query       string
		wantAction  string
		wantSrc     string // TXT marker of the upstream that answered (forward only)
		wantA       string // rewrite answer (rewrite only)
	}{
		{"more specific forwarder beats wildcard at apex", []condForward{forwarder},
			"sub.ha.corp.example", "forward", "cond", ""},
		{"more specific forwarder beats wildcard for subdomains", []condForward{forwarder},
			"a.b.ha.corp.example", "forward", "cond", ""},
		{"exact rewrite beats forwarder at its apex", []condForward{forwarder},
			"ha.corp.example", "rewrite", "", "10.0.0.9"},
		{"tie: rewrite wins over same-suffix forwarder", []condForward{cf("corp.example", &fakeUpstream{name: "cond"})},
			"foo.corp.example", "rewrite", "", "10.1.2.3"},
		{"more specific wildcard beats forwarder", []condForward{cf("corp.example", &fakeUpstream{name: "cond"})},
			"x.deep.corp.example", "rewrite", "", "10.4.4.4"},
		{"forwarder without usable upstreams does not override", []condForward{cf("ha.corp.example")},
			"sub.ha.corp.example", "rewrite", "", "10.1.2.3"},
		{"unrelated name forwards to default", []condForward{forwarder},
			"other.test", "forward", "default", ""},
		{"most specific of two matching forwarders wins over wildcard", overlapping,
			"sub.ha.corp.example", "forward", "cond-ha", ""},
		{"unusable specific forwarder falls back to broad one, tying with wildcard", []condForward{cf("ha.corp.example"), cf("corp.example", &fakeUpstream{name: "cond-broad"})},
			"sub.ha.corp.example", "rewrite", "", "10.1.2.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newResolver(tc.conditional...)
			req := new(dns.Msg)
			req.SetQuestion(dns.Fqdn(tc.query), dns.TypeA)
			resp, action, _ := r.Resolve(req, "10.0.0.1")
			if action != tc.wantAction {
				t.Fatalf("Resolve(%q) action=%q, want %q", tc.query, action, tc.wantAction)
			}
			switch tc.wantAction {
			case "forward":
				if got := respSource(resp); got != tc.wantSrc {
					t.Fatalf("Resolve(%q) answered by upstream %q, want %q", tc.query, got, tc.wantSrc)
				}
			case "rewrite":
				if len(resp.Answer) != 1 {
					t.Fatalf("Resolve(%q) answers=%d, want 1", tc.query, len(resp.Answer))
				}
				aRec, ok := resp.Answer[0].(*dns.A)
				if !ok || aRec.A.String() != tc.wantA {
					t.Fatalf("Resolve(%q) = %v, want A %s", tc.query, resp.Answer[0], tc.wantA)
				}
			}
		})
	}
}

// TestRewriteAddressNODATA covers the split-horizon hole: a name whose address
// is overridden locally must not leak the public horizon's records for the
// other address family, nor the address hints in HTTPS/SVCB records. Address-
// shaped queries with no matching rewrite record get an authoritative NODATA;
// non-address types (and CNAME-only rewrites) still forward.
func TestRewriteAddressNODATA(t *testing.T) {
	rr := func(typ uint16, v string) RewriteRR { return RewriteRR{Type: typ, Value: v} }
	newRes := func() *Resolver {
		r := New(Options{})
		r.SetPolicy(&Policy{
			Rewrites: map[string][]RewriteRR{
				"app.ipmaze.net": {rr(dns.TypeA, "192.168.1.30")},
				"v6only.lan":     {rr(dns.TypeAAAA, "fd00::30")},
				"dual.lan":       {rr(dns.TypeA, "192.168.1.31"), rr(dns.TypeAAAA, "fd00::31")},
				"alias.lan":      {rr(dns.TypeCNAME, "app.ipmaze.net")},
			},
			Wildcards: map[string][]RewriteRR{
				"corp.example": {rr(dns.TypeA, "10.1.2.3")},
			},
		})
		r.rt.Store(&runtime{
			defaultUpstreams: []Upstream{&fakeUpstream{name: "public"}},
			blockMode:        "nxdomain",
		})
		return r
	}

	cases := []struct {
		name       string
		query      string
		qtype      uint16
		wantAction string
		wantNodata bool   // NOERROR, authoritative, zero answers
		wantAnswer string // expected address/first answer (rewrite hits only)
	}{
		{"AAAA for A-only name is NODATA", "app.ipmaze.net", dns.TypeAAAA, "rewrite", true, ""},
		{"HTTPS for A-only name is NODATA", "app.ipmaze.net", dns.TypeHTTPS, "rewrite", true, ""},
		{"SVCB for A-only name is NODATA", "app.ipmaze.net", dns.TypeSVCB, "rewrite", true, ""},
		{"A for A-only name still answers", "app.ipmaze.net", dns.TypeA, "rewrite", false, "192.168.1.30"},
		{"A for AAAA-only name is NODATA", "v6only.lan", dns.TypeA, "rewrite", true, ""},
		{"AAAA for AAAA-only name still answers", "v6only.lan", dns.TypeAAAA, "rewrite", false, "fd00::30"},
		{"explicit AAAA rewrite still wins", "dual.lan", dns.TypeAAAA, "rewrite", false, "fd00::31"},
		{"non-address type still forwards", "app.ipmaze.net", dns.TypeTXT, "forward", false, ""},
		{"CNAME-only rewrite still forwards A", "alias.lan", dns.TypeA, "forward", false, ""},
		{"AAAA under address wildcard is NODATA", "foo.corp.example", dns.TypeAAAA, "rewrite", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRes()
			req := new(dns.Msg)
			req.SetQuestion(dns.Fqdn(tc.query), tc.qtype)
			resp, action, _ := r.Resolve(req, "10.0.0.1")
			if action != tc.wantAction {
				t.Fatalf("Resolve(%q %s) action=%q, want %q", tc.query, dns.TypeToString[tc.qtype], action, tc.wantAction)
			}
			if tc.wantAction == "forward" {
				if got := respSource(resp); got != "public" {
					t.Fatalf("Resolve(%q) answered by upstream %q, want public", tc.query, got)
				}
				return
			}
			if tc.wantNodata {
				if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || !resp.Authoritative {
					t.Fatalf("Resolve(%q %s) = rcode %s, %d answers, auth=%v; want authoritative empty NOERROR",
						tc.query, dns.TypeToString[tc.qtype], dns.RcodeToString[resp.Rcode], len(resp.Answer), resp.Authoritative)
				}
				return
			}
			if len(resp.Answer) != 1 {
				t.Fatalf("Resolve(%q %s) answers=%d, want 1", tc.query, dns.TypeToString[tc.qtype], len(resp.Answer))
			}
			var got string
			switch a := resp.Answer[0].(type) {
			case *dns.A:
				got = a.A.String()
			case *dns.AAAA:
				got = a.AAAA.String()
			default:
				t.Fatalf("Resolve(%q) unexpected answer %v", tc.query, resp.Answer[0])
			}
			if got != tc.wantAnswer {
				t.Fatalf("Resolve(%q %s) = %s, want %s", tc.query, dns.TypeToString[tc.qtype], got, tc.wantAnswer)
			}
		})
	}
}

// TestApplySettingsSortsForwardersBySpecificity pins the longest-suffix-first
// order that conditionalFor's first-match scan — and therefore the
// wildcard-vs-forwarder override — depends on.
func TestApplySettingsSortsForwardersBySpecificity(t *testing.T) {
	r := New(Options{})
	// Declared shortest-first to prove ApplySettings sorts.
	r.ApplySettings(Settings{Forwarders: []ForwardGroup{
		{Suffix: "corp.example", Upstreams: []string{"127.0.0.1:53"}},
		{Suffix: "ha.corp.example", Upstreams: []string{"127.0.0.2:53"}},
	}})
	cond := r.rt.Load().conditional
	if len(cond) != 2 || cond[0].suffix != "ha.corp.example" || cond[1].suffix != "corp.example" {
		t.Fatalf("conditional order = %+v, want ha.corp.example before corp.example", cond)
	}
	cf, ok := conditionalFor(r.rt.Load(), "x.ha.corp.example")
	if !ok || cf.suffix != "ha.corp.example" {
		t.Fatalf("conditionalFor picked %q, want the most specific ha.corp.example", cf.suffix)
	}
}
