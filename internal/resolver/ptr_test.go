package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestBuildReverse(t *testing.T) {
	rr := func(typ uint16, v string) RewriteRR { return RewriteRR{Type: typ, Value: v} }
	got := buildReverse(map[string][]RewriteRR{
		// Three names for one address: shortest, then alphabetical.
		"storage.example.lan": {rr(dns.TypeA, "192.0.2.10")},
		"nas.example.lan":     {rr(dns.TypeA, "192.0.2.10")},
		"fs1.example.lan":     {rr(dns.TypeA, "192.0.2.10")},
		"dual.example.lan":    {rr(dns.TypeA, "192.0.2.20"), rr(dns.TypeAAAA, "2001:DB8::20")},
		// Ignored: CNAMEs, family mismatches, garbage.
		"alias.example.lan":      {rr(dns.TypeCNAME, "nas.example.lan")},
		"v6-in-a.example.lan":    {rr(dns.TypeA, "2001:db8::30")},
		"v4-in-aaaa.example.lan": {rr(dns.TypeAAAA, "192.0.2.31")},
		"bad.example.lan":        {rr(dns.TypeA, "not-an-ip")},
	})
	want := map[string]string{
		"10.2.0.192.in-addr.arpa": "fs1.example.lan",
		"20.2.0.192.in-addr.arpa": "dual.example.lan",
		"0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa": "dual.example.lan",
	}
	if len(got) != len(want) {
		t.Fatalf("buildReverse = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("buildReverse[%s] = %q, want %q", k, got[k], v)
		}
	}
}

// TestRewritePTR covers PTR answers synthesized from exact A/AAAA rewrites and
// their precedence: a conditional forwarder covering the reverse zone wins, an
// address without a rewrite (or a non-PTR query) keeps forwarding.
func TestRewritePTR(t *testing.T) {
	rr := func(typ uint16, v string) RewriteRR { return RewriteRR{Type: typ, Value: v} }
	cf := func(suffix string, ups ...Upstream) condForward {
		return condForward{suffix: suffix, dotSuffix: "." + suffix, ups: ups}
	}
	newRes := func(conditional ...condForward) *Resolver {
		r := New(Options{})
		r.SetPolicy(&Policy{
			Rewrites: map[string][]RewriteRR{
				"nas.example.lan":     {rr(dns.TypeA, "192.0.2.10")},
				"storage.example.lan": {rr(dns.TypeA, "192.0.2.10")},
				"v6.example.lan":      {rr(dns.TypeAAAA, "2001:db8::20")},
				"a-only.example.lan":  {rr(dns.TypeA, "192.0.2.30")},
			},
			Wildcards: map[string][]RewriteRR{
				"lab.example.lan": {rr(dns.TypeA, "192.0.2.40")},
			},
		})
		r.rt.Store(&runtime{
			defaultUpstreams: []Upstream{&fakeUpstream{name: "default"}},
			conditional:      conditional,
			blockMode:        "nxdomain",
		})
		return r
	}
	rev := func(ip string) string {
		s, err := dns.ReverseAddr(ip)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	cases := []struct {
		name        string
		conditional []condForward
		query       string
		qtype       uint16
		wantAction  string
		wantPTR     string // rewrite hits
		wantSrc     string // forward hits: upstream that answered
	}{
		{"IPv4 PTR answers the preferred name", nil, rev("192.0.2.10"), dns.TypePTR, "rewrite", "nas.example.lan.", ""},
		{"IPv6 PTR", nil, rev("2001:db8::20"), dns.TypePTR, "rewrite", "v6.example.lan.", ""},
		{"query name case is ignored", nil, "10.2.0.192.IN-ADDR.ARPA.", dns.TypePTR, "rewrite", "nas.example.lan.", ""},
		{"no rewrite for the address forwards", nil, rev("192.0.2.99"), dns.TypePTR, "forward", "", "default"},
		{"wildcard rewrites imply no PTR", nil, rev("192.0.2.40"), dns.TypePTR, "forward", "", "default"},
		{"non-PTR query on a reverse name forwards", nil, rev("192.0.2.10"), dns.TypeTXT, "forward", "", "default"},
		{"forwarder for the reverse zone wins", []condForward{cf("2.0.192.in-addr.arpa", &fakeUpstream{name: "rev-zone"})},
			rev("192.0.2.10"), dns.TypePTR, "forward", "", "rev-zone"},
		{"forwarder for a broad reverse zone wins too", []condForward{cf("in-addr.arpa", &fakeUpstream{name: "rev-all"})},
			rev("192.0.2.10"), dns.TypePTR, "forward", "", "rev-all"},
		{"forwarder for another reverse zone does not interfere", []condForward{cf("100.51.198.in-addr.arpa", &fakeUpstream{name: "rev-other"})},
			rev("192.0.2.10"), dns.TypePTR, "rewrite", "nas.example.lan.", ""},
		{"forwarder without usable upstreams does not override", []condForward{cf("2.0.192.in-addr.arpa")},
			rev("192.0.2.10"), dns.TypePTR, "rewrite", "nas.example.lan.", ""},
		{"IPv6 reverse-zone forwarder wins", []condForward{cf("8.b.d.0.1.0.0.2.ip6.arpa", &fakeUpstream{name: "rev6"})},
			rev("2001:db8::20"), dns.TypePTR, "forward", "", "rev6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRes(tc.conditional...)
			req := new(dns.Msg)
			req.SetQuestion(tc.query, tc.qtype)
			resp, action, _ := r.Resolve(req, "192.0.2.1")
			if action != tc.wantAction {
				t.Fatalf("Resolve(%s %s) action=%q, want %q", tc.query, dns.TypeToString[tc.qtype], action, tc.wantAction)
			}
			if tc.wantAction == "forward" {
				if got := respSource(resp); got != tc.wantSrc {
					t.Fatalf("Resolve(%s) answered by %q, want %q", tc.query, got, tc.wantSrc)
				}
				return
			}
			if !resp.Authoritative || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
				t.Fatalf("Resolve(%s) = %v, want one authoritative PTR", tc.query, resp)
			}
			ptr, ok := resp.Answer[0].(*dns.PTR)
			if !ok || ptr.Ptr != tc.wantPTR || ptr.Hdr.Name != tc.query {
				t.Fatalf("Resolve(%s) = %v, want PTR %s owned by the query name", tc.query, resp.Answer[0], tc.wantPTR)
			}
		})
	}

	// The forward side is untouched: a rewritten name still answers NODATA for
	// the address family it has no record for.
	r := newRes()
	req := new(dns.Msg)
	req.SetQuestion("a-only.example.lan.", dns.TypeAAAA)
	resp, action, _ := r.Resolve(req, "192.0.2.1")
	if action != "rewrite" || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("AAAA for A-only rewrite: action=%q rcode=%s answers=%d, want rewrite NODATA",
			action, dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
}

// A policy swap rebuilds the reverse map: removing a rewrite removes its PTR.
func TestRewritePTRFollowsPolicy(t *testing.T) {
	r := New(Options{})
	r.rt.Store(&runtime{defaultUpstreams: []Upstream{&fakeUpstream{name: "default"}}, blockMode: "nxdomain"})
	query := func() string {
		req := new(dns.Msg)
		req.SetQuestion("10.2.0.192.in-addr.arpa.", dns.TypePTR)
		_, action, _ := r.Resolve(req, "192.0.2.1")
		return action
	}
	if got := query(); got != "forward" {
		t.Fatalf("empty policy: action %q, want forward", got)
	}
	r.SetPolicy(&Policy{Rewrites: map[string][]RewriteRR{"nas.example.lan": {{Type: dns.TypeA, Value: "192.0.2.10"}}}})
	if got := query(); got != "rewrite" {
		t.Fatalf("with rewrite: action %q, want rewrite", got)
	}
	r.SetPolicy(&Policy{})
	if got := query(); got != "forward" {
		t.Fatalf("after removal: action %q, want forward", got)
	}
}
