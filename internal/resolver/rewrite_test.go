package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestLookupRewrite(t *testing.T) {
	a := func(v string) []RewriteRR { return []RewriteRR{{Type: dns.TypeA, Value: v}} }
	pol := &Policy{
		Rewrites: map[string][]RewriteRR{
			"azzate.ferrario.dev": a("10.9.9.9"), // exact apex
			"nas.lan":             a("192.168.1.10"),
		},
		Wildcards: map[string][]RewriteRR{
			"azzate.ferrario.dev":     a("10.1.2.3"), // *.azzate.ferrario.dev
			"sub.azzate.ferrario.dev": a("10.5.5.5"), // *.sub.azzate.ferrario.dev (more specific)
		},
	}

	cases := []struct {
		name      string
		query     string
		wantHit   bool
		wantValue string
	}{
		{"exact apex beats wildcard", "azzate.ferrario.dev", true, "10.9.9.9"},
		{"plain exact", "nas.lan", true, "192.168.1.10"},
		{"single-label subdomain", "foo.azzate.ferrario.dev", true, "10.1.2.3"},
		{"multi-label subdomain", "a.b.azzate.ferrario.dev", true, "10.1.2.3"},
		{"most specific wildcard wins", "x.sub.azzate.ferrario.dev", true, "10.5.5.5"},
		{"sibling is not matched", "notazzate.ferrario.dev", false, ""},
		{"unrelated name", "example.com", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rrs, ok := pol.lookupRewrite(tc.query)
			if ok != tc.wantHit {
				t.Fatalf("lookupRewrite(%q) hit=%v, want %v", tc.query, ok, tc.wantHit)
			}
			if !tc.wantHit {
				return
			}
			if len(rrs) != 1 || rrs[0].Value != tc.wantValue {
				t.Fatalf("lookupRewrite(%q) = %+v, want value %q", tc.query, rrs, tc.wantValue)
			}
		})
	}
}
