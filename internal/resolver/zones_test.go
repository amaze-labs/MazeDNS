package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAuthoritativeZone(t *testing.T) {
	res := New(Options{Zones: []ZoneSpec{{
		Name: "home.lan",
		Records: []ZoneRecordSpec{
			{Name: "@", Type: "A", Value: "192.168.1.1"},
			{Name: "nas", Type: "A", Value: "192.168.1.10"},
		},
	}}})

	ask := func(qname string, qtype uint16) (*dns.Msg, string) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(qname), qtype)
		return res.Resolve(m, "test")
	}

	// apex A
	resp, action := ask("home.lan", dns.TypeA)
	if action != "authoritative" || !resp.Authoritative {
		t.Fatalf("apex: action=%s aa=%v", action, resp.Authoritative)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.168.1.1" {
		t.Fatalf("apex answer: %v", resp.Answer)
	}

	// nas A
	resp, _ = ask("nas.home.lan", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatalf("nas answer: %v", resp.Answer)
	}

	// missing name in zone -> authoritative NXDOMAIN
	resp, _ = ask("nope.home.lan", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("want NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}

	// SOA at apex
	resp, _ = ask("home.lan", dns.TypeSOA)
	if len(resp.Answer) != 1 {
		t.Fatalf("want SOA, got %v", resp.Answer)
	}
	if _, ok := resp.Answer[0].(*dns.SOA); !ok {
		t.Fatalf("not an SOA: %v", resp.Answer[0])
	}

	// outside the zone -> not answered authoritatively
	if _, action := ask("example.com", dns.TypeA); action == "authoritative" {
		t.Fatal("example.com must not be authoritative")
	}
}
