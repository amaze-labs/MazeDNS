package resolver

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// buildReverse derives the PTR answers implied by exact A/AAAA rewrites:
// reverse name ("<reversed-ip>.in-addr.arpa" / "...ip6.arpa", lowercase, no
// trailing dot) -> the host name to answer with. Wildcard rewrites never
// contribute (they name no single host), nor do CNAMEs or values of the wrong
// address family. When several names point at one address, the preferred one
// is kept — shortest, then alphabetical — so every client (and the control
// plane's client naming, which uses the same rule) sees the same single name
// regardless of how intermediate resolvers order a multi-record RRset.
func buildReverse(rewrites map[string][]RewriteRR) map[string]string {
	out := map[string]string{}
	for name, rrs := range rewrites {
		if name == "" || strings.Contains(name, "*") {
			continue
		}
		for _, rr := range rrs {
			rev, ok := reverseNameFor(rr)
			if !ok {
				continue
			}
			if cur, taken := out[rev]; !taken || preferName(name, cur) {
				out[rev] = name
			}
		}
	}
	return out
}

// reverseNameFor returns the reverse-lookup name for an address rewrite. An A
// record must hold an IPv4 address and an AAAA record a genuine IPv6 one.
func reverseNameFor(rr RewriteRR) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(rr.Value))
	if ip == nil {
		return "", false
	}
	switch rr.Type {
	case dns.TypeA:
		if ip.To4() == nil {
			return "", false
		}
	case dns.TypeAAAA:
		if ip.To4() != nil {
			return "", false
		}
	default:
		return "", false
	}
	rev, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(rev, "."), true
}

// preferName reports whether a should be preferred over b: shorter first, then
// alphabetical.
func preferName(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// rewritePTR answers a PTR query from the rewrite-derived reverse map, or
// returns nil to let the query continue down the pipeline. A conditional
// forwarder covering the reverse name wins over the synthesized answer: the
// forwarder is an explicit routing decision for that reverse zone (e.g. to a
// DHCP server that owns the PTRs), while the PTR is only implied by a forward
// record. Authoritative zones are matched earlier and win as well.
func (r *Resolver) rewritePTR(rt *runtime, pol *Policy, req *dns.Msg, q dns.Question, name string) *dns.Msg {
	target, ok := pol.reverse[name]
	if !ok {
		return nil
	}
	if _, fwd := conditionalFor(rt, name); fwd {
		return nil
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.Answer = append(m.Answer, &dns.PTR{Hdr: rrHeader(q.Name, dns.TypePTR), Ptr: dns.Fqdn(target)})
	return m
}
