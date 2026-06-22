package resolver

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/filter"
)

// ZoneRecordSpec is one configured record in an authoritative zone.
type ZoneRecordSpec struct {
	Name  string // relative label(s); "@" or "" means the apex
	Type  string // A | AAAA | CNAME | TXT | MX
	Value string
	TTL   uint32
}

// ZoneSpec is an authoritative zone from config.
type ZoneSpec struct {
	Name    string
	Records []ZoneRecordSpec
}

type zone struct {
	apex    string
	soa     *dns.SOA
	ns      []dns.RR
	records map[string][]dns.RR // owner FQDN (normalized, no trailing dot) -> records
}

// Zones holds the authoritative zones, ordered longest-apex-first.
type Zones struct {
	list []*zone
}

// NewZones builds the authoritative zone set from specs.
func NewZones(specs []ZoneSpec) *Zones {
	zs := &Zones{}
	for _, s := range specs {
		apex := filter.Normalize(s.Name)
		if apex == "" {
			continue
		}
		z := &zone{apex: apex, records: map[string][]dns.RR{}}
		z.soa = &dns.SOA{
			Hdr:     dns.RR_Header{Name: dns.Fqdn(apex), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns." + dns.Fqdn(apex),
			Mbox:    "hostmaster." + dns.Fqdn(apex),
			Serial:  uint32(time.Now().Unix()),
			Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 300,
		}
		z.ns = []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{Name: dns.Fqdn(apex), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns." + dns.Fqdn(apex),
		}}
		for _, rs := range s.Records {
			owner := recordOwner(rs.Name, apex)
			if rr, ok := buildRR(owner, rs); ok {
				z.records[owner] = append(z.records[owner], rr)
			}
		}
		zs.list = append(zs.list, z)
	}
	sort.Slice(zs.list, func(i, j int) bool { return len(zs.list[i].apex) > len(zs.list[j].apex) })
	return zs
}

// match returns the most-specific zone authoritative for name, or nil.
func (zs *Zones) match(name string) *zone {
	for _, z := range zs.list {
		if name == z.apex || strings.HasSuffix(name, "."+z.apex) {
			return z
		}
	}
	return nil
}

// answer builds an authoritative reply for a query whose name is inside z.
func (z *zone) answer(req *dns.Msg, q dns.Question, name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	if name == z.apex {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, z.soa)
			return m
		case dns.TypeNS:
			m.Answer = append(m.Answer, z.ns...)
			return m
		}
	}

	recs := z.records[name]
	if len(recs) == 0 {
		m.Rcode = dns.RcodeNameError // authoritative NXDOMAIN
		m.Ns = append(m.Ns, z.soa)
		return m
	}

	matched := false
	for _, rr := range recs {
		if rr.Header().Rrtype == q.Qtype {
			m.Answer = append(m.Answer, rr)
			matched = true
		}
	}
	if !matched { // CNAME fallback (clients re-resolve the target)
		for _, rr := range recs {
			if rr.Header().Rrtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, rr)
				matched = true
			}
		}
	}
	if !matched { // NODATA: name exists, type does not
		m.Ns = append(m.Ns, z.soa)
	}
	return m
}

func recordOwner(name, apex string) string {
	n := filter.Normalize(name)
	if n == "" || n == "@" {
		return apex
	}
	if n == apex || strings.HasSuffix(n, "."+apex) {
		return n
	}
	return n + "." + apex
}

func buildRR(owner string, rs ZoneRecordSpec) (dns.RR, bool) {
	ttl := rs.TTL
	if ttl == 0 {
		ttl = 300
	}
	hdr := dns.RR_Header{Name: dns.Fqdn(owner), Class: dns.ClassINET, Ttl: ttl}
	switch strings.ToUpper(rs.Type) {
	case "A":
		ip := net.ParseIP(rs.Value)
		if ip == nil || ip.To4() == nil {
			return nil, false
		}
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: ip.To4()}, true
	case "AAAA":
		ip := net.ParseIP(rs.Value)
		if ip == nil || ip.To4() != nil {
			return nil, false
		}
		hdr.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: hdr, AAAA: ip}, true
	case "CNAME":
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(rs.Value)}, true
	case "TXT":
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: []string{rs.Value}}, true
	case "MX":
		parts := strings.Fields(rs.Value)
		if len(parts) != 2 {
			return nil, false
		}
		pref, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, false
		}
		hdr.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: hdr, Preference: uint16(pref), Mx: dns.Fqdn(parts[1])}, true
	}
	return nil, false
}
