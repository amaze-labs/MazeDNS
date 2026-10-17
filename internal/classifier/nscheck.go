package classifier

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Nameserver trust: a domain served by a trusted company's OWN nameservers
// (aaplimg.com on a.ns.apple.com) is that company's infrastructure. Two things
// can fake that, so both are checked before the trusted shortcut is granted:
//
//   - a shared DNS host serves anyone's zone: a domain on *.ns.cloudflare.com or
//     ns1.domaincontrol.com says nothing about its owner, even though the host's
//     own domain is popular (sharedDNSHost);
//   - anyone can LIST a brand's nameservers at their registrar; the registry
//     then reports them, but the brand's servers won't answer for that zone
//     (servesZone asks one directly).

// sharedDNSHosts are registered domains of DNS hosting providers, registrars'
// default nameservers and parking services: their nameservers serve customers'
// zones, so they never vouch for a domain.
var sharedDNSHosts = map[string]bool{
	"cloudflare.com": true, "akam.net": true, "akamaiedge.net": true, "akadns.net": true,
	"azure-dns.com": true, "azure-dns.net": true, "azure-dns.org": true, "azure-dns.info": true,
	"googledomains.com": true, "domaincontrol.com": true, "registrar-servers.com": true,
	"nsone.net": true, "dynect.net": true, "ultradns.com": true, "ultradns.net": true,
	"ultradns.org": true, "ultradns.biz": true, "ultradns.info": true, "dnsmadeeasy.com": true,
	"dnsimple.com": true, "dnsimple-edge.net": true, "dnsimple-edge.org": true,
	"digitalocean.com": true, "linode.com": true, "hetzner.com": true, "hetzner.de": true,
	"ovh.net": true, "gandi.net": true, "name.com": true, "porkbun.com": true,
	"cloudns.net": true, "he.net": true, "wixdns.net": true, "squarespacedns.com": true,
	"vercel-dns.com": true, "wordpress.com": true, "bluehost.com": true, "hostgator.com": true,
	"siteground.net": true, "ui-dns.com": true, "ui-dns.de": true, "ui-dns.org": true,
	"ui-dns.biz": true, "one.com": true, "afraid.org": true, "dns-parking.com": true,
	"worldnic.com": true, "name-services.com": true, "dnsowl.com": true, "dreamhost.com": true,
	"sedoparking.com": true, "bodis.com": true, "parkingcrew.net": true, "above.com": true,
	"namebrightdns.com": true, "hostinger.com": true, "netlify.com": true, "shopify.com": true,
}

// sharedDNSHost reports whether a nameserver's registered domain belongs to a
// shared DNS host. Route 53 spreads over awsdns-NN.{com,net,org,co.uk}.
func sharedDNSHost(nsReg string) bool {
	return sharedDNSHosts[nsReg] || strings.HasPrefix(nsReg, "awsdns-")
}

const nsCheckTimeout = 3 * time.Second

// nsCheckPort is the DNS port servesZone queries (overridden in tests).
var nsCheckPort = "53"

// servesZone reports whether nameserver ns answers authoritatively for domain:
// an SOA query without recursion must come back NOERROR with the AA bit and the
// domain's SOA. A nameserver merely listed at the registry (lame delegation)
// answers REFUSED or a referral instead.
func servesZone(ctx context.Context, domain, ns string) bool {
	ctx, cancel := context.WithTimeout(ctx, nsCheckTimeout)
	defer cancel()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.RecursionDesired = false
	c := &dns.Client{Timeout: nsCheckTimeout}
	resp, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort(ns, nsCheckPort))
	if err != nil || resp == nil || !resp.Authoritative || resp.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(domain)) {
			return true
		}
	}
	return false
}
