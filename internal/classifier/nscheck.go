package classifier

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Nameserver ownership: a domain served only by a trusted company's OWN
// nameservers (aaplimg.com on a.ns.apple.com) is that company's infrastructure.
// It is weighed as a trust factor (see computeScore), and three things that
// could fake it are ruled out first:
//
//   - a shared DNS host serves anyone's zone: a domain on *.ns.cloudflare.com or
//     ns1.domaincontrol.com says nothing about its owner, even though the host's
//     own domain is popular (sharedDNSHost);
//   - anyone can LIST a brand's nameservers at their registrar, alone or next to
//     their own: so EVERY listed nameserver must be the brand's, and the zone
//     must actually resolve — with only the brand's servers to ask, a resolver
//     can only get an answer from them (a lame delegation fails);
//   - that answer is fetched over DNS-over-HTTPS from a public resolver, so it
//     can't be forged between the control plane and the nameserver.

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

const nsCheckTimeout = 5 * time.Second

// dohResolvers answer zoneResolves over HTTPS; the second is tried only if the
// first can't be reached (overridden in tests).
var dohResolvers = []string{"https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"}

// zoneResolves reports whether domain's zone answers: a recursive SOA query over
// DoH must come back NOERROR with the domain's SOA.
func zoneResolves(ctx context.Context, domain string) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	packed, err := m.Pack()
	if err != nil {
		return false
	}
	for _, u := range dohResolvers {
		resp, err := dohQuery(ctx, u, packed)
		if err != nil {
			continue // resolver unreachable: try the next one
		}
		if resp.Rcode != dns.RcodeSuccess {
			return false
		}
		for _, rr := range resp.Answer {
			if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(domain)) {
				return true
			}
		}
		return false
	}
	return false
}

func dohQuery(ctx context.Context, url string, packed []byte) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, nsCheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}
