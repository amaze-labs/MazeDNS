package classifier

import (
	"reflect"
	"testing"
)

// Trimmed real replies from whois.nic.io (ICANN style) and whois.denic.de.
const sampleWhoisIO = `Domain Name: socialsnowball.io
Registry Domain ID: REDACTED
Registrar WHOIS Server: whois.godaddy.com
Updated Date: 2024-11-30T10:01:12Z
Creation Date: 2019-12-16T15:27:33Z
Registry Expiry Date: 2027-12-16T15:27:33Z
Registrar: GoDaddy.com, LLC
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Organization: REDACTED FOR PRIVACY
Name Server: JAVIER.NS.CLOUDFLARE.COM
Name Server: addilyn.ns.cloudflare.com
DNSSEC: unsigned
`

const sampleWhoisDENIC = `% Restricted rights.
% available at the DENIC website:
% https://webwhois.denic.de/?lang=en

Domain: heise.de
Nserver: ns2.pop-hannover.net
Nserver: ns.heise.de 193.99.145.37 2a00:e68:14:800:0:0:0:d1ce
Status: connect
Changed: 2018-12-17T17:11:43+01:00
`

func TestParseWhois43ICANNStyle(t *testing.T) {
	info := parseWhois43("socialsnowball.io", sampleWhoisIO)
	if info.Created != "2019-12-16T15:27:33Z" || info.AgeDays <= 0 {
		t.Errorf("created = %q, age = %d", info.Created, info.AgeDays)
	}
	if info.Expires != "2027-12-16T15:27:33Z" || info.Registrar != "GoDaddy.com, LLC" {
		t.Errorf("expires = %q, registrar = %q", info.Expires, info.Registrar)
	}
	if info.Registrant != "" {
		t.Errorf("redacted registrant kept: %q", info.Registrant)
	}
	if want := []string{"javier.ns.cloudflare.com", "addilyn.ns.cloudflare.com"}; !reflect.DeepEqual(info.Nameservers, want) {
		t.Errorf("nameservers = %v", info.Nameservers)
	}
	if want := []string{"clientDeleteProhibited", "clientTransferProhibited"}; !reflect.DeepEqual(info.Status, want) {
		t.Errorf("status = %v", info.Status)
	}
	if info.DNSSEC || info.Source != "whois" {
		t.Errorf("dnssec = %v, source = %q", info.DNSSEC, info.Source)
	}
}

// DENIC publishes no creation date: age stays unknown, the rest is still read.
func TestParseWhois43DENIC(t *testing.T) {
	info := parseWhois43("heise.de", sampleWhoisDENIC)
	if info.AgeDays != 0 || info.Created != "" {
		t.Errorf("age = %d, created = %q", info.AgeDays, info.Created)
	}
	if want := []string{"ns2.pop-hannover.net", "ns.heise.de"}; !reflect.DeepEqual(info.Nameservers, want) {
		t.Errorf("nameservers = %v", info.Nameservers)
	}
	if info.Updated != "2018-12-17T17:11:43+01:00" {
		t.Errorf("updated = %q", info.Updated)
	}
}

func TestParseRDAPDateWhoisShapes(t *testing.T) {
	for _, s := range []string{"2019-12-16 15:27:33", "16-Dec-2019", "2019.12.16", "2019/12/16", "2019-12-16 (YYYY-MM-DD)"} {
		if _, ok := parseRDAPDate(s); !ok {
			t.Errorf("parseRDAPDate(%q) failed", s)
		}
	}
}

func TestIsReservedName(t *testing.T) {
	for name, want := range map[string]bool{
		"this-url-does-not-exist-1234.invalid": true,
		"printer.local.":                       true,
		"nas.home.arpa":                        true,
		"router.lan":                           true,
		"www.example.com":                      true,
		"example.org":                          true,
		"exampleshop.com":                      false,
		"google.com":                           false,
		"socialsnowball.io":                    false,
	} {
		if got := IsReservedName(name); got != want {
			t.Errorf("IsReservedName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestHostingPlatform(t *testing.T) {
	for name, want := range map[string]string{
		"evecurls.workers.dev":     "workers.dev",
		"a.b.evecurls.workers.dev": "workers.dev",
		"someone.github.io":        "github.io",
		"site.netlify.app":         "netlify.app",
		"workers.dev":              "", // the platform itself
		"google.com":               "",
		"bbc.co.uk":                "", // ICANN suffix, a real registration
	} {
		if got := HostingPlatform(name); got != want {
			t.Errorf("HostingPlatform(%q) = %q, want %q", name, got, want)
		}
	}
}
