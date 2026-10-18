package classifier

import (
	"reflect"
	"strings"
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

func TestValidWhoisHost(t *testing.T) {
	for h, want := range map[string]bool{
		"whois.nic.io":           true,
		"WHOIS.DENIC.DE":         true,
		"127.0.0.1":              false,
		"::1":                    false,
		"localhost":              false,
		"whois.nic.io:8080":      false,
		"evil.example/x":         false,
		"whois nic io":           false,
		strings.Repeat("a", 254): false,
	} {
		if got := validWhoisHost(h); got != want {
			t.Errorf("validWhoisHost(%q) = %v, want %v", h, got, want)
		}
	}
}

func TestPublicOnlyRefusesInternalAddresses(t *testing.T) {
	for addr, ok := range map[string]bool{
		"199.7.85.13:43":        true, // whois.iana.org
		"127.0.0.1:43":          false,
		"10.0.0.5:43":           false,
		"192.168.1.1:43":        false,
		"169.254.169.254:43":    false, // cloud metadata
		"[::1]:43":              false,
		"[fd00::1]:43":          false,
		"0.0.0.0:43":            false,
		"0.1.2.3:43":            false, // "this network" reaches the local host
		"100.64.0.1:43":         false, // NetBird / Tailscale / carrier NAT
		"[::ffff:127.0.0.1]:43": false,
		"[64:ff9b::a00:1]:43":   false, // NAT64 of 10.0.0.1
		"[2001:500:88::2]:43":   true,
	} {
		if err := publicOnly("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("publicOnly(%s) err = %v, want allowed=%v", addr, err, ok)
		}
	}
}

// EURid (.eu): values grouped under section headers; no creation date at all.
const sampleWhoisEURid = `% The WHOIS service offered by EURid is for informational purposes only.
Domain: campaign-image.eu
Script: LATIN

Registrant:
        NOT DISCLOSED!
        Visit www.eurid.eu for the web-based WHOIS.

Registrar:
        Name: MarkMonitor International Limited
        Website: https://www.markmonitor.com/

Name servers:
        ns11.zns-53.com
        pdns90.ultradns.biz

Please visit www.eurid.eu for more info.
`

// Nominet (.uk): indented headers, CRLF line endings, glue after nameservers.
const sampleWhoisNominet = "\r\n    Domain name:\r\n        bbc.co.uk\r\n\r\n" +
	"    Registrar:\r\n        British Broadcasting Corporation [Tag = BBC]\r\n        URL: https://www.bbc.co.uk\r\n\r\n" +
	"    Relevant dates:\r\n        Registered on: 05-Aug-1996\r\n        Expiry date:  13-Dec-2034\r\n\r\n" +
	"    Name servers:\r\n        ddns0.bbc.co.uk           148.163.199.1  2607:f740:e04e::1\r\n        ddns0.bbc.com\r\n\r\n" +
	"    WHOIS lookup made at 08:41:49 18-Oct-2026\r\n"

func TestParseWhois43Sections(t *testing.T) {
	eu := parseWhois43("campaign-image.eu", sampleWhoisEURid)
	if eu.Registrar != "MarkMonitor International Limited" {
		t.Errorf(".eu registrar = %q", eu.Registrar)
	}
	if want := []string{"ns11.zns-53.com", "pdns90.ultradns.biz"}; !reflect.DeepEqual(eu.Nameservers, want) {
		t.Errorf(".eu nameservers = %v, want %v", eu.Nameservers, want)
	}
	if eu.Registrant != "" || eu.AgeDays != 0 {
		t.Errorf(".eu registrant = %q, age = %d; want neither", eu.Registrant, eu.AgeDays)
	}

	uk := parseWhois43("bbc.co.uk", sampleWhoisNominet)
	if uk.Registrar != "British Broadcasting Corporation" {
		t.Errorf(".uk registrar = %q", uk.Registrar)
	}
	if want := []string{"ddns0.bbc.co.uk", "ddns0.bbc.com"}; !reflect.DeepEqual(uk.Nameservers, want) {
		t.Errorf(".uk nameservers = %v, want %v", uk.Nameservers, want)
	}
	if uk.Created != "05-Aug-1996" || uk.AgeDays <= 0 || uk.Expires != "13-Dec-2034" {
		t.Errorf(".uk created = %q (age %d), expires = %q", uk.Created, uk.AgeDays, uk.Expires)
	}
}

// Trimmed real replies from whois.jprs.jp (queried with "/e"): a plain .jp
// name, and a co.jp name with its item letters and no registered date.
const sampleWhoisJP = `[ JPRS database provides information on network administration. Its use is    ]
[ at the end of command, e.g. 'whois -h whois.jprs.jp xxx/e'.                 ]
Domain Information:
[Domain Name]                   520.JP

[Registrant]                    . Sakura

[Name Server]                   ajay.ns.cloudflare.com
[Name Server]                   gina.ns.cloudflare.com
[Signing Key]                   2371 13 2 (
                                614A5EB71B4171F819359F5476E712B5 )

[Created on]                    2022/05/23
[Expires on]                    2027/05/31
[Status]                        Active
[Last Updated]                  2026/06/01 01:05:03 (JST)

Contact Information:
[Name]                          . Sakura
`

const sampleWhoisCoJP = `Domain Information:
a. [Domain Name]                SONY.CO.JP
g. [Organization]               Sony Group Corporation
l. [Organization Type]          Corporation
p. [Name Server]                a1-166.akam.net
p. [Name Server]                a13-66.akam.net
s. [Signing Key]                
[State]                         Connected (2027/03/31)
[Registered Date]                
[Connected Date]                2011/04/15
[Last Update]                   2026/04/01 01:03:06 (JST)
`

func TestParseWhois43JPRS(t *testing.T) {
	jp := parseWhois43("520.jp", sampleWhoisJP)
	if jp.Created != "2022/05/23" || jp.Expires != "2027/05/31" || jp.Updated != "2026/06/01 01:05:03 (JST)" ||
		jp.Registrant != ". Sakura" || jp.AgeDays <= 0 {
		t.Errorf("520.jp: %+v", jp)
	}
	if want := []string{"ajay.ns.cloudflare.com", "gina.ns.cloudflare.com"}; !reflect.DeepEqual(jp.Nameservers, want) {
		t.Errorf("520.jp nameservers = %v", jp.Nameservers)
	}
	if !reflect.DeepEqual(jp.Status, []string{"Active"}) {
		t.Errorf("520.jp status = %v", jp.Status)
	}

	co := parseWhois43("sony.co.jp", sampleWhoisCoJP)
	if co.Created != "2011/04/15" || co.Registrant != "Sony Group Corporation" || len(co.Nameservers) != 2 ||
		!reflect.DeepEqual(co.Status, []string{"Connected"}) || co.AgeDays < 5000 {
		t.Errorf("sony.co.jp: %+v", co)
	}
}
