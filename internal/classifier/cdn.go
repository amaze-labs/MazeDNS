package classifier

import "strings"

// CDNTrustedDomains is a curated allowlist of CDN / cloud-edge infrastructure
// registered domains. Because the classifier works at the registered-domain
// (eTLD+1) level, a verdict on one of these would apply to ALL traffic on that
// provider — so flagging "cloudfront.net" or "akamaiedge.net" would block a huge
// swath of legitimate sites. These are always trusted (unioned into the trusted
// set regardless of the popularity-list settings) to prevent exactly that class
// of false positive. Confirmed-malicious hostnames are still handled by the
// blocklists/threat feeds at the full-hostname level upstream.
var CDNTrustedDomains = []string{
	// Cloudflare
	"cloudflare.com", "cloudflare.net", "cloudflarestream.com", "cloudflare-dns.com",
	"cloudflareinsights.com", "cloudflareclient.com", "cloudflareaccess.com", "cdnjs.com",
	// Akamai
	"akamai.net", "akamaiedge.net", "akamaihd.net", "akamaitechnologies.com",
	"akamaized.net", "edgekey.net", "edgesuite.net", "akadns.net", "akamaistream.net",
	// Fastly
	"fastly.net", "fastlylb.net", "fastly-edge.com",
	// Amazon / AWS
	"cloudfront.net", "amazonaws.com", "awsstatic.com", "amplifyapp.com",
	"awsglobalaccelerator.com", "elasticbeanstalk.com",
	// Microsoft / Azure
	"azurefd.net", "azureedge.net", "azureedge.com", "azure.com", "azurewebsites.net",
	"windows.net", "trafficmanager.net", "msecnd.net", "aspnetcdn.com", "azure-api.net",
	"azurestaticapps.net", "cloudapp.net", "azure-dns.com", "azurefd.com",
	"microsoft.com", "msftconnecttest.com", "s-microsoft.com", "msft.net", "msauth.net",
	// Google
	"googleusercontent.com", "gstatic.com", "googleapis.com", "ggpht.com",
	"googlevideo.com", "google.com", "withgoogle.com", "appspot.com",
	"web.app", "firebaseapp.com", "gvt1.com", "gvt2.com", "ytimg.com",
	// Apple
	"mzstatic.com", "cdn-apple.com", "aaplimg.com",
	// Independent CDNs
	"jsdelivr.net", "unpkg.com", "stackpathdns.com", "stackpathcdn.com",
	"bunny.net", "b-cdn.net", "bunnycdn.com", "cdn77.org", "cdn77.com",
	"kxcdn.com", "cachefly.net", "edgecastcdn.net", "hwcdn.net", "llnwd.net",
	"lldns.net", "footprint.net", "keycdn.com", "gcore.com", "gcdn.co",
	"netdna-ssl.com", "netdna-cdn.com", "maxcdn.com", "swiftcdn.com",
	// Major app CDNs (whole-provider domains)
	"fbcdn.net", "cdninstagram.com", "twimg.com", "licdn.com", "pinimg.com",
	"redditstatic.com", "redditmedia.com", "wp.com", "gravatar.com", "vimeocdn.com",
}

// cdnSuffixes indexes CDNTrustedDomains for fast lookup.
var cdnSuffixes = func() map[string]struct{} {
	m := make(map[string]struct{}, len(CDNTrustedDomains))
	for _, d := range CDNTrustedDomains {
		m[d] = struct{}{}
	}
	return m
}()

// IsCDN reports whether name is (a subdomain of) a known CDN / cloud-edge
// provider. It walks the name's parent suffixes rather than using the registered
// domain, because many CDN bases (e.g. cloudfront.net, azureedge.net) are on the
// Public Suffix List's private section — so each subdomain's "registered domain"
// is the full host, and a plain set lookup would never match the provider.
func IsCDN(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	for name != "" {
		if _, ok := cdnSuffixes[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
	return false
}

// CDNCount returns the number of CDN/cloud-edge providers on the allowlist.
func CDNCount() int { return len(CDNTrustedDomains) }
