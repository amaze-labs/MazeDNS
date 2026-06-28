package classifier

import "testing"

// CDN/cloud-edge domains and their subdomains must be recognized as trusted, even
// for providers on the Public Suffix List's private section (cloudfront.net etc.),
// so a verdict can never block a whole provider.
func TestIsCDN(t *testing.T) {
	trusted := []string{
		"cloudflare.net",
		"foo.azurefd.net",     // subdomain
		"d111.cloudfront.net", // PSL private suffix -> subdomain is its own registered domain
		"assets.fastly.net",
		"e1234.akamaiedge.net",
		"x.y.z.amazonaws.com",
		"gstatic.com",
	}
	for _, name := range trusted {
		if !IsCDN(name) {
			t.Errorf("%s should be recognized as CDN/cloud-edge", name)
		}
	}
	for _, name := range []string{"evil.example", "cloudflare.net.evil.com", "notfastly.net"} {
		if IsCDN(name) {
			t.Errorf("%s must NOT be recognized as CDN", name)
		}
	}
}
