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

// A customer subdomain on a CDN-run hosting platform gets its own verdict; the
// provider's own infrastructure stays trusted.
func TestCDNInfrastructure(t *testing.T) {
	for domain, want := range map[string]bool{
		"cloudfront.net":                true,
		"akamaiedge.net":                true,
		"googleapis.com":                true,
		"evil.web.app":                  false,
		"phish.firebaseapp.com":         false,
		"x.azurewebsites.net":           false,
		"d111111abcdef8.cloudfront.net": false,
		"example.com":                   false,
	} {
		if got := cdnInfrastructure(domain); got != want {
			t.Errorf("cdnInfrastructure(%q) = %v, want %v", domain, got, want)
		}
	}
}
