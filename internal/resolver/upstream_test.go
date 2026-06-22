package resolver

import (
	"testing"
	"time"
)

func TestParseUpstream(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":                              "udp://1.1.1.1:53",
		"udp://8.8.8.8:53":                     "udp://8.8.8.8:53",
		"tcp://8.8.8.8":                        "tcp://8.8.8.8:53",
		"tls://1.1.1.1:853#cloudflare-dns.com": "tls://1.1.1.1:853",
		"https://dns.quad9.net/dns-query":      "https://dns.quad9.net/dns-query",
	}
	for spec, want := range cases {
		u, err := ParseUpstream(spec, time.Second)
		if err != nil {
			t.Fatalf("ParseUpstream(%q): %v", spec, err)
		}
		if got := u.String(); got != want {
			t.Errorf("ParseUpstream(%q).String() = %q, want %q", spec, got, want)
		}
	}
}
