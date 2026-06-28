package classifier

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleRDAP = `{
  "status": ["client transfer prohibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2030-01-15T00:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2024-01-10T00:00:00Z"}
  ],
  "entities": [
    {"roles": ["registrar"], "vcardArray": ["vcard", [["version",{},"text","4.0"],["fn",{},"text","Example Registrar, Inc."]]]},
    {"roles": ["registrant"], "vcardArray": ["vcard", [["version",{},"text","4.0"],["fn",{},"text","Jane Doe"],["org",{},"text","Apple Inc."]]]}
  ],
  "nameservers": [{"ldhName": "A.NS.APPLE.COM"}, {"ldhName": "B.NS.APPLE.COM"}]
}`

func TestParseRDAP(t *testing.T) {
	var rd rdapResp
	if err := json.Unmarshal([]byte(sampleRDAP), &rd); err != nil {
		t.Fatal(err)
	}
	info := parseRDAP("example.com", rd)
	if info.Created != "2020-01-15T00:00:00Z" {
		t.Errorf("created = %q", info.Created)
	}
	if info.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar = %q", info.Registrar)
	}
	if len(info.Nameservers) != 2 || info.Nameservers[0] != "a.ns.apple.com" {
		t.Errorf("nameservers = %v", info.Nameservers)
	}
	if info.Registrant != "Apple Inc." {
		t.Errorf("registrant org = %q, want Apple Inc.", info.Registrant)
	}
	if info.AgeDays < 1500 { // registered in 2020 — comfortably old
		t.Errorf("age_days = %d, expected a large number", info.AgeDays)
	}
	// The summary fed to the model must carry the ownership signals (registrant +
	// nameservers) so it won't flag a brand's own domain as phishing.
	s := info.summary()
	for _, want := range []string{"Apple Inc.", "a.ns.apple.com", "registrar"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q: %q", want, s)
		}
	}
}

func TestWhoisSummaryYoungDomain(t *testing.T) {
	s := WhoisInfo{Created: "2020-01-01T00:00:00Z", AgeDays: 10, Registrar: "R"}.summary()
	if !strings.Contains(s, "very new") {
		t.Errorf("a 10-day-old domain should be flagged new: %q", s)
	}
}
