package ruleimport

import "testing"

func TestParse(t *testing.T) {
	in := `
! Title: test list
[Adblock Plus 2.0]
||ads.example.com^
||tracker.example.com^$third-party
@@||good.example.com^
||example.com/path^
/regex.*/
||*.wild.com^
0.0.0.0 hosts-blocked.test
127.0.0.1 localhost
plain-domain.test
# trailing comment
`
	got := map[string]string{} // domain -> action
	for _, r := range Parse(in) {
		got[r.Domain] = r.Action
	}

	want := map[string]string{
		"ads.example.com":     "deny",
		"tracker.example.com": "deny",
		"good.example.com":    "allow",
		"hosts-blocked.test":  "deny",
		"plain-domain.test":   "deny",
	}
	for d, a := range want {
		if got[d] != a {
			t.Errorf("domain %q: action=%q, want %q", d, got[d], a)
		}
	}
	// Path/wildcard/regex/localhost must be rejected (not over-blocked).
	for _, bad := range []string{"example.com", "wild.com", "*.wild.com", "localhost"} {
		if _, ok := got[bad]; ok {
			t.Errorf("did not expect a rule for %q", bad)
		}
	}
}
