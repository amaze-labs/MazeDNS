package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// legacyConfigHash is the original configHash, kept verbatim as the reference:
// agents in the field compute exactly this, so the optimized implementation
// must stay byte-identical to it.
func legacyConfigHash(rules []Rule, rewrites []Rewrite, fws []ForwardSpec) string {
	lines := make([]string, 0, len(rules)+len(rewrites)+len(fws))
	for _, r := range rules {
		lines = append(lines, fmt.Sprintf("R|%s|%s|%s|%t", r.Action, r.Domain, r.Category, r.Enabled))
	}
	for _, rw := range rewrites {
		lines = append(lines, fmt.Sprintf("W|%s|%s|%s|%t", rw.Domain, rw.RRType, rw.Value, rw.Enabled))
	}
	for _, f := range fws {
		lines = append(lines, fmt.Sprintf("F|%s|%s", f.Suffix, strings.Join(f.Upstreams, ",")))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])[:12]
}

func TestConfigHashMatchesLegacyFormat(t *testing.T) {
	// Enough rules that the streamed join crosses several 64 KiB buffer flushes,
	// plus one line longer than the buffer itself.
	var many []Rule
	for i := 0; i < 20000; i++ {
		many = append(many, Rule{Action: []string{"deny", "allow"}[i%2], Domain: fmt.Sprintf("d%05d.example.lan", i),
			Category: []string{"ads", "", "custom"}[i%3], Enabled: i%7 != 0})
	}
	many = append(many, Rule{Action: "deny", Domain: strings.Repeat("x", 70<<10) + ".example.lan", Category: "ads", Enabled: true})

	cases := []struct {
		name  string
		rules []Rule
		rws   []Rewrite
		fws   []ForwardSpec
	}{
		{name: "empty"},
		{name: "single rule", rules: []Rule{{Action: "deny", Domain: "ads.example.lan", Category: "ads", Enabled: true}}},
		{
			name: "mixed",
			rules: []Rule{
				{Action: "deny", Domain: "b.example.lan", Category: "", Enabled: false},
				{Action: "allow", Domain: "a.example.lan", Category: "custom", Enabled: true},
				{Action: "deny", Domain: "ünïcode.example.lan", Category: "malware", Enabled: true},
			},
			rws: []Rewrite{
				{Domain: "nas.example.lan", RRType: "A", Value: "192.0.2.10", Enabled: true},
				{Domain: "nas.example.lan", RRType: "AAAA", Value: "2001:db8::10", Enabled: false},
			},
			fws: []ForwardSpec{
				{Suffix: "corp.example.lan", Upstreams: []string{"192.0.2.53:53", "192.0.2.54:53"}},
				{Suffix: "empty.example.lan"},
			},
		},
		{name: "large", rules: many, rws: []Rewrite{{Domain: "x.example.lan", RRType: "CNAME", Value: "y.example.lan", Enabled: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Copies: configHash sorts its own lines, but keep inputs pristine anyway.
			want := legacyConfigHash(append([]Rule(nil), tc.rules...), tc.rws, tc.fws)
			if got := configHash(tc.rules, tc.rws, tc.fws); got != want {
				t.Fatalf("configHash = %q, legacy = %q", got, want)
			}
		})
	}
}

func BenchmarkConfigHash(b *testing.B) {
	rules := make([]Rule, 0, 100000)
	for i := 0; i < cap(rules); i++ {
		rules = append(rules, Rule{Action: "deny", Domain: fmt.Sprintf("host-%06d.ads.example.lan", i), Category: "ads", Enabled: true})
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = configHash(rules, nil, nil)
	}
}
