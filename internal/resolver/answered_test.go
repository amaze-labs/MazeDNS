package resolver

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/filter"
)

// forward reports which upstream's response it returned, whatever the
// strategy: the one that answered, the one whose SERVFAIL is relayed when all
// failed softly, and none (-1) when nothing answered.
func TestForwardReportsWinner(t *testing.T) {
	bothStrategies(t, func(t *testing.T, r *Resolver, rt *runtime) {
		ups := []Upstream{
			&fakeUpstream{name: "dead", err: errors.New("boom")},
			&fakeUpstream{name: "backup"},
		}
		resp, _, idx, err := r.forward(rt, newReq(), ups)
		if err != nil || respSource(resp) != "backup" || idx != 1 {
			t.Errorf("failover: source %q, idx %d, err %v; want backup, 1", respSource(resp), idx, err)
		}

		ups = []Upstream{
			&fakeUpstream{name: "refused", rcode: dns.RcodeRefused},
			&fakeUpstream{name: "servfail", rcode: dns.RcodeServerFailure},
		}
		resp, _, idx, err = r.forward(rt, newReq(), ups)
		if err != nil || respSource(resp) != "servfail" || idx != 1 {
			t.Errorf("all soft: source %q, idx %d, err %v; want servfail, 1", respSource(resp), idx, err)
		}

		ups = []Upstream{&fakeUpstream{name: "a", err: errors.New("x")}, &fakeUpstream{name: "b", err: errors.New("y")}}
		if _, _, idx, err = r.forward(rt, newReq(), ups); err == nil || idx != -1 {
			t.Errorf("all failed: idx %d, err %v; want -1 and an error", idx, err)
		}

		if _, _, idx, _ = r.forward(rt, newReq(), []Upstream{&fakeUpstream{name: "only"}}); idx != 0 {
			t.Errorf("single upstream: idx %d, want 0", idx)
		}
	})
}

// An upstream is labelled with its spec as configured (not the normalised
// form), except that a DoH URL keeps only scheme and host: credentials, a
// token in the query, or an account ID in the path (NextDNS, ControlD) must
// never reach the query log, the API or metric labels.
func TestUpstreamLabel(t *testing.T) {
	for spec, want := range map[string]string{
		"1.1.1.1":                                 "1.1.1.1",
		" udp://9.9.9.9:53 ":                      "udp://9.9.9.9:53",
		"tls://1.1.1.1:853#cloudflare-dns.com":    "tls://1.1.1.1:853#cloudflare-dns.com",
		"https://dns.quad9.net/dns-query":         "https://dns.quad9.net",
		"https://user:pw@doh.example/q?token=abc": "https://doh.example",
		"https://dns.nextdns.io/abc123":           "https://dns.nextdns.io",
		"https://bad url":                         "https://(invalid url)",
	} {
		if got := upstreamLabel(spec); got != want {
			t.Errorf("upstreamLabel(%q) = %q, want %q", spec, got, want)
		}
	}
}

// Every forwarded query's event names the upstream that answered it (and the
// conditional forwarder that routed it); answers that didn't go upstream name
// none.
func TestQueryEventNamesUpstream(t *testing.T) {
	dead := newSwitchableUpstream(t)
	dead.blackhole.Store(true)
	backup := newSwitchableUpstream(t)
	corp := newSwitchableUpstream(t)

	var ev QueryEvent
	r := New(Options{Timeout: time.Second, OnQuery: func(e *QueryEvent) { ev = *e }})
	deadSpec, backupSpec, corpSpec := "udp://"+dead.addr(), backup.addr(), "udp://"+corp.addr()
	r.ApplySettings(Settings{
		Upstreams:         []string{deadSpec, backupSpec},
		Forwarders:        []ForwardGroup{{Suffix: "Corp.Internal.", Upstreams: []string{corpSpec}}},
		UpstreamTimeoutMs: 100,
		Cache:             CacheSettings{Enabled: true, MaxEntries: 100},
	})
	r.SetPolicy(&Policy{Block: filter.New(), Allow: filter.New(),
		Rewrites: map[string][]RewriteRR{"nas.lan": {{Type: dns.TypeA, Value: "10.0.0.5"}}}})

	ask := func(name string) QueryEvent {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		ev = QueryEvent{}
		r.Handle(&stubRW{}, req)
		return ev
	}
	for _, tc := range []struct {
		name, action, upstream, forwarder string
	}{
		{"example.com.", "forward", backupSpec, ""}, // the first upstream is down
		{"example.com.", "cache", "", ""},
		{"db.corp.internal.", "forward", corpSpec, "corp.internal"},
		{"nas.lan.", "rewrite", "", ""},
	} {
		got := ask(tc.name)
		if got.Action != tc.action || got.Upstream != tc.upstream || got.Forwarder != tc.forwarder {
			t.Errorf("%s: action %q upstream %q forwarder %q; want %q, %q, %q",
				tc.name, got.Action, got.Upstream, got.Forwarder, tc.action, tc.upstream, tc.forwarder)
		}
	}
}
