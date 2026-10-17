package classifier

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// trustedWorker is a worker whose trusted list holds the given domains and whose
// zone check reports the given zones as resolving.
func trustedWorker(t *testing.T, trusted []string, resolving ...string) (*Worker, *int) {
	t.Helper()
	set, err := parseTrusted(strings.NewReader(strings.Join(trusted, "\n")), 0)
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{trusted: newSetHolder("trusted", false)}
	w.trusted.set.Store(set)
	calls := 0
	w.zoneResolves = func(_ context.Context, domain string) bool {
		calls++
		for _, z := range resolving {
			if z == domain {
				return true
			}
		}
		return false
	}
	return w, &calls
}

func TestTrustedNameservers(t *testing.T) {
	trusted := []string{"apple.com", "cloudflare.com", "domaincontrol.com"}
	rdap := func(ns ...string) WhoisInfo { return WhoisInfo{Source: "rdap", Nameservers: ns} }
	ctx := context.Background()

	// Served only by the brand's own nameservers, and the zone resolves.
	w, _ := trustedWorker(t, trusted, "aaplimg.com")
	if got := w.trustedNameservers(ctx, "aaplimg.com", rdap("a.ns.apple.com", "b.ns.apple.com")); got != "apple.com" {
		t.Errorf("own nameservers: got %q, want apple.com", got)
	}

	// Listed at the registry but the brand's servers don't answer (lame delegation).
	w, _ = trustedWorker(t, trusted)
	if got := w.trustedNameservers(ctx, "evil.com", rdap("a.ns.apple.com")); got != "" {
		t.Errorf("lame delegation trusted as %q", got)
	}

	// The brand's nameserver listed next to the attacker's own: the zone resolves
	// (the attacker's server answers), but that proves nothing about the brand.
	w, calls := trustedWorker(t, trusted, "evil.com")
	if got := w.trustedNameservers(ctx, "evil.com", rdap("ns1.attacker.net", "a.ns.apple.com")); got != "" {
		t.Errorf("mixed delegation trusted as %q", got)
	}
	if *calls != 0 {
		t.Errorf("zone checks = %d, want 0 for a mixed delegation", *calls)
	}

	// Shared DNS hosts serve anyone's zone: never trusted, never even checked.
	w, calls = trustedWorker(t, trusted, "phish.com")
	for _, ns := range []string{"javier.ns.cloudflare.com", "ns1.domaincontrol.com", "ns-1.awsdns-01.com"} {
		if got := w.trustedNameservers(ctx, "phish.com", rdap(ns)); got != "" {
			t.Errorf("shared host %s trusted as %q", ns, got)
		}
	}
	if *calls != 0 {
		t.Errorf("zone checks = %d, want 0 for shared hosts", *calls)
	}

	// Port-43 WHOIS is forgeable in transit: no nameserver trust.
	w, _ = trustedWorker(t, trusted, "aaplimg.com")
	if got := w.trustedNameservers(ctx, "aaplimg.com", WhoisInfo{Source: "whois", Nameservers: []string{"a.ns.apple.com"}}); got != "" {
		t.Errorf("plain WHOIS granted trust: %q", got)
	}
}

// dohServer answers DoH queries: the SOA for zone, SERVFAIL for anything else.
func dohServer(t *testing.T, zone string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		if strings.EqualFold(q.Question[0].Name, dns.Fqdn(zone)) {
			soa, _ := dns.NewRR(dns.Fqdn(zone) + " 300 IN SOA a.ns.apple.com. hostmaster.apple.com. 1 7200 3600 1209600 300")
			m.Answer = append(m.Answer, soa)
		} else {
			m.Rcode = dns.RcodeServerFailure // what a resolver returns for a lame delegation
		}
		out, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	old := dohResolvers
	// The first resolver is unreachable: the second must be tried.
	dohResolvers = []string{"http://127.0.0.1:1/dns-query", srv.URL}
	t.Cleanup(func() {
		srv.Close()
		dohResolvers = old
	})
}

func TestZoneResolves(t *testing.T) {
	dohServer(t, "aaplimg.com")
	if !zoneResolves(context.Background(), "aaplimg.com") {
		t.Error("SOA answer not accepted")
	}
	if zoneResolves(context.Background(), "evil.com") {
		t.Error("SERVFAIL accepted as resolving")
	}
}
