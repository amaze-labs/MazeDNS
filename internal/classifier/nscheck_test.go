package classifier

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// trustedWorker is a worker whose trusted list holds the given domains and whose
// zone check answers true only for the listed nameservers.
func trustedWorker(t *testing.T, trusted []string, serving ...string) (*Worker, *int) {
	t.Helper()
	set, err := parseTrusted(strings.NewReader(strings.Join(trusted, "\n")), 0)
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{trusted: newSetHolder("trusted", false)}
	w.trusted.set.Store(set)
	calls := 0
	w.servesZone = func(_ context.Context, _, ns string) bool {
		calls++
		for _, s := range serving {
			if s == ns {
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

	// A brand's own nameservers that really serve the zone.
	w, _ := trustedWorker(t, trusted, "a.ns.apple.com")
	if got := w.trustedNameservers(context.Background(), "aaplimg.com", rdap("a.ns.apple.com")); got != "apple.com" {
		t.Errorf("own nameservers: got %q, want apple.com", got)
	}

	// Listed at the registry but not answering for the zone (lame delegation).
	w, _ = trustedWorker(t, trusted)
	if got := w.trustedNameservers(context.Background(), "evil.com", rdap("a.ns.apple.com")); got != "" {
		t.Errorf("lame delegation trusted as %q", got)
	}

	// Shared DNS hosts serve anyone's zone: never trusted, never even queried.
	w, calls := trustedWorker(t, trusted, "javier.ns.cloudflare.com", "ns1.domaincontrol.com", "ns-1.awsdns-01.com")
	for _, ns := range []string{"javier.ns.cloudflare.com", "ns1.domaincontrol.com", "ns-1.awsdns-01.com"} {
		if got := w.trustedNameservers(context.Background(), "phish.com", rdap(ns)); got != "" {
			t.Errorf("shared host %s trusted as %q", ns, got)
		}
	}
	if *calls != 0 {
		t.Errorf("zone checks = %d, want 0 for shared hosts", *calls)
	}

	// Port-43 WHOIS is forgeable in transit: no nameserver trust.
	w, _ = trustedWorker(t, trusted, "a.ns.apple.com")
	if got := w.trustedNameservers(context.Background(), "aaplimg.com", WhoisInfo{Source: "whois", Nameservers: []string{"a.ns.apple.com"}}); got != "" {
		t.Errorf("plain WHOIS granted trust: %q", got)
	}

	// At most two zone checks per domain, however many nameservers it lists.
	w, calls = trustedWorker(t, trusted)
	w.trustedNameservers(context.Background(), "evil.com", rdap("a.ns.apple.com", "b.ns.apple.com", "c.ns.apple.com", "d.ns.apple.com"))
	if *calls != 2 {
		t.Errorf("zone checks = %d, want 2", *calls)
	}
}

// authServer runs a DNS server on 127.0.0.1 that is authoritative only for zone.
func authServer(t *testing.T, zone string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	old := nsCheckPort
	nsCheckPort = port
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if strings.EqualFold(r.Question[0].Name, dns.Fqdn(zone)) {
			m.Authoritative = true
			soa, _ := dns.NewRR(dns.Fqdn(zone) + " 300 IN SOA a.ns.apple.com. hostmaster.apple.com. 1 7200 3600 1209600 300")
			m.Answer = append(m.Answer, soa)
		} else {
			m.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = srv.Shutdown()
		nsCheckPort = old
	})
}

func TestServesZone(t *testing.T) {
	authServer(t, "aaplimg.com")
	if !servesZone(context.Background(), "aaplimg.com", "127.0.0.1") {
		t.Error("authoritative SOA answer not accepted")
	}
	if servesZone(context.Background(), "evil.com", "127.0.0.1") {
		t.Error("REFUSED answer accepted as serving the zone")
	}
}
