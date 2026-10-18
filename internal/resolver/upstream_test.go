package resolver

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseUpstream(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":                              "udp://1.1.1.1:53",
		"udp://8.8.8.8:53":                     "udp://8.8.8.8:53",
		"tcp://8.8.8.8":                        "tcp://8.8.8.8:53",
		"tls://1.1.1.1:853#cloudflare-dns.com": "tls://1.1.1.1:853",
		"https://dns.quad9.net/dns-query":      "https://dns.quad9.net/dns-query",
		// credentials and query tokens never reach logs
		"https://user:secret@doh.example/dns-query?token=abc": "https://doh.example/dns-query",
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

// newPlain with proto "tcp" must set up pipelined connections, so plain TCP
// upstreams (conditional-forwarding specs like "tcp://...") reuse connections
// instead of paying a fresh TCP handshake on every query. UDP needs none.
func TestNewPlainPipelinesOnlyTCP(t *testing.T) {
	if newPlain("127.0.0.1:53", "tcp", time.Second).pipe == nil {
		t.Fatal("plain TCP upstream should pipeline over persistent connections")
	}
	if newPlain("127.0.0.1:53", "udp", time.Second).pipe != nil {
		t.Fatal("plain UDP upstream should not keep connections")
	}
}

// dropFirstTCP is a DNS-over-TCP server that closes its first `drop` connections
// without answering (as Quad9 does to some new connections under a burst) and
// answers on later ones. It returns the address and a connection counter.
func dropFirstTCP(t *testing.T, drop int) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if int(n.Add(1)) <= drop {
				c.Close()
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				dc := &dns.Conn{Conn: c}
				for {
					req, err := dc.ReadMsg()
					if err != nil {
						return
					}
					m := new(dns.Msg)
					m.SetReply(req)
					_ = dc.WriteMsg(m)
				}
			}(c)
		}
	}()
	return ln.Addr().String(), &n
}

// A fresh connection the server drops before answering is retried once on a new
// connection instead of surfacing "EOF" (a SERVFAIL to the client).
func TestTCPRetriesDroppedFreshConn(t *testing.T) {
	addr, conns := dropFirstTCP(t, 1)
	u := newPlain(addr, "tcp", time.Second)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if _, _, err := u.Exchange(m); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := conns.Load(); got != 2 {
		t.Fatalf("connections = %d, want 2 (one dropped, one retry)", got)
	}
}

// Bounded retries: a server that keeps dropping connections still fails, fast,
// after pipeAttempts connections.
func TestTCPRetriesDroppedConnBounded(t *testing.T) {
	addr, conns := dropFirstTCP(t, 100)
	u := newPlain(addr, "tcp", time.Second)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if _, _, err := u.Exchange(m); !connDropped(err) {
		t.Fatalf("err = %v, want a dropped-connection error", err)
	}
	if got := conns.Load(); got != pipeAttempts {
		t.Fatalf("connections = %d, want %d", got, pipeAttempts)
	}
}

// Forward errors name the upstream, so the log says which server failed.
func TestExchangeErrorNamesUpstream(t *testing.T) {
	addr, _ := dropFirstTCP(t, 100)
	u := newPlain(addr, "tcp", time.Second)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	_, _, err := exchange(u, m)
	if err == nil || !strings.HasPrefix(err.Error(), "tcp://"+addr+": ") {
		t.Fatalf("err = %v, want it prefixed with the upstream", err)
	}
}
