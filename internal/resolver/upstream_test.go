package resolver

import (
	"net"
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

// trackedConn is a net.Conn whose Close we can observe.
type trackedConn struct {
	net.Conn
	closed bool
}

func (c *trackedConn) Close() error { c.closed = true; return c.Conn.Close() }

// A pooled DoT connection idle past dotIdleTimeout must be discarded (closed) and
// not handed back, so a query never reuses a likely-dead connection and stalls.
func TestDotPoolDiscardsIdleConn(t *testing.T) {
	u := &dotUpstream{pool: make(chan pooledConn, dotPoolSize)}

	c1, c2 := net.Pipe()
	defer c2.Close()
	tc := &trackedConn{Conn: c1}
	// Inject a connection that was last used well beyond the idle window.
	u.pool <- pooledConn{conn: &dns.Conn{Conn: tc}, lastUsed: time.Now().Add(-2 * dotIdleTimeout)}

	if got := u.getConn(); got != nil {
		t.Fatalf("getConn returned a stale connection; want nil")
	}
	if !tc.closed {
		t.Errorf("stale pooled connection was not closed")
	}
}

// A pooled DoT connection still within the idle window must be reused.
func TestDotPoolReusesFreshConn(t *testing.T) {
	u := &dotUpstream{pool: make(chan pooledConn, dotPoolSize)}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	conn := &dns.Conn{Conn: c1}
	u.pool <- pooledConn{conn: conn, lastUsed: time.Now()}

	if got := u.getConn(); got != conn {
		t.Fatalf("getConn did not return the warm pooled connection")
	}
}
