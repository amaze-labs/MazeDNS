package resolver

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/metrics"
)

// largeUDPSize is the EDNS/receive buffer we advertise and read with. It follows
// the DNS Flag Day 2020 recommendation of 1232 bytes: large enough for most
// (incl. DNSSEC-signed) answers, but small enough to stay under the common 1500-
// byte path MTU so responses are NOT IP-fragmented. Fragmented UDP is widely
// dropped by routers/NAT/firewalls, which black-holes large answers and makes
// resolution time out; anything bigger than this cleanly falls back to TCP.
const largeUDPSize = 1232

// dotPoolSize is the number of TLS connections kept warm per DoT upstream, so
// queries reuse an established session instead of paying a full TLS handshake
// each time.
const dotPoolSize = 4

// Upstream resolves a query against a single upstream server.
type Upstream interface {
	Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error)
	String() string
}

// ParseUpstream builds an Upstream from a spec:
//
//	1.1.1.1                                -> plain UDP (TCP fallback) on :53
//	udp://1.1.1.1:53                        -> plain UDP
//	tcp://1.1.1.1:53                        -> plain TCP
//	tls://1.1.1.1:853#cloudflare-dns.com    -> DoT (TLS server name after '#')
//	https://dns.quad9.net/dns-query         -> DoH
func ParseUpstream(spec string, timeout time.Duration) (Upstream, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case strings.HasPrefix(spec, "https://"):
		return &dohUpstream{url: spec, client: &http.Client{Timeout: timeout}}, nil
	case strings.HasPrefix(spec, "tls://"):
		rest := strings.TrimPrefix(spec, "tls://")
		host, server := rest, ""
		if i := strings.IndexByte(rest, '#'); i >= 0 {
			host, server = rest[:i], rest[i+1:]
		}
		host = ensurePort(host, "853")
		if server == "" {
			server, _, _ = net.SplitHostPort(host)
		}
		return &dotUpstream{
			addr:   host,
			client: &dns.Client{Net: "tcp-tls", Timeout: timeout, TLSConfig: &tls.Config{ServerName: server}},
			pool:   make(chan *dns.Conn, dotPoolSize),
		}, nil
	case strings.HasPrefix(spec, "tcp://"):
		return newPlain(ensurePort(strings.TrimPrefix(spec, "tcp://"), "53"), "tcp", timeout), nil
	case strings.HasPrefix(spec, "udp://"):
		return newPlain(ensurePort(strings.TrimPrefix(spec, "udp://"), "53"), "udp", timeout), nil
	default:
		return newPlain(ensurePort(spec, "53"), "udp", timeout), nil
	}
}

type plainUpstream struct {
	addr    string
	proto   string      // "udp" | "tcp"
	primary *dns.Client // reused across queries (proto = udp or tcp)
	tcp     *dns.Client // TCP fallback for truncated UDP responses
	metrics *metrics.Metrics
}

func newPlain(addr, proto string, timeout time.Duration) *plainUpstream {
	return &plainUpstream{
		addr:    addr,
		proto:   proto,
		primary: &dns.Client{Net: proto, Timeout: timeout, UDPSize: largeUDPSize},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout},
	}
}

func (u *plainUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	resp, rtt, err := u.primary.Exchange(req, u.addr)
	if err == nil && resp != nil && resp.Truncated && u.proto == "udp" {
		if u.metrics != nil {
			u.metrics.UpstreamTCPFallback.Inc()
		}
		if r2, rtt2, e2 := u.tcp.Exchange(req, u.addr); e2 == nil {
			return r2, rtt2, nil
		}
	}
	return resp, rtt, err
}

func (u *plainUpstream) String() string { return u.proto + "://" + u.addr }

// dotUpstream resolves over DNS-over-TLS, pooling established TLS connections to
// avoid a handshake per query.
type dotUpstream struct {
	addr   string
	client *dns.Client
	pool   chan *dns.Conn
}

func (u *dotUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	// Try a warm pooled connection first; on any error it may be stale, so fall
	// back to a fresh dial and retry once.
	if conn := u.getConn(); conn != nil {
		if resp, rtt, err := u.client.ExchangeWithConn(req, conn); err == nil {
			u.putConn(conn)
			return resp, rtt, nil
		}
		conn.Close()
	}
	conn, err := u.client.Dial(u.addr)
	if err != nil {
		return nil, 0, err
	}
	resp, rtt, err := u.client.ExchangeWithConn(req, conn)
	if err != nil {
		conn.Close()
		return nil, 0, err
	}
	u.putConn(conn)
	return resp, rtt, nil
}

func (u *dotUpstream) getConn() *dns.Conn {
	select {
	case c := <-u.pool:
		return c
	default:
		return nil
	}
}

func (u *dotUpstream) putConn(c *dns.Conn) {
	select {
	case u.pool <- c:
	default:
		c.Close() // pool full — let the extra connection go.
	}
}

func (u *dotUpstream) String() string { return "tls://" + u.addr }

type dohUpstream struct {
	url    string
	client *http.Client
}

func (u *dohUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	start := time.Now()
	packed, err := req.Pack()
	if err != nil {
		return nil, 0, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, u.url, bytes.NewReader(packed))
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	resp, err := u.client.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("doh: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, 0, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, 0, err
	}
	return out, time.Since(start), nil
}

func (u *dohUpstream) String() string { return u.url }

func ensurePort(addr, defPort string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, defPort)
}
