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

// dotIdleTimeout bounds how long a pooled TLS connection may sit idle before we
// treat it as likely-dead and discard it instead of reusing it. DoT servers and
// stateful firewalls/NATs silently drop idle TCP flows; reusing one that has been
// dropped makes the next query block on a read until the per-query timeout. Keep
// this comfortably under typical server keep-alive / NAT idle windows.
const dotIdleTimeout = 10 * time.Second

// dotProbeTimeout is the short read budget for a *reused* pooled connection. A
// warm DoT server answers in well under this, so if a pooled connection has gone
// stale within the idle window we fail over to a fresh dial in ~dotProbeTimeout
// instead of stalling for the full per-query timeout. Capped at the upstream
// timeout so it never exceeds the overall budget.
const dotProbeTimeout = 2 * time.Second

// dotKeepaliveInterval is how often the resolver refreshes an idle DoT connection
// to keep it warm (see MaintainUpstreams). It is kept below dotIdleTimeout — and
// below typical server keep-alive / NAT idle windows — so a low-traffic node
// always has a live TLS session ready and never pays a handshake on a cache miss.
const dotKeepaliveInterval = 5 * time.Second

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
		probeTimeout := dotProbeTimeout
		if timeout > 0 && timeout < probeTimeout {
			probeTimeout = timeout
		}
		return &dotUpstream{
			addr:   host,
			client: &dns.Client{Net: "tcp-tls", Timeout: timeout, TLSConfig: &tls.Config{ServerName: server}},
			// probe never dials (only used with an already-open pooled conn), so it
			// needs no Net/TLSConfig — just a short read deadline for fast failover.
			probe: &dns.Client{Timeout: probeTimeout},
			pool:  make(chan pooledConn, dotPoolSize),
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
	client *dns.Client // full per-query timeout; used for fresh dials + exchange
	probe  *dns.Client // short read budget; used only with a reused pooled conn
	pool   chan pooledConn
}

// pooledConn is a warm TLS connection plus when it was last returned to the pool,
// so we can discard it once it has been idle long enough to likely be dead.
type pooledConn struct {
	conn     *dns.Conn
	lastUsed time.Time
}

func (u *dotUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	// Measure the whole operation (including any time wasted on a stale pooled
	// connection before failing over) so the reported rtt reflects real latency.
	start := time.Now()
	// Try a warm pooled connection first, but with a short read deadline: if it has
	// gone stale we fail over to a fresh dial in ~dotProbeTimeout instead of blocking
	// for the full per-query timeout.
	if conn := u.getConn(); conn != nil {
		if resp, _, err := u.probe.ExchangeWithConn(req, conn); err == nil {
			u.putConn(conn)
			return resp, time.Since(start), nil
		}
		conn.Close()
	}
	conn, err := u.client.Dial(u.addr)
	if err != nil {
		return nil, time.Since(start), err
	}
	resp, _, err := u.client.ExchangeWithConn(req, conn)
	if err != nil {
		conn.Close()
		return nil, time.Since(start), err
	}
	u.putConn(conn)
	return resp, time.Since(start), nil
}

// getConn returns a warm pooled connection, discarding any that have been idle
// past dotIdleTimeout (and are therefore likely dropped). Returns nil if the pool
// has no usable connection, so the caller dials fresh.
func (u *dotUpstream) getConn() *dns.Conn {
	for {
		select {
		case pc := <-u.pool:
			if time.Since(pc.lastUsed) > dotIdleTimeout {
				pc.conn.Close()
				continue
			}
			return pc.conn
		default:
			return nil
		}
	}
}

func (u *dotUpstream) putConn(c *dns.Conn) {
	select {
	case u.pool <- pooledConn{conn: c, lastUsed: time.Now()}:
	default:
		c.Close() // pool full — let the extra connection go.
	}
}

// keepWarm makes sure the pool holds at least one live TLS connection: it refreshes
// a pooled connection with a cheap query (which also keeps the server/NAT flow
// alive), or dials a fresh one. Called periodically so an idle upstream doesn't pay
// a handshake on the next real query. Best-effort: any error just drops the dead
// connection and the next tick retries.
func (u *dotUpstream) keepWarm() {
	conn := u.getConn()
	if conn == nil {
		c, err := u.client.Dial(u.addr)
		if err != nil {
			return
		}
		// A freshly dialled connection is already warm; pool it as-is.
		u.putConn(c)
		return
	}
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeNS)
	if _, _, err := u.probe.ExchangeWithConn(m, conn); err != nil {
		conn.Close()
		if c, err := u.client.Dial(u.addr); err == nil {
			u.putConn(c) // replace the dead connection with a warm one
		}
		return
	}
	u.putConn(conn)
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
