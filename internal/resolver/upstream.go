package resolver

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
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

// dotIdleTimeout bounds how long an idle stream connection (DoT, plain TCP) may
// go without reading anything before we treat it as likely-dead and close it
// instead of reusing it. DoT servers and
// stateful firewalls/NATs silently drop idle TCP flows; reusing one that has been
// dropped makes the next query block on a read until the per-query timeout. Keep
// this comfortably under typical server keep-alive / NAT idle windows.
const dotIdleTimeout = 10 * time.Second

// dotProbeTimeout is the short read budget for a query on a connection that has
// gone quiet (see pipeSuspectAfter). A warm DoT server answers in well under
// this, so if the connection has gone stale we fail over to a fresh dial in
// ~dotProbeTimeout instead of stalling for the full per-query timeout. Capped at
// the upstream timeout so it never exceeds the overall budget.
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

// warmer is implemented by upstreams that keep a pool of persistent connections
// (DoT, plain TCP) which benefit from being refreshed on a timer so a low-traffic
// node never pays a handshake on the next real query. See Resolver.MaintainUpstreams.
type warmer interface{ keepWarm() }

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
		client := &dns.Client{Net: "tcp-tls", Timeout: timeout, TLSConfig: &tls.Config{ServerName: server}}
		return &dotUpstream{addr: host, pipe: newPipePool(host, client)}, nil
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
	// pipe is only set when proto == "tcp": a plain TCP forwarder otherwise pays
	// a fresh TCP handshake on every single query (dns.Client.Exchange dials and
	// closes a new connection each call). UDP needs none: a UDP "connection" is
	// just a local unconnected socket, so one per query is cheap (no handshake).
	pipe *pipePool
}

func newPlain(addr, proto string, timeout time.Duration) *plainUpstream {
	u := &plainUpstream{
		addr:    addr,
		proto:   proto,
		primary: &dns.Client{Net: proto, Timeout: timeout, UDPSize: largeUDPSize},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout},
	}
	if proto == "tcp" {
		u.pipe = newPipePool(addr, u.primary)
	}
	return u
}

func (u *plainUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	if u.pipe != nil {
		return u.pipe.exchange(req)
	}
	resp, rtt, err := u.primary.Exchange(req, u.addr)
	if err == nil && resp != nil && resp.Truncated {
		if u.metrics != nil {
			u.metrics.UpstreamTCPFallback.Inc()
		}
		if r2, rtt2, e2 := u.tcp.Exchange(req, u.addr); e2 == nil {
			return r2, rtt2, nil
		}
	}
	return resp, rtt, err
}

// connDropped reports whether err means the server closed the connection under
// us (EOF, reset, broken pipe) rather than a timeout or a dial failure.
func connDropped(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// keepWarm keeps a TCP connection ready (see pipePool.keepWarm). A no-op for
// UDP, which has no connections to keep.
func (u *plainUpstream) keepWarm() {
	if u.pipe != nil {
		u.pipe.keepWarm()
	}
}

func (u *plainUpstream) String() string { return u.proto + "://" + u.addr }

// dotUpstream resolves over DNS-over-TLS on pipelined connections (see
// pipeline.go): a handful of TLS sessions carry every query, so a cache miss
// pays no handshake.
type dotUpstream struct {
	addr string
	pipe *pipePool
}

func (u *dotUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	return u.pipe.exchange(req)
}

// keepWarm keeps a TLS session ready, so an idle upstream doesn't pay a
// handshake on the next real query (see Resolver.MaintainUpstreams).
func (u *dotUpstream) keepWarm() { u.pipe.keepWarm() }

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

// String names the upstream in errors and logs. A DoH URL can carry credentials
// (user:pass@) or a token in the query, so only scheme, host and path are shown.
func (u *dohUpstream) String() string {
	p, err := url.Parse(u.url)
	if err != nil {
		return "https://(invalid url)"
	}
	return p.Scheme + "://" + p.Host + p.Path
}

// upstreamLabel names an upstream in the query log and metrics: its spec as the
// operator configured it (String normalises it, and drops a DoT server name),
// except that a DoH URL keeps only scheme, host and path — credentials or a
// token in it must not reach the log.
func upstreamLabel(spec string) string {
	spec = strings.TrimSpace(spec)
	if !strings.HasPrefix(spec, "https://") {
		return spec
	}
	return (&dohUpstream{url: spec}).String()
}

func ensurePort(addr, defPort string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, defPort)
}
