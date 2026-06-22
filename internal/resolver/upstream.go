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
)

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
		}, nil
	case strings.HasPrefix(spec, "tcp://"):
		return &plainUpstream{addr: ensurePort(strings.TrimPrefix(spec, "tcp://"), "53"), proto: "tcp", timeout: timeout}, nil
	case strings.HasPrefix(spec, "udp://"):
		return &plainUpstream{addr: ensurePort(strings.TrimPrefix(spec, "udp://"), "53"), proto: "udp", timeout: timeout}, nil
	default:
		return &plainUpstream{addr: ensurePort(spec, "53"), proto: "udp", timeout: timeout}, nil
	}
}

type plainUpstream struct {
	addr    string
	proto   string // "udp" | "tcp"
	timeout time.Duration
}

func (u *plainUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	c := &dns.Client{Net: u.proto, Timeout: u.timeout}
	resp, rtt, err := c.Exchange(req, u.addr)
	if err == nil && resp != nil && resp.Truncated && u.proto == "udp" {
		tcp := &dns.Client{Net: "tcp", Timeout: u.timeout}
		if r2, rtt2, e2 := tcp.Exchange(req, u.addr); e2 == nil {
			return r2, rtt2, nil
		}
	}
	return resp, rtt, err
}

func (u *plainUpstream) String() string { return u.proto + "://" + u.addr }

type dotUpstream struct {
	addr   string
	client *dns.Client
}

func (u *dotUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	return u.client.Exchange(req, u.addr)
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
