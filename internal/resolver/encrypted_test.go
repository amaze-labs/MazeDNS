package resolver

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/filter"
)

func newTestResolver() *Resolver {
	res := New(Options{})
	res.SetPolicy(&Policy{
		Block:    filter.New(),
		Allow:    filter.New(),
		Rewrites: map[string][]RewriteRR{"test.local": {{Type: dns.TypeA, Value: "10.0.0.1"}}},
	})
	return res
}

func assertAnswer(t *testing.T, msg *dns.Msg) {
	t.Helper()
	if len(msg.Answer) != 1 {
		t.Fatalf("want 1 answer, got %d", len(msg.Answer))
	}
	if a, ok := msg.Answer[0].(*dns.A); !ok || a.A.String() != "10.0.0.1" {
		t.Fatalf("unexpected answer: %v", msg.Answer[0])
	}
}

func TestDoHHandler(t *testing.T) {
	res := newTestResolver()
	ts := httptest.NewServer(res.DoHHandler())
	defer ts.Close()

	m := new(dns.Msg)
	m.SetQuestion("test.local.", dns.TypeA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}

	check := func(resp *http.Response) {
		t.Helper()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		out := new(dns.Msg)
		if err := out.Unpack(body); err != nil {
			t.Fatal(err)
		}
		assertAnswer(t, out)
	}

	post, err := http.Post(ts.URL, "application/dns-message", bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	check(post)

	get, err := http.Get(ts.URL + "?dns=" + base64.RawURLEncoding.EncodeToString(wire))
	if err != nil {
		t.Fatal(err)
	}
	check(get)
}

func TestDoTServer(t *testing.T) {
	res := newTestResolver()
	cert, _, err := TLSCert("", "")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", res.Handle)
	srv := &dns.Server{
		Listener: tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}}),
		Net:      "tcp-tls",
		Handler:  mux,
	}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	c := &dns.Client{Net: "tcp-tls", TLSConfig: &tls.Config{InsecureSkipVerify: true}, Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("test.local.", dns.TypeA)
	resp, _, err := c.Exchange(m, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, resp)
}
