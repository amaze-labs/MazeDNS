package resolver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The server binds its UDP socket(s) on a fixed port (SO_REUSEPORT lets several
// share it) and answers queries over UDP. We only assert the transport works —
// with no upstreams configured the answer is SERVFAIL, which is fine here.
func TestServerServesUDP(t *testing.T) {
	r := New(Options{})
	r.rt.Store(&runtime{blockMode: "nxdomain"})

	const addr = "127.0.0.1:15353"
	s := NewServer(addr, r)
	if len(s.udp) < 1 {
		t.Fatal("expected at least one UDP listener")
	}

	errc := make(chan error, 1)
	go func() { errc <- s.ListenAndServe() }()
	defer s.Shutdown(context.Background())

	cl := &dns.Client{Timeout: time.Second}
	var resp *dns.Msg
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		// Bail out early (and skip) if the port couldn't be bound.
		select {
		case e := <-errc:
			if e != nil && strings.Contains(e.Error(), "address already in use") {
				t.Skipf("port busy: %v", e)
			}
			t.Fatalf("server exited: %v", e)
		default:
		}
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		if out, _, err := cl.Exchange(m, addr); err == nil {
			resp = out
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp == nil {
		t.Fatal("no response from server over UDP")
	}
}
