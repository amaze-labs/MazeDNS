package resolver

import (
	"context"
	stdruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// udpListeners auto-scales to the available CPUs when MAZEDNS_UDP_LISTENERS is
// unset, honors an explicit count (capped), and lets 1 force the single socket.
func TestUDPListeners(t *testing.T) {
	// Pin GOMAXPROCS so "auto" is deterministic, and restore it after.
	prev := stdruntime.GOMAXPROCS(4)
	defer stdruntime.GOMAXPROCS(prev)

	t.Run("auto scales to CPUs when unset", func(t *testing.T) {
		t.Setenv("MAZEDNS_UDP_LISTENERS", "")
		if got := udpListeners(); got != 4 {
			t.Fatalf("auto = %d, want 4 (GOMAXPROCS)", got)
		}
	})
	t.Run("auto is bounded by maxUDPListeners", func(t *testing.T) {
		restore := stdruntime.GOMAXPROCS(32)
		defer stdruntime.GOMAXPROCS(restore)
		t.Setenv("MAZEDNS_UDP_LISTENERS", "")
		if got := udpListeners(); got != maxUDPListeners {
			t.Fatalf("auto = %d, want %d (cap)", got, maxUDPListeners)
		}
	})
	t.Run("explicit 1 forces a single socket", func(t *testing.T) {
		t.Setenv("MAZEDNS_UDP_LISTENERS", "1")
		if got := udpListeners(); got != 1 {
			t.Fatalf("explicit 1 = %d, want 1", got)
		}
	})
	t.Run("explicit count is honored and capped", func(t *testing.T) {
		t.Setenv("MAZEDNS_UDP_LISTENERS", "2")
		if got := udpListeners(); got != 2 {
			t.Fatalf("explicit 2 = %d, want 2", got)
		}
		t.Setenv("MAZEDNS_UDP_LISTENERS", "999")
		if got := udpListeners(); got != maxUDPListeners {
			t.Fatalf("explicit 999 = %d, want %d (cap)", got, maxUDPListeners)
		}
	})
	t.Run("garbage falls back to auto", func(t *testing.T) {
		t.Setenv("MAZEDNS_UDP_LISTENERS", "nope")
		if got := udpListeners(); got != 4 {
			t.Fatalf("garbage = %d, want 4 (auto)", got)
		}
	})
}

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
