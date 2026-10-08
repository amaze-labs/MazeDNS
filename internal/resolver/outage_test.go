package resolver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/filter"
)

// switchableUpstream is a real UDP DNS server that either answers (A 1.2.3.4,
// TTL 1) or, while blackholed, silently drops every query — like a WAN outage
// where packets leave but nothing ever comes back.
type switchableUpstream struct {
	pc        net.PacketConn
	blackhole atomic.Bool
}

func newSwitchableUpstream(t *testing.T) *switchableUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &switchableUpstream{pc: pc}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if u.blackhole.Load() {
				continue
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil || len(req.Question) == 0 {
				continue
			}
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   net.IP{1, 2, 3, 4},
			})
			out, _ := m.Pack()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return u
}

func (u *switchableUpstream) addr() string { return u.pc.LocalAddr().String() }

// Reproduces the shape of issue #28 end to end, through a real listener: an
// extended upstream outage with clients still querying. Throughout the outage,
// local rewrites answer fast — even while many forwards are hanging on the dead
// upstream — expired cached names are served stale, and uncached public names
// fail with SERVFAIL within the configured budget. When the upstream comes back,
// forwarding recovers on its own, without restarting anything.
func TestOutageAndRecoveryWithoutRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: waits for a cache TTL to expire")
	}
	const budget = 600 * time.Millisecond
	up := newSwitchableUpstream(t)

	r := New(Options{Timeout: budget})
	r.ApplySettings(Settings{
		Upstreams:         []string{"udp://" + up.addr()},
		UpstreamTimeoutMs: 200,
		Cache:             CacheSettings{Enabled: true, MaxEntries: 1000},
	})
	r.SetPolicy(&Policy{
		Block:    filter.New(),
		Allow:    filter.New(),
		Rewrites: map[string][]RewriteRR{"nas.lan": {{Type: dns.TypeA, Value: "10.0.0.5"}}},
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	t.Setenv("MAZEDNS_UDP_LISTENERS", "1")
	srv := NewServer(addr, r)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	defer srv.Shutdown(context.Background())
	for deadline := time.Now().Add(3 * time.Second); ; {
		select {
		case err := <-errc:
			t.Skipf("cannot bind %s: %v", addr, err)
		default:
		}
		if udp, tcp := srv.Listening(); udp && tcp {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listeners never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	query := func(proto, name string) (*dns.Msg, time.Duration, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		cl := &dns.Client{Net: proto, Timeout: 3 * budget}
		start := time.Now()
		resp, _, err := cl.Exchange(m, addr)
		return resp, time.Since(start), err
	}
	mustRcode := func(proto, name string, want int) time.Duration {
		t.Helper()
		resp, took, err := query(proto, name)
		if err != nil {
			t.Fatalf("%s %s: %v", proto, name, err)
		}
		if resp.Rcode != want {
			t.Fatalf("%s %s: rcode %s, want %s", proto, name, dns.RcodeToString[resp.Rcode], dns.RcodeToString[want])
		}
		return took
	}

	// Online: a public name is forwarded and cached.
	mustRcode("udp", "cached.example", dns.RcodeSuccess)

	// WAN goes down. Let the cached record's 1s TTL expire.
	up.blackhole.Store(true)
	time.Sleep(1100 * time.Millisecond)

	// Many clients keep querying uncached public names, which all hang on the
	// dead upstream; meanwhile local rewrites must stay fast over UDP and TCP.
	var wg sync.WaitGroup
	var slowFail atomic.Int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, took, err := query("udp", fmt.Sprintf("public%d.example", i))
			if err != nil || resp.Rcode != dns.RcodeServerFailure || took > budget+500*time.Millisecond {
				slowFail.Add(1)
			}
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // the forwards are now in flight
	for i := 0; i < 20; i++ {
		for _, proto := range []string{"udp", "tcp"} {
			if took := mustRcode(proto, "nas.lan", dns.RcodeSuccess); took > 100*time.Millisecond {
				t.Fatalf("local rewrite over %s took %v during the outage", proto, took)
			}
		}
	}
	wg.Wait()
	if n := slowFail.Load(); n != 0 {
		t.Fatalf("%d public queries did not fail with SERVFAIL within the budget", n)
	}

	// The expired record is served stale rather than failing.
	if resp, _, err := query("udp", "cached.example"); err != nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("stale answer during the outage: resp=%v err=%v", resp, err)
	}

	h := r.Health()
	if h.LastForwardError.IsZero() || h.ForwardError == "" {
		t.Fatalf("outage not visible in Health: %+v", h)
	}

	// WAN comes back: forwarding recovers by itself.
	up.blackhole.Store(false)
	restored := time.Now()
	mustRcode("udp", "after.example", dns.RcodeSuccess)
	mustRcode("tcp", "nas.lan", dns.RcodeSuccess)
	if h := r.Health(); h.LastForwardOK.Before(restored.Add(-healthResolution)) {
		t.Fatalf("recovery not visible in Health: %+v", h)
	}
}
