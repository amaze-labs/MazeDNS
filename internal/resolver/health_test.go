package resolver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func probeReq(qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("Probe.MazeDNS.Internal.", qtype)
	return m
}

// The probe is answered locally, ahead of maintenance and control-plane-only,
// with no upstreams configured, and is never counted or reported to OnQuery.
func TestProbeAnsweredLocally(t *testing.T) {
	var events int
	r := New(Options{OnQuery: func(*QueryEvent) { events++ }})

	for _, mode := range []string{"normal", "maintenance", "control-plane-only"} {
		r.SetMaintenance(mode == "maintenance")
		r.SetControlPlaneOnly(mode == "control-plane-only")

		w := &stubRW{}
		r.Handle(w, probeReq(dns.TypeA))
		if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) != 1 {
			t.Fatalf("%s: probe reply = %v, want one NOERROR answer", mode, w.msg)
		}
		a, ok := w.msg.Answer[0].(*dns.A)
		if !ok || !a.A.Equal(net.IPv4(127, 0, 0, 1)) || a.Hdr.Ttl != 0 {
			t.Fatalf("%s: answer = %v, want A 127.0.0.1 TTL 0", mode, w.msg.Answer[0])
		}
	}

	r.SetMaintenance(false)
	r.SetControlPlaneOnly(false)
	w := &stubRW{}
	r.Handle(w, probeReq(dns.TypeAAAA))
	if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) != 0 {
		t.Fatalf("AAAA probe = %v, want empty NOERROR", w.msg)
	}

	if total, _, _, _, _, _ := r.StatsSnapshot(); total != 0 {
		t.Errorf("probe counted in stats: total = %d", total)
	}
	if events != 0 {
		t.Errorf("probe reported to OnQuery %d times", events)
	}
	if !r.Health().LastQuery.IsZero() {
		t.Error("probe updated LastQuery")
	}
}

// Health records the last answered query and the last forward outcome,
// including the error text of a failed forward.
func TestHealthTracksForwardOutcome(t *testing.T) {
	r := New(Options{})
	up := &fakeUpstream{name: "up"}
	r.rt.Store(&runtime{blockMode: "nxdomain", defaultUpstreams: []Upstream{up}})

	if h := r.Health(); !h.LastQuery.IsZero() || !h.LastForwardOK.IsZero() || !h.LastForwardError.IsZero() {
		t.Fatalf("fresh resolver health = %+v, want zero", h)
	}

	before := time.Now().Add(-time.Second)
	r.Handle(&stubRW{}, newReq())
	h := r.Health()
	if h.LastQuery.Before(before) || h.LastForwardOK.Before(before) {
		t.Fatalf("after a good forward: %+v", h)
	}
	if !h.LastForwardError.IsZero() {
		t.Fatalf("unexpected forward error: %+v", h)
	}

	up.err = errors.New("i/o timeout")
	w := &stubRW{}
	r.Handle(w, newReq())
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[w.msg.Rcode])
	}
	h = r.Health()
	if h.LastForwardError.Before(before) || h.ForwardError != "i/o timeout" {
		t.Fatalf("after a failed forward: %+v", h)
	}
}

// Listening reflects the bound listeners, and the probe is answered over both
// UDP and TCP by a real server.
func TestServerListeningAndProbe(t *testing.T) {
	r := New(Options{})
	const addr = "127.0.0.1:15354"
	s := NewServer(addr, r)
	if udp, tcp := s.Listening(); udp || tcp {
		t.Fatal("listening before ListenAndServe")
	}
	errc := make(chan error, 1)
	go func() { errc <- s.ListenAndServe() }()
	defer s.Shutdown(context.Background())

	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-errc:
			t.Skipf("cannot bind %s: %v", addr, err)
		default:
		}
		if udp, tcp := s.Listening(); udp && tcp {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listeners never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	for _, proto := range []string{"udp", "tcp"} {
		cl := &dns.Client{Net: proto, Timeout: time.Second}
		resp, _, err := cl.Exchange(probeReq(dns.TypeA), addr)
		if err != nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("%s probe: resp=%v err=%v", proto, resp, err)
		}
	}

	s.Shutdown(context.Background())
	if udp, tcp := s.Listening(); udp || tcp {
		t.Fatal("still listening after Shutdown")
	}
}
