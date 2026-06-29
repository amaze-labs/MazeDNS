package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// stubRW is a minimal dns.ResponseWriter that captures the written reply.
type stubRW struct {
	msg *dns.Msg
}

func (s *stubRW) LocalAddr() net.Addr         { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (s *stubRW) RemoteAddr() net.Addr        { return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5353} }
func (s *stubRW) WriteMsg(m *dns.Msg) error   { s.msg = m; return nil }
func (s *stubRW) Write(b []byte) (int, error) { return len(b), nil }
func (s *stubRW) Close() error                { return nil }
func (s *stubRW) TsigStatus() error           { return nil }
func (s *stubRW) TsigTimersOnly(bool)         {}
func (s *stubRW) Hijack()                     {}

// In maintenance mode every query is answered SERVFAIL; toggling it off restores
// normal resolution (here: NXDOMAIN-style handling with no upstreams configured).
func TestMaintenanceModeServfail(t *testing.T) {
	r := New(Options{})
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	r.SetMaintenance(true)
	if !r.InMaintenance() {
		t.Fatal("InMaintenance should be true after SetMaintenance(true)")
	}
	w := &stubRW{}
	r.Handle(w, req)
	if w.msg == nil {
		t.Fatal("expected a reply in maintenance mode")
	}
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[w.msg.Rcode])
	}

	// Resuming stops the SERVFAIL short-circuit (no upstreams -> SERVFAIL from the
	// forward path is fine; what matters is the maintenance flag is cleared).
	r.SetMaintenance(false)
	if r.InMaintenance() {
		t.Fatal("InMaintenance should be false after SetMaintenance(false)")
	}
}
