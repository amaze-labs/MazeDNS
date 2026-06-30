package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

// In control-plane-only mode every query is answered REFUSED (distinct from the
// SERVFAIL of maintenance), and it takes precedence over maintenance.
func TestControlPlaneOnlyRefused(t *testing.T) {
	r := New(Options{})
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	r.SetControlPlaneOnly(true)
	if !r.ControlPlaneOnly() {
		t.Fatal("ControlPlaneOnly should be true after SetControlPlaneOnly(true)")
	}
	w := &stubRW{}
	r.Handle(w, req)
	if w.msg == nil {
		t.Fatal("expected a reply in control-plane-only mode")
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[w.msg.Rcode])
	}

	// Even with maintenance also on, control-plane-only wins (REFUSED, not SERVFAIL).
	r.SetMaintenance(true)
	w2 := &stubRW{}
	r.Handle(w2, req)
	if w2.msg.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED (control-plane-only precedes maintenance)", dns.RcodeToString[w2.msg.Rcode])
	}

	r.SetControlPlaneOnly(false)
	if r.ControlPlaneOnly() {
		t.Fatal("ControlPlaneOnly should be false after SetControlPlaneOnly(false)")
	}
}
