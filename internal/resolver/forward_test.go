package resolver

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeUpstream is a controllable Upstream for testing the forward/hedge logic.
type fakeUpstream struct {
	name  string
	delay time.Duration
	err   error
	rcode int // response rcode (0 = NOERROR)
}

func (f *fakeUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.err != nil {
		return nil, 0, f.err
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = f.rcode
	m.Extra = append(m.Extra, &dns.TXT{
		Hdr: dns.RR_Header{Name: "src.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
		Txt: []string{f.name},
	})
	return m, f.delay, f.err
}

func (f *fakeUpstream) String() string { return f.name }

func respSource(m *dns.Msg) string {
	if len(m.Extra) == 0 {
		return ""
	}
	if txt, ok := m.Extra[0].(*dns.TXT); ok && len(txt.Txt) > 0 {
		return txt.Txt[0]
	}
	return ""
}

func newReq() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	return m
}

func TestForwardSingleUpstream(t *testing.T) {
	r := New(Options{})
	resp, _, err := r.forward(newReq(), []Upstream{&fakeUpstream{name: "a"}})
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := respSource(resp); got != "a" {
		t.Errorf("source = %q, want a", got)
	}
}

// A healthy fast primary should answer before the hedge fires, so a slow second
// upstream never decides the result.
func TestForwardPrimaryWins(t *testing.T) {
	r := New(Options{})
	ups := []Upstream{
		&fakeUpstream{name: "primary"},
		&fakeUpstream{name: "slow", delay: 200 * time.Millisecond},
	}
	resp, _, err := r.forward(newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := respSource(resp); got != "primary" {
		t.Errorf("source = %q, want primary", got)
	}
}

// A failing primary must fail over to a healthy secondary, not return the error.
func TestForwardFailoverOnError(t *testing.T) {
	r := New(Options{})
	ups := []Upstream{
		&fakeUpstream{name: "dead", err: errors.New("boom")},
		&fakeUpstream{name: "backup"},
	}
	resp, _, err := r.forward(newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := respSource(resp); got != "backup" {
		t.Errorf("source = %q, want backup", got)
	}
}

// A slow primary should be beaten by a fast hedged secondary.
func TestForwardHedgeBeatsSlowPrimary(t *testing.T) {
	r := New(Options{})
	ups := []Upstream{
		&fakeUpstream{name: "slow", delay: 300 * time.Millisecond},
		&fakeUpstream{name: "fast", delay: 10 * time.Millisecond},
	}
	start := time.Now()
	resp, _, err := r.forward(newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := respSource(resp); got != "fast" {
		t.Errorf("source = %q, want fast", got)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("took %v, expected the hedge to beat the slow primary", elapsed)
	}
}

// A SERVFAIL from the primary is a soft failure: fail over to a healthy
// secondary rather than returning the SERVFAIL.
func TestForwardFailoverOnServfail(t *testing.T) {
	r := New(Options{})
	ups := []Upstream{
		&fakeUpstream{name: "broken", rcode: dns.RcodeServerFailure},
		&fakeUpstream{name: "backup"},
	}
	resp, _, err := r.forward(newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := respSource(resp); got != "backup" {
		t.Errorf("source = %q, want backup", got)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", resp.Rcode)
	}
}

// If every upstream SERVFAILs, return the SERVFAIL (not an error).
func TestForwardAllServfail(t *testing.T) {
	r := New(Options{})
	ups := []Upstream{
		&fakeUpstream{name: "a", rcode: dns.RcodeServerFailure},
		&fakeUpstream{name: "b", rcode: dns.RcodeServerFailure},
	}
	resp, _, err := r.forward(newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected a SERVFAIL response, got %+v", resp)
	}
}

// NXDOMAIN is a valid negative answer — it must be returned immediately, NOT
// treated as a failure that fails over (which could mask it).
func TestForwardNXDOMAINWinsImmediately(t *testing.T) {
	r := New(Options{})
	ups := []Upstream{
		&fakeUpstream{name: "primary", rcode: dns.RcodeNameError},
		&fakeUpstream{name: "slow", delay: 300 * time.Millisecond},
	}
	start := time.Now()
	resp, _, err := r.forward(newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := respSource(resp); got != "primary" || resp.Rcode != dns.RcodeNameError {
		t.Errorf("source = %q rcode = %d, want primary NXDOMAIN", respSource(resp), resp.Rcode)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("took %v, NXDOMAIN should return without waiting on the slow upstream", elapsed)
	}
}

// All upstreams failing must surface an error rather than hang.
func TestForwardAllFail(t *testing.T) {
	r := New(Options{})
	ups := []Upstream{
		&fakeUpstream{name: "a", err: errors.New("a")},
		&fakeUpstream{name: "b", err: errors.New("b")},
	}
	if _, _, err := r.forward(newReq(), ups); err == nil {
		t.Fatal("expected an error when all upstreams fail")
	}
}
