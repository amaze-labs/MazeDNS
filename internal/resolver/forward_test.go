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
