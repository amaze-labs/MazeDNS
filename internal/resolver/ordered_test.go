package resolver

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// callLog records the order in which upstreams are contacted.
type callLog struct {
	mu    sync.Mutex
	names []string
}

func (l *callLog) add(name string) {
	l.mu.Lock()
	l.names = append(l.names, name)
	l.mu.Unlock()
}

func (l *callLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.names...)
}

// loggedUpstream is a fakeUpstream that records every contact in a callLog.
type loggedUpstream struct {
	fakeUpstream
	log *callLog
}

func (u *loggedUpstream) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	u.log.add(u.name)
	return u.fakeUpstream.Exchange(req)
}

func logged(log *callLog, f fakeUpstream) *loggedUpstream {
	return &loggedUpstream{fakeUpstream: f, log: log}
}

func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Ordered: while the primary answers — even slower than the hedge delay — the
// second upstream is never contacted.
func TestOrderedNeverContactsSecondaryWhenPrimaryAnswers(t *testing.T) {
	r := New(Options{})
	log := &callLog{}
	ups := []Upstream{
		logged(log, fakeUpstream{name: "primary", delay: 4 * hedgeDelay}),
		logged(log, fakeUpstream{name: "secondary"}),
	}
	for range 3 {
		resp, _, err := r.forward(&runtime{upstreamTimeout: time.Second}, newReq(), ups)
		if err != nil {
			t.Fatalf("forward: %v", err)
		}
		if got := respSource(resp); got != "primary" {
			t.Fatalf("source = %q, want primary", got)
		}
	}
	time.Sleep(2 * hedgeDelay) // give a (wrongly) launched secondary time to show up
	if got := log.get(); !equalNames(got, []string{"primary", "primary", "primary"}) {
		t.Fatalf("contacted %v, want only the primary", got)
	}
}

// The same slow-but-healthy primary under the hedged strategy does reach the
// second upstream — the old behavior, kept as an explicit option.
func TestHedgedContactsSecondaryWhenPrimaryIsSlow(t *testing.T) {
	r := New(Options{})
	log := &callLog{}
	ups := []Upstream{
		logged(log, fakeUpstream{name: "primary", delay: 4 * hedgeDelay}),
		logged(log, fakeUpstream{name: "secondary", delay: 8 * hedgeDelay}),
	}
	if _, _, err := r.forward(&runtime{hedged: true}, newReq(), ups); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := log.get(); !equalNames(got, []string{"primary", "secondary"}) {
		t.Fatalf("contacted %v, want primary then secondary (hedged)", got)
	}
}

// Ordered: a primary that does not answer within the per-upstream timeout is
// abandoned and the next upstream answers, well before the overall budget.
func TestOrderedFailoverOnTimeout(t *testing.T) {
	r := New(Options{Timeout: 5 * time.Second})
	log := &callLog{}
	ups := []Upstream{
		logged(log, fakeUpstream{name: "hung", delay: 3 * time.Second}),
		logged(log, fakeUpstream{name: "backup"}),
	}
	start := time.Now()
	resp, _, err := r.forward(&runtime{upstreamTimeout: 100 * time.Millisecond}, newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	elapsed := time.Since(start)
	if got := respSource(resp); got != "backup" {
		t.Fatalf("source = %q, want backup", got)
	}
	if elapsed < 100*time.Millisecond || elapsed > time.Second {
		t.Fatalf("took %v, want about the 100ms per-upstream timeout", elapsed)
	}
	if got := log.get(); !equalNames(got, []string{"hung", "backup"}) {
		t.Fatalf("contacted %v, want hung then backup", got)
	}
}

// Ordered: the third upstream is tried only after the first and second have
// both failed, one after the other, and each failure (error, SERVFAIL,
// REFUSED) moves on immediately rather than waiting for the timeout.
func TestOrderedFailsOverOneAtATime(t *testing.T) {
	r := New(Options{})
	log := &callLog{}
	ups := []Upstream{
		logged(log, fakeUpstream{name: "err", err: errors.New("connection refused")}),
		logged(log, fakeUpstream{name: "servfail", rcode: dns.RcodeServerFailure}),
		logged(log, fakeUpstream{name: "refused", rcode: dns.RcodeRefused}),
		logged(log, fakeUpstream{name: "good"}),
		logged(log, fakeUpstream{name: "unused"}),
	}
	start := time.Now()
	resp, _, err := r.forward(&runtime{upstreamTimeout: time.Second}, newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := respSource(resp); got != "good" {
		t.Fatalf("source = %q, want good", got)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("took %v: failures should fail over immediately, not after the timeout", elapsed)
	}
	if got := log.get(); !equalNames(got, []string{"err", "servfail", "refused", "good"}) {
		t.Fatalf("contacted %v, want err, servfail, refused, good in order", got)
	}
}

// Ordered: no new upstream is started once the overall query budget is spent,
// so a long list of dead upstreams cannot stretch a query past it.
func TestOrderedRespectsOverallBudget(t *testing.T) {
	r := New(Options{Timeout: 250 * time.Millisecond})
	log := &callLog{}
	var ups []Upstream
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		ups = append(ups, logged(log, fakeUpstream{name: n, delay: 2 * time.Second}))
	}
	start := time.Now()
	_, _, err := r.forward(&runtime{upstreamTimeout: 100 * time.Millisecond}, newReq(), ups)
	if !errors.Is(err, errUpstreamTimeout) {
		t.Fatalf("err = %v, want errUpstreamTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 600*time.Millisecond {
		t.Fatalf("took %v, want about the 250ms overall budget", elapsed)
	}
	if got := log.get(); !equalNames(got, []string{"a", "b", "c"}) {
		t.Fatalf("contacted %v, want a, b, c (budget spent before d)", got)
	}
}

// Ordered: the last upstream is given the rest of the overall budget, not just
// the per-upstream timeout — there is nothing left to fail over to.
func TestOrderedLastUpstreamGetsRemainingBudget(t *testing.T) {
	r := New(Options{Timeout: 2 * time.Second})
	ups := []Upstream{
		&fakeUpstream{name: "dead", err: errors.New("boom")},
		&fakeUpstream{name: "slow", delay: 300 * time.Millisecond},
	}
	resp, _, err := r.forward(&runtime{upstreamTimeout: 100 * time.Millisecond}, newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := respSource(resp); got != "slow" {
		t.Fatalf("source = %q, want slow", got)
	}
}

// Ordered: an upstream we already failed over from may still answer late; its
// answer is used when the next upstream fails.
func TestOrderedAcceptsLateAnswer(t *testing.T) {
	r := New(Options{Timeout: 2 * time.Second})
	ups := []Upstream{
		&fakeUpstream{name: "late", delay: 200 * time.Millisecond},
		&fakeUpstream{name: "dead", err: errors.New("boom")},
	}
	resp, _, err := r.forward(&runtime{upstreamTimeout: 50 * time.Millisecond}, newReq(), ups)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := respSource(resp); got != "late" {
		t.Fatalf("source = %q, want late", got)
	}
}

// Conditional forwarders with several upstreams follow the same strategy as
// the default list: ordered never contacts the second while the first answers
// and fails over on SERVFAIL; hedged reaches the second when the first is slow.
func TestConditionalForwarderFollowsStrategy(t *testing.T) {
	cases := []struct {
		name    string
		hedged  bool
		primary fakeUpstream
		wantSrc string
		want    []string
	}{
		{"ordered healthy primary", false, fakeUpstream{name: "cond-1", delay: 4 * hedgeDelay}, "cond-1", []string{"cond-1"}},
		{"ordered servfail fails over", false, fakeUpstream{name: "cond-1", rcode: dns.RcodeServerFailure}, "cond-2", []string{"cond-1", "cond-2"}},
		{"hedged slow primary", true, fakeUpstream{name: "cond-1", delay: 8 * hedgeDelay}, "cond-2", []string{"cond-1", "cond-2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &callLog{}
			r := New(Options{})
			r.rt.Store(&runtime{
				blockMode:        "nxdomain",
				hedged:           tc.hedged,
				upstreamTimeout:  time.Second,
				defaultUpstreams: []Upstream{logged(log, fakeUpstream{name: "default"})},
				conditional: []condForward{{
					suffix: "corp.example", dotSuffix: ".corp.example",
					ups: []Upstream{logged(log, tc.primary), logged(log, fakeUpstream{name: "cond-2"})},
				}},
			})
			req := new(dns.Msg)
			req.SetQuestion("host.corp.example.", dns.TypeA)
			resp, action, _ := r.Resolve(req, "192.0.2.10")
			if action != "forward" {
				t.Fatalf("action = %q, want forward", action)
			}
			if got := respSource(resp); got != tc.wantSrc {
				t.Fatalf("answered by %q, want %q", got, tc.wantSrc)
			}
			time.Sleep(2 * hedgeDelay)
			if got := log.get(); !equalNames(got, tc.want) {
				t.Fatalf("contacted %v, want %v", got, tc.want)
			}
		})
	}
}

// Settings without the strategy fields (saved before they existed) run the
// ordered strategy with the default per-upstream timeout; only an explicit
// "hedged" selects hedging.
func TestApplySettingsUpstreamStrategy(t *testing.T) {
	defTimeout := time.Duration(DefaultUpstreamTimeoutMs) * time.Millisecond
	cases := []struct {
		name        string
		json        string
		wantHedged  bool
		wantTimeout time.Duration
	}{
		{"legacy settings (fields absent)", `{"upstreams":["192.0.2.1","192.0.2.2"]}`, false, defTimeout},
		{"explicit ordered", `{"upstreams":["192.0.2.1"],"upstream_strategy":"ordered","upstream_timeout_ms":800}`, false, 800 * time.Millisecond},
		{"explicit hedged", `{"upstreams":["192.0.2.1"],"upstream_strategy":"hedged"}`, true, 0},
		{"case-insensitive hedged", `{"upstreams":["192.0.2.1"],"upstream_strategy":"HEDGED"}`, true, 0},
		{"unknown strategy falls back to ordered", `{"upstreams":["192.0.2.1"],"upstream_strategy":"random"}`, false, defTimeout},
		{"timeout clamped to minimum", `{"upstreams":["192.0.2.1"],"upstream_timeout_ms":5}`, false, MinUpstreamTimeoutMs * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s Settings
			if err := json.Unmarshal([]byte(tc.json), &s); err != nil {
				t.Fatal(err)
			}
			r := New(Options{})
			r.ApplySettings(s)
			rt := r.rt.Load()
			if rt.hedged != tc.wantHedged {
				t.Fatalf("hedged = %v, want %v", rt.hedged, tc.wantHedged)
			}
			if rt.upstreamTimeout != tc.wantTimeout {
				t.Fatalf("upstreamTimeout = %v, want %v", rt.upstreamTimeout, tc.wantTimeout)
			}
		})
	}
}

// With ordered failover, every upstream but the last gets the per-upstream
// timeout as its network timeout (so an abandoned exchange does not linger);
// the last keeps the full budget. Hedged lists keep the full budget throughout.
func TestApplySettingsUpstreamNetworkTimeouts(t *testing.T) {
	timeouts := func(ups []Upstream) []time.Duration {
		var out []time.Duration
		for _, u := range ups {
			out = append(out, u.(*plainUpstream).primary.Timeout)
		}
		return out
	}
	specs := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}

	r := New(Options{Timeout: 5 * time.Second})
	r.ApplySettings(Settings{Upstreams: specs, UpstreamTimeoutMs: 700,
		Forwarders: []ForwardGroup{{Suffix: "corp.example", Upstreams: specs[:2]}}})
	rt := r.rt.Load()
	want := []time.Duration{700 * time.Millisecond, 700 * time.Millisecond, 5 * time.Second}
	if got := timeouts(rt.defaultUpstreams); !equalDurations(got, want) {
		t.Fatalf("ordered default timeouts = %v, want %v", got, want)
	}
	if got := timeouts(rt.conditional[0].ups); !equalDurations(got, want[1:]) {
		t.Fatalf("ordered forwarder timeouts = %v, want %v", got, want[1:])
	}

	r.ApplySettings(Settings{Upstreams: specs, UpstreamStrategy: StrategyHedged, UpstreamTimeoutMs: 700})
	want = []time.Duration{5 * time.Second, 5 * time.Second, 5 * time.Second}
	if got := timeouts(r.rt.Load().defaultUpstreams); !equalDurations(got, want) {
		t.Fatalf("hedged timeouts = %v, want %v", got, want)
	}
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSettingsNormalizeUpstreams(t *testing.T) {
	s := Settings{}
	s.NormalizeUpstreams()
	if s.UpstreamStrategy != StrategyOrdered || s.UpstreamTimeoutMs != DefaultUpstreamTimeoutMs {
		t.Fatalf("zero settings normalized to %q/%d, want ordered/%d", s.UpstreamStrategy, s.UpstreamTimeoutMs, DefaultUpstreamTimeoutMs)
	}
	s = Settings{UpstreamStrategy: " Hedged ", UpstreamTimeoutMs: 99999}
	s.NormalizeUpstreams()
	if s.UpstreamStrategy != StrategyHedged || s.UpstreamTimeoutMs != MaxUpstreamTimeoutMs {
		t.Fatalf("normalized to %q/%d, want hedged/%d", s.UpstreamStrategy, s.UpstreamTimeoutMs, MaxUpstreamTimeoutMs)
	}
}
