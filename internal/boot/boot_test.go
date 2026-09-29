package boot

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestMergeForwarders(t *testing.T) {
	local := resolver.Settings{
		Upstreams: []string{"1.1.1.1:53"},
		Forwarders: []resolver.ForwardGroup{
			{Suffix: "corp.internal", Upstreams: []string{"10.0.0.9:53"}}, // shadowed by central
			{Suffix: "printers.lan", Upstreams: []string{"10.0.0.8:53"}},  // survives
		},
	}
	central := []store.ForwardSpec{
		{Suffix: "CORP.Internal.", Upstreams: []string{"10.0.0.2:53"}}, // wins despite case/dot
		{Suffix: "lab.internal", Upstreams: []string{"10.9.0.2:53"}},
	}
	got := MergeForwarders(local, central)
	if len(got.Forwarders) != 3 {
		t.Fatalf("want 3 merged forwarders, got %d: %+v", len(got.Forwarders), got.Forwarders)
	}
	byName := map[string][]string{}
	for _, f := range got.Forwarders {
		byName[f.Suffix] = f.Upstreams
	}
	if ups := byName["corp.internal"]; len(ups) != 1 || ups[0] != "10.0.0.2:53" {
		t.Fatalf("central must win for corp.internal: %+v", byName)
	}
	if _, ok := byName["printers.lan"]; !ok {
		t.Fatal("non-conflicting local forwarder must survive")
	}
	// The input settings must not be mutated; other fields pass through.
	if got.Upstreams[0] != "1.1.1.1:53" || len(local.Forwarders) != 2 {
		t.Fatal("merge must not mutate inputs or drop other settings")
	}
	// No central entries -> unchanged local settings.
	same := MergeForwarders(local, nil)
	if len(same.Forwarders) != 2 {
		t.Fatalf("nil central must be a no-op, got %+v", same.Forwarders)
	}
}

// TestRewritePTRScoping runs the real replication path: the control plane
// filters rewrites per node, each agent stores its served set and builds its
// policy from it. PTR answers must follow exactly the forward records that node
// serves (scope, precedence, enabled flag), with no scope logic on the agent.
func TestRewritePTRScoping(t *testing.T) {
	openStore := func(name string) *store.Store {
		st, err := store.Open(filepath.Join(t.TempDir(), name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}
	cp := openStore("cp")
	add := func(domain, rrtype, value, scopeType string, vals ...string) int64 {
		id, err := cp.AddRewriteScoped(domain, rrtype, value, scopeType, vals)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	// Split horizon: nas is 192.0.2.10 everywhere except site-b.
	add("nas.example.lan", "A", "192.0.2.10", store.ScopeAll)
	add("nas.example.lan", "A", "192.0.2.20", store.ScopeSites, "site-b")
	// Only agent-01 serves printer.
	add("printer.example.lan", "A", "192.0.2.30", store.ScopeNodes, "agent-01")
	// A disabled override falls back to the broader enabled entry.
	add("app.example.lan", "AAAA", "2001:db8::40", store.ScopeAll)
	off := add("app.example.lan", "AAAA", "2001:db8::41", store.ScopeNodes, "agent-02")
	if err := cp.UpdateRewrite(off, "2001:db8::41", false, store.ScopeNodes, []string{"agent-02"}); err != nil {
		t.Fatal(err)
	}
	// Wildcards imply no PTR.
	add("*.lab.example.lan", "A", "192.0.2.50", store.ScopeAll)

	agent := func(node, site string) *resolver.Resolver {
		rws, err := cp.ListRewritesForNode(node, site)
		if err != nil {
			t.Fatal(err)
		}
		st := openStore(node)
		if err := st.ApplySnapshot(nil, rws); err != nil {
			t.Fatal(err)
		}
		pol, err := BuildPolicy(st, config.Config{})
		if err != nil {
			t.Fatal(err)
		}
		r := resolver.New(resolver.Options{})
		r.SetPolicy(pol)
		return r
	}
	ptr := func(r *resolver.Resolver, ip string) string {
		t.Helper()
		rev, err := dns.ReverseAddr(ip)
		if err != nil {
			t.Fatal(err)
		}
		req := new(dns.Msg)
		req.SetQuestion(rev, dns.TypePTR)
		resp, action, _ := r.Resolve(req, "192.0.2.1")
		if action != "rewrite" {
			return "" // not answered locally (no upstreams here, so it errors out)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("PTR %s: %d answers, want 1", ip, len(resp.Answer))
		}
		return resp.Answer[0].(*dns.PTR).Ptr
	}

	a1, a2 := agent("agent-01", "site-a"), agent("agent-02", "site-b")
	cases := []struct {
		ip    string
		want1 string // agent-01 (site-a)
		want2 string // agent-02 (site-b)
	}{
		{"192.0.2.10", "nas.example.lan.", ""},
		{"192.0.2.20", "", "nas.example.lan."},
		{"192.0.2.30", "printer.example.lan.", ""},
		{"2001:db8::40", "app.example.lan.", "app.example.lan."},
		{"2001:db8::41", "", ""},
		{"192.0.2.50", "", ""},
	}
	for _, c := range cases {
		if got := ptr(a1, c.ip); got != c.want1 {
			t.Errorf("agent-01 PTR %s = %q, want %q", c.ip, got, c.want1)
		}
		if got := ptr(a2, c.ip); got != c.want2 {
			t.Errorf("agent-02 PTR %s = %q, want %q", c.ip, got, c.want2)
		}
	}
}

// Settings saved before the upstream strategy existed load as ordered with the
// default timeout, unless the config file sets them; stored values win.
func TestLoadOrSeedSettingsUpstreamStrategy(t *testing.T) {
	open := func(t *testing.T, raw string) *store.Store {
		t.Helper()
		st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if raw != "" {
			if err := st.SaveSettings(raw); err != nil {
				t.Fatal(err)
			}
		}
		return st
	}
	legacy := `{"upstreams":["192.0.2.1:53","192.0.2.2:53"],"block_response":"nxdomain"}`
	hedgedCfg := config.Default()
	hedgedCfg.UpstreamStrategy = "hedged"
	hedgedCfg.UpstreamTimeout = config.Duration(700 * time.Millisecond)

	cases := []struct {
		name         string
		raw          string
		cfg          config.Config
		wantStrategy string
		wantTimeout  int
	}{
		{"legacy row, default config", legacy, config.Default(), resolver.StrategyOrdered, resolver.DefaultUpstreamTimeoutMs},
		{"legacy row, config sets hedged", legacy, hedgedCfg, resolver.StrategyHedged, 700},
		{"stored values win over config",
			`{"upstreams":["192.0.2.1:53"],"upstream_strategy":"ordered","upstream_timeout_ms":900}`,
			hedgedCfg, resolver.StrategyOrdered, 900},
		{"first boot seeds from config", "", hedgedCfg, resolver.StrategyHedged, 700},
		{"first boot, default config", "", config.Default(), resolver.StrategyOrdered, resolver.DefaultUpstreamTimeoutMs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := LoadOrSeedSettings(open(t, tc.raw), tc.cfg)
			if s.UpstreamStrategy != tc.wantStrategy || s.UpstreamTimeoutMs != tc.wantTimeout {
				t.Fatalf("got %q/%d, want %q/%d", s.UpstreamStrategy, s.UpstreamTimeoutMs, tc.wantStrategy, tc.wantTimeout)
			}
		})
	}
}

// Central settings replace the node's local ones, except the local conditional
// forwarders; without central settings the local ones apply.
func TestEffectiveSettingsCentralWins(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SaveSettings(`{"upstreams":["1.1.1.1:53"],"forwarders":[{"suffix":"printers.lan","upstreams":["10.0.0.8:53"]}]}`); err != nil {
		t.Fatal(err)
	}
	if s := EffectiveSettings(st, config.Default()); s.Upstreams[0] != "1.1.1.1:53" {
		t.Fatalf("no central settings: want local upstreams, got %+v", s)
	}
	if err := st.SetClusterSettings(`{"upstreams":["tls://192.0.2.53:853"],"rate_limit_qpm":600}`); err != nil {
		t.Fatal(err)
	}
	s := EffectiveSettings(st, config.Default())
	if len(s.Upstreams) != 1 || s.Upstreams[0] != "tls://192.0.2.53:853" || s.RateLimitQPM != 600 ||
		s.UpstreamStrategy != resolver.StrategyOrdered {
		t.Fatalf("central settings must win: %+v", s)
	}
	if len(s.Forwarders) != 1 || s.Forwarders[0].Suffix != "printers.lan" {
		t.Fatalf("local forwarders must survive: %+v", s.Forwarders)
	}
}
