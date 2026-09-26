package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// fakeCP is a minimal control plane: it serves snap, answers 304 when the
// agent advertises support and reports exactly the snapshot's state (like the
// real one), unless legacy is set (a control plane that predates 304). It
// records the headers of every poll.
type fakeCP struct {
	mu      sync.Mutex
	snap    Snapshot
	legacy  bool
	status  int // forced status (0 = normal behavior)
	headers []http.Header
}

func (f *fakeCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = append(f.headers, r.Header.Clone())
	if f.status != 0 {
		http.Error(w, "boom", f.status)
		return
	}
	maint := "0"
	if f.snap.Maintenance {
		maint = "1"
	}
	if !f.legacy && r.Header.Get(HeaderAcceptNotModified) == "1" &&
		r.Header.Get(HeaderNodeVersion) == f.snap.Version &&
		r.Header.Get(HeaderNodeID) == f.snap.NodeID &&
		r.Header.Get(HeaderPausedUntil) == jsonInt(f.snap.PausedUntil) &&
		r.Header.Get(HeaderMaintenance) == maint {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_ = json.NewEncoder(w).Encode(f.snap)
}

func (f *fakeCP) last() http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.headers[len(f.headers)-1]
}

func jsonInt(v int64) string { b, _ := json.Marshal(v); return string(b) }

// newAgentAgainst builds an agent (with a persisted node id) against cp and
// counts reloads / state callbacks.
type agentProbe struct {
	reloads, pauses, maints int
}

func newAgentAgainst(t *testing.T, cp http.Handler) (*Agent, *store.Store, *agentProbe) {
	t.Helper()
	ts := httptest.NewServer(cp)
	t.Cleanup(ts.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	p := &agentProbe{}
	ag := NewAgent(ts.URL, "", "tok", "", time.Second, st,
		func() error { p.reloads++; return nil }, nil,
		func(int64) { p.pauses++ }, func(bool) { p.maints++ })
	ag.SetNodeID("node-1", func(string) {})
	return ag, st, p
}

// masterVersion returns the version a control plane would advertise for snap:
// the hash of its content as an agent computes it after applying.
func masterVersion(t *testing.T, snap Snapshot) string {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "master.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetClusterForwarders(snap.Forwarders); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplySnapshot(snap.Rules, snap.Rewrites); err != nil {
		t.Fatal(err)
	}
	v, err := st.ConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func testSnapshot(t *testing.T) Snapshot {
	snap := Snapshot{
		NodeID:      "node-1",
		Rules:       []store.Rule{{Action: "deny", Domain: "ads.example.lan", Category: "ads", Enabled: true, UpdatedAt: 1}},
		Rewrites:    []store.Rewrite{{Domain: "nas.example.lan", RRType: "A", Value: "192.0.2.10", Enabled: true, UpdatedAt: 1}},
		PausedUntil: 1_900_000_000,
		Maintenance: true,
	}
	snap.Version = masterVersion(t, snap)
	return snap
}

// The first poll after boot never offers 304 support (the pause/maintenance
// state is not applied yet); once a full snapshot is applied, polls carry
// the capability and the applied state, a 304 applies nothing, and the local
// copy keeps serving.
func TestAgentHandlesNotModified(t *testing.T) {
	cp := &fakeCP{snap: testSnapshot(t)}
	ag, st, p := newAgentAgainst(t, cp)

	ag.syncOnce(context.Background())
	if h := cp.last(); h.Get(HeaderAcceptNotModified) != "" {
		t.Fatal("first poll must not offer 304 before any state is applied")
	}
	if p.reloads != 1 || p.pauses != 1 || p.maints != 1 {
		t.Fatalf("first poll should apply everything: %+v", *p)
	}
	rules, _ := st.ListRules()
	if len(rules) != 1 {
		t.Fatalf("rules not applied: %+v", rules)
	}

	ag.syncOnce(context.Background())
	h := cp.last()
	if h.Get(HeaderAcceptNotModified) != "1" || h.Get(HeaderNodeID) != "node-1" ||
		h.Get(HeaderPausedUntil) != "1900000000" || h.Get(HeaderMaintenance) != "1" ||
		h.Get(HeaderNodeVersion) != cp.snap.Version {
		t.Fatalf("second poll should advertise 304 support with the applied state: %v", h)
	}
	if p.reloads != 1 || p.pauses != 1 || p.maints != 1 {
		t.Fatalf("a 304 must apply nothing: %+v", *p)
	}
	if rules, _ := st.ListRules(); len(rules) != 1 {
		t.Fatalf("local copy must be kept on 304: %+v", rules)
	}

	// A pause lifted on the control plane is not hidden by the 304 path.
	cp.mu.Lock()
	cp.snap.PausedUntil = 0
	cp.mu.Unlock()
	ag.syncOnce(context.Background())
	if p.pauses != 2 || p.reloads != 1 {
		t.Fatalf("changed pause must be delivered and applied without a reload: %+v", *p)
	}
	ag.syncOnce(context.Background())
	if cp.last().Get(HeaderPausedUntil) != "0" || p.pauses != 2 {
		t.Fatalf("agent should report the new pause and get a 304: %v %+v", cp.last(), *p)
	}
}

// Against a control plane that predates 304 the capability header is simply
// ignored: the agent gets the full snapshot and, versions matching, applies
// nothing — the pre-304 behavior.
func TestAgentAgainstLegacyControlPlane(t *testing.T) {
	cp := &fakeCP{snap: testSnapshot(t), legacy: true}
	ag, st, p := newAgentAgainst(t, cp)
	for i := 0; i < 3; i++ {
		ag.syncOnce(context.Background())
	}
	if p.reloads != 1 {
		t.Fatalf("matching versions must not re-apply: %d reloads", p.reloads)
	}
	if rules, _ := st.ListRules(); len(rules) != 1 {
		t.Fatalf("rules: %+v", rules)
	}
}

// A non-200, non-304 answer is an error: the agent logs it and keeps serving
// its local copy untouched.
func TestAgentKeepsLocalCopyOnError(t *testing.T) {
	cp := &fakeCP{snap: testSnapshot(t)}
	ag, st, p := newAgentAgainst(t, cp)
	ag.syncOnce(context.Background())
	cp.mu.Lock()
	cp.status = http.StatusInternalServerError
	cp.mu.Unlock()
	ag.syncOnce(context.Background())
	if rules, _ := st.ListRules(); len(rules) != 1 || p.reloads != 1 {
		t.Fatalf("error response must not touch the local copy: rules=%+v probe=%+v", rules, *p)
	}
}

// The agent's config version is computed once when a snapshot is applied and
// persisted; later polls send it without re-hashing the rule set.
func TestAgentPersistsVersionOnApply(t *testing.T) {
	cp := &fakeCP{snap: testSnapshot(t), legacy: true}
	ag, st, _ := newAgentAgainst(t, cp)
	ag.syncOnce(context.Background())

	fresh, _ := st.ConfigVersion()
	persisted, _ := st.GetMeta("applied_config_version")
	if persisted == "" || persisted != fresh || ag.version != fresh {
		t.Fatalf("applied version not persisted: meta=%q agent=%q fresh=%q", persisted, ag.version, fresh)
	}
	// Polls reuse the in-memory value: tamper with the persisted copy and the
	// header does not change (no reload from the store, no re-hash).
	if err := st.SetMeta("applied_config_version", "tampered"); err != nil {
		t.Fatal(err)
	}
	ag.syncOnce(context.Background())
	if got := cp.last().Get(HeaderNodeVersion); got != fresh {
		t.Fatalf("poll header = %q, want the cached %q", got, fresh)
	}

	// A restarted agent reuses the persisted version while the fingerprint of
	// its tables still matches (here the tampered value proves it was reused,
	// not recomputed)...
	restarted := NewAgent("http://unused.example.lan", "", "tok", "", time.Second, st, nil, nil, nil, nil)
	if got := restarted.localVersion(); got != "tampered" {
		t.Fatalf("restart should reuse the persisted version, got %q", got)
	}
	// ...and recomputes it when the tables changed behind its back, e.g. a
	// snapshot applied by an older agent build that does not record it.
	if err := st.ApplySnapshot([]store.Rule{{Action: "deny", Domain: "other.example.lan", Category: "ads", Enabled: true}}, nil); err != nil {
		t.Fatal(err)
	}
	want, _ := st.ConfigVersion()
	restarted2 := NewAgent("http://unused.example.lan", "", "tok", "", time.Second, st, nil, nil, nil, nil)
	if got := restarted2.localVersion(); got != want {
		t.Fatalf("changed tables must invalidate the persisted version: got %q want %q", got, want)
	}
}
