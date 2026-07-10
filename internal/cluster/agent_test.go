package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestAgentSync(t *testing.T) {
	snap := Snapshot{
		Version:  "pending", // any value != the worker's empty-config hash triggers the first apply
		Rules:    []store.Rule{{Action: "deny", Domain: "ads.test", Enabled: true, UpdatedAt: 1}},
		Rewrites: []store.Rewrite{{Domain: "nas.lan", RRType: "A", Value: "10.0.0.5", Enabled: true, UpdatedAt: 1}},
		Forwarders: []store.ForwardSpec{
			{Suffix: "corp.internal", Upstreams: []string{"10.0.0.2:53"}},
		},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	reloaded := false
	settingsApplied := false
	ag := NewAgent(ts.URL, "", "tok", "", time.Second, st, func() error { reloaded = true; return nil }, func() store.NodeStats { return store.NodeStats{} }, nil, nil)
	ag.SetApplySettings(func() { settingsApplied = true })
	ag.syncOnce(context.Background())

	rules, _ := st.ListRules()
	if len(rules) != 1 || rules[0].Domain != "ads.test" {
		t.Fatalf("rules not applied: %+v", rules)
	}
	rws, _ := st.ListRewrites()
	if len(rws) != 1 || rws[0].Value != "10.0.0.5" {
		t.Fatalf("rewrites not applied: %+v", rws)
	}
	fws, _ := st.ClusterForwarders()
	if len(fws) != 1 || fws[0].Suffix != "corp.internal" {
		t.Fatalf("forwarders not persisted: %+v", fws)
	}
	if !reloaded {
		t.Fatal("reload was not called after a change")
	}
	if !settingsApplied {
		t.Fatal("applySettings was not called after a change")
	}
	applied, _ := st.ConfigVersion()
	if applied == "" {
		t.Fatal("config version should be a non-empty content hash")
	}

	// Master now advertises the version the worker already holds -> no-op.
	snap.Version = applied
	reloaded = false
	ag.syncOnce(context.Background())
	if reloaded {
		t.Fatal("reload fired again despite unchanged version")
	}

	// An emptied central forwarder list clears the persisted blob on the agent.
	snap.Version = "changed-again"
	snap.Forwarders = nil
	settingsApplied = false
	ag.syncOnce(context.Background())
	if fws, _ := st.ClusterForwarders(); len(fws) != 0 {
		t.Fatalf("forwarders blob not cleared: %+v", fws)
	}
	if !settingsApplied {
		t.Fatal("applySettings must fire when forwarders are removed")
	}

	// Wrong token -> fetch error.
	bad := NewAgent(ts.URL, "", "wrong", "", time.Second, st, nil, nil, nil, nil)
	if _, err := bad.fetch(context.Background()); err == nil {
		t.Fatal("expected an auth error with a wrong token")
	}
}

// TestAgentStopsReenrollOnRevoked verifies the agent stops hammering the control
// plane once it learns its node was revoked: the reenroll callback is invoked once,
// then disabled — subsequent polls do not retry it. (The agent keeps serving DNS
// standalone from its local config.)
func TestAgentStopsReenrollOnRevoked(t *testing.T) {
	// The snapshot endpoint always rejects the node key (revoked).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ag := NewAgent(ts.URL, "", "tok", "", time.Second, st,
		func() error { return nil }, func() store.NodeStats { return store.NodeStats{} }, nil, nil)

	calls := 0
	ag.SetReenroll(func(context.Context) (string, error) {
		calls++
		return "", ErrNodeRevoked
	})

	ag.syncOnce(context.Background())
	if calls != 1 {
		t.Fatalf("reenroll should be attempted once on the revoked 401, got %d", calls)
	}
	if ag.reenroll != nil {
		t.Fatal("reenroll must be disabled after a revoked response")
	}

	// Subsequent polls must NOT re-enroll again.
	ag.syncOnce(context.Background())
	ag.syncOnce(context.Background())
	if calls != 1 {
		t.Fatalf("reenroll must not be retried after revocation, got %d total calls", calls)
	}
}
