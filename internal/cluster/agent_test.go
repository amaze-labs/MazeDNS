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
	ag := NewAgent(ts.URL, "", "tok", time.Second, st, func() error { reloaded = true; return nil }, func() store.NodeStats { return store.NodeStats{} }, nil)
	ag.syncOnce(context.Background())

	rules, _ := st.ListRules()
	if len(rules) != 1 || rules[0].Domain != "ads.test" {
		t.Fatalf("rules not applied: %+v", rules)
	}
	rws, _ := st.ListRewrites()
	if len(rws) != 1 || rws[0].Value != "10.0.0.5" {
		t.Fatalf("rewrites not applied: %+v", rws)
	}
	if !reloaded {
		t.Fatal("reload was not called after a change")
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

	// Wrong token -> fetch error.
	bad := NewAgent(ts.URL, "", "wrong", time.Second, st, nil, nil, nil)
	if _, err := bad.fetch(context.Background()); err == nil {
		t.Fatal("expected an auth error with a wrong token")
	}
}
