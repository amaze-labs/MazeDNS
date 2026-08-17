package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/logbuf"
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

func TestAgentShipsProcessLogs(t *testing.T) {
	type recv struct {
		auth string
		body procLogBody
	}
	var got []recv
	fail := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cluster/proclog" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var b procLogBody
		_ = json.NewDecoder(r.Body).Decode(&b)
		got = append(got, recv{auth: r.Header.Get("Authorization"), body: b})
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ag := NewAgent(ts.URL, "", "tok", "", time.Second, st, nil, nil, nil, nil)
	ring := logbuf.New(10)
	ag.SetProcessLogs(ring)

	// Nothing buffered: no request is made.
	ag.shipProcLogs(context.Background())
	if len(got) != 0 {
		t.Fatalf("empty ring should ship nothing, got %d posts", len(got))
	}

	ring.Append(time.UnixMilli(1), "info", "started")
	ring.Append(time.UnixMilli(2), "warn", "slow upstream")
	ag.shipProcLogs(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 post, got %d", len(got))
	}
	if got[0].auth != "Bearer tok" {
		t.Fatalf("auth = %q", got[0].auth)
	}
	if got[0].body.BootID == "" || len(got[0].body.Entries) != 2 || got[0].body.Entries[1].Msg != "slow upstream" {
		t.Fatalf("payload = %+v", got[0].body)
	}

	// The cursor advanced: nothing new means no request.
	ag.shipProcLogs(context.Background())
	if len(got) != 1 {
		t.Fatalf("already-shipped lines must not re-ship, got %d posts", len(got))
	}

	// A failed post leaves the cursor so the lines re-ship next cycle.
	ring.Append(time.UnixMilli(3), "error", "sync failed")
	fail = true
	ag.shipProcLogs(context.Background())
	fail = false
	ag.shipProcLogs(context.Background())
	if len(got) != 2 || len(got[1].body.Entries) != 1 || got[1].body.Entries[0].Msg != "sync failed" {
		t.Fatalf("retry after failure: %+v", got)
	}
}

func TestAgentProcLogBatchByteBudget(t *testing.T) {
	var batches [][]logbuf.Entry
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b procLogBody
		_ = json.NewDecoder(r.Body).Decode(&b)
		batches = append(batches, b.Entries)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ag := NewAgent(ts.URL, "", "tok", "", time.Second, st, nil, nil, nil, nil)
	ring := logbuf.New(300)
	ag.SetProcessLogs(ring)

	// 100 max-size lines (~800KB total) exceed the 512KB budget: shipping must
	// split into multiple in-order batches instead of one oversized post.
	big := strings.Repeat("x", logbuf.MaxMsgLen)
	for i := 0; i < 100; i++ {
		ring.Append(time.UnixMilli(int64(i)), "info", big)
	}
	for i := 0; i < 10 && ag.procLogCursor < 100; i++ {
		ag.shipProcLogs(context.Background())
	}
	if len(batches) < 2 {
		t.Fatalf("oversized backlog should ship in >1 batch, got %d", len(batches))
	}
	total := 0
	for _, b := range batches {
		size := 0
		for _, e := range b {
			size += len(e.Msg) + 64
		}
		if size > procLogByteBudget+logbuf.MaxMsgLen+64 {
			t.Fatalf("batch of %d entries (%d bytes) exceeds the byte budget", len(b), size)
		}
		total += len(b)
	}
	if total != 100 {
		t.Fatalf("shipped %d entries in total, want all 100", total)
	}
	if batches[0][0].Seq != 1 || batches[len(batches)-1][len(batches[len(batches)-1])-1].Seq != 100 {
		t.Fatal("batches must cover the backlog in order without gaps")
	}
}

func TestAgentProcLogSkipsRejectedBatch(t *testing.T) {
	status := http.StatusBadRequest
	posts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts++
		w.WriteHeader(status)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ag := NewAgent(ts.URL, "", "tok", "", time.Second, st, nil, nil, nil, nil)
	ring := logbuf.New(10)
	ag.SetProcessLogs(ring)
	ring.Append(time.UnixMilli(1), "info", "poison")

	// A 400 means the master will never take this batch: skip it so shipping
	// can't wedge re-sending it forever.
	ag.shipProcLogs(context.Background())
	if ag.procLogCursor != 1 {
		t.Fatalf("cursor = %d after rejected batch, want 1 (skipped)", ag.procLogCursor)
	}
	ag.shipProcLogs(context.Background())
	if posts != 1 {
		t.Fatalf("rejected batch must not re-ship, got %d posts", posts)
	}
}
