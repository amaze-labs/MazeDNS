package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/IPMaze/MazeDNS/internal/cluster"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// pollOpts describes one agent poll. capable=false models an agent built
// before 304 support: it sends only its key and config version.
type pollOpts struct {
	key, version string
	capable      bool
	nodeID       string
	pausedUntil  int64
	maintenance  bool
	stats        string
	advertise    string
}

func poll(s *Server, o pollOpts) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+o.key)
	req.Header.Set(cluster.HeaderNodeVersion, o.version)
	req.Header.Set("X-MazeDNS-App-Version", "1.2.3")
	if o.stats != "" {
		req.Header.Set("X-MazeDNS-Stats", o.stats)
	}
	if o.advertise != "" {
		req.Header.Set("X-MazeDNS-Advertise-Addr", o.advertise)
	}
	if o.capable {
		req.Header.Set(cluster.HeaderAcceptNotModified, "1")
		req.Header.Set(cluster.HeaderNodeID, o.nodeID)
		req.Header.Set(cluster.HeaderPausedUntil, strconv.FormatInt(o.pausedUntil, 10))
		m := "0"
		if o.maintenance {
			m = "1"
		}
		req.Header.Set(cluster.HeaderMaintenance, m)
	}
	rr := httptest.NewRecorder()
	s.clusterSnapshot(rr, req)
	return rr
}

func decodeSnap(t *testing.T, rr *httptest.ResponseRecorder) cluster.Snapshot {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	var snap cluster.Snapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	return snap
}

// enrolledAgent enrolls agent-01 with a couple of rules and returns the server,
// store, key, node, and the node's current snapshot (as a full 200).
func enrolledAgent(t *testing.T) (*Server, *store.Store, string, *store.Node, cluster.Snapshot) {
	t.Helper()
	s, st := newEnrollServer(t, "s3cr3t", false)
	key := jsonField(enroll(s, `{"name":"agent-01","token":"s3cr3t"}`).Body.String(), "key")
	if key == "" {
		t.Fatal("no key issued")
	}
	for _, d := range []string{"ads.example.lan", "tracker.example.lan"} {
		if _, err := st.AddRule("deny", d, "ads"); err != nil {
			t.Fatal(err)
		}
	}
	node := mustNode(t, st, "agent-01")
	snap := decodeSnap(t, poll(s, pollOpts{key: key}))
	if len(snap.Rules) != 2 || snap.Version == "" {
		t.Fatalf("bootstrap snapshot: %+v", snap)
	}
	return s, st, key, node, snap
}

// upToDate is a capable poll from an agent that holds exactly the current state.
func upToDate(key string, node *store.Node, snap cluster.Snapshot) pollOpts {
	return pollOpts{key: key, version: snap.Version, capable: true, nodeID: node.ID,
		pausedUntil: snap.PausedUntil, maintenance: snap.Maintenance}
}

func TestSnapshotNotModifiedForCapableUpToDateAgent(t *testing.T) {
	s, st, key, node, snap := enrolledAgent(t)
	o := upToDate(key, node, snap)
	o.stats = `{"total":42,"blocked":7}`
	o.advertise = "192.0.2.10"
	rr := poll(s, o)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304 (%s)", rr.Code, rr.Body.String())
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("304 must carry no body, got %q", rr.Body.String())
	}
	// Bookkeeping still ran on the 304 path.
	n := mustNode(t, st, "agent-01")
	if n.Version != snap.Version || n.Address != "192.0.2.10" || n.LastSeen == 0 {
		t.Fatalf("TouchNode did not run on 304: %+v", n)
	}
	nodes, _ := st.ListNodes()
	if len(nodes) != 1 || nodes[0].Total != 42 || nodes[0].Blocked != 7 || nodes[0].AppVersion != "1.2.3" {
		t.Fatalf("stats/app version not recorded on 304: %+v", nodes)
	}
	// The advertised-address audit runs on the 304 path too.
	o.advertise = "192.0.2.11"
	if rr := poll(s, o); rr.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rr.Code)
	}
	audit, _ := st.ListAudit()
	found := false
	for _, e := range audit {
		if e.Action == "cluster.node.address" {
			found = true
		}
	}
	if !found {
		t.Fatalf("address change not audited on the 304 path: %+v", audit)
	}
}

// An agent that does not advertise 304 support (every build before it) must
// keep receiving the full snapshot even when its version matches: it would
// apply an empty rule set and stop blocking.
func TestSnapshotOldAgentAlwaysGetsFullRules(t *testing.T) {
	s, _, key, _, snap := enrolledAgent(t)
	for i := 0; i < 2; i++ {
		got := decodeSnap(t, poll(s, pollOpts{key: key, version: snap.Version}))
		if got.Version != snap.Version || len(got.Rules) != 2 {
			t.Fatalf("old agent must get the full rule set: %+v", got)
		}
	}
}

// Anything the agent reports that differs from the current snapshot forces a
// full 200: the config version, and the fields outside the version hash.
func TestSnapshotFullWhenAgentStateDiffers(t *testing.T) {
	s, st, key, node, snap := enrolledAgent(t)
	cases := []struct {
		name   string
		mutate func(o *pollOpts)
	}{
		{"stale version", func(o *pollOpts) { o.version = "000000000000" }},
		{"empty version", func(o *pollOpts) { o.version = "" }},
		{"unknown node id", func(o *pollOpts) { o.nodeID = "" }},
		{"other node id", func(o *pollOpts) { o.nodeID = uuid.NewString() }},
		{"pause differs", func(o *pollOpts) { o.pausedUntil = 12345 }},
		{"maintenance differs", func(o *pollOpts) { o.maintenance = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := upToDate(key, node, snap)
			tc.mutate(&o)
			got := decodeSnap(t, poll(s, o))
			if len(got.Rules) != 2 || got.Version != snap.Version {
				t.Fatalf("expected the full snapshot: %+v", got)
			}
		})
	}

	// Changes on the control plane that are not in the version hash propagate.
	t.Run("pause set on control plane", func(t *testing.T) {
		until := time.Now().Add(time.Hour).Unix()
		if err := st.SetBlockPausedUntil(until); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.SetBlockPausedUntil(0) })
		got := decodeSnap(t, poll(s, upToDate(key, node, snap)))
		if got.PausedUntil != until {
			t.Fatalf("pause must propagate: got %d want %d", got.PausedUntil, until)
		}
		o := upToDate(key, node, got)
		if rr := poll(s, o); rr.Code != http.StatusNotModified {
			t.Fatalf("once applied, the paused state is up to date: status %d", rr.Code)
		}
	})
	t.Run("maintenance set on control plane", func(t *testing.T) {
		if err := st.SetNodeMaintenance(node.ID, true); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.SetNodeMaintenance(node.ID, false) })
		got := decodeSnap(t, poll(s, upToDate(key, node, snap)))
		if !got.Maintenance {
			t.Fatal("maintenance must propagate")
		}
		if rr := poll(s, upToDate(key, node, got)); rr.Code != http.StatusNotModified {
			t.Fatalf("once applied, maintenance is up to date: status %d", rr.Code)
		}
	})
}

// A config change on the control plane reaches a capable agent on its next
// poll (the cached version is invalidated), and it is not-modified again once
// the agent reports the new version.
func TestSnapshotConfigChangeReachesCapableAgent(t *testing.T) {
	s, st, key, node, snap := enrolledAgent(t)
	if rr := poll(s, upToDate(key, node, snap)); rr.Code != http.StatusNotModified {
		t.Fatalf("warm-up: status = %d, want 304", rr.Code)
	}
	if _, err := st.AddRewrite("nas.example.lan", "A", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	got := decodeSnap(t, poll(s, upToDate(key, node, snap)))
	if got.Version == snap.Version || len(got.Rewrites) != 1 || len(got.Rules) != 2 {
		t.Fatalf("change not delivered: %+v", got)
	}
	if rr := poll(s, upToDate(key, node, got)); rr.Code != http.StatusNotModified {
		t.Fatalf("after applying the change: status = %d, want 304", rr.Code)
	}
	// An override scoped to a site the node is not in leaves its view (and
	// version) unchanged: still 304.
	if _, err := st.AddRewriteScoped("nas.example.lan", "A", "192.0.2.20", store.ScopeSites, []string{"site-a"}); err != nil {
		t.Fatal(err)
	}
	if rr := poll(s, upToDate(key, node, got)); rr.Code != http.StatusNotModified {
		t.Fatalf("out-of-scope change: status = %d, want 304", rr.Code)
	}
	// Moving the node into that site changes its view: the old version is
	// refused and the override is delivered.
	if err := st.SetNodeSite(node.ID, "site-a", ""); err != nil {
		t.Fatal(err)
	}
	moved := decodeSnap(t, poll(s, upToDate(key, node, got)))
	if moved.Version == got.Version || len(moved.Rewrites) != 1 || moved.Rewrites[0].Value != "192.0.2.20" {
		t.Fatalf("site move not delivered: %+v", moved)
	}
}

// A key rotated on a poll must be delivered on that poll: the response is the
// full snapshot carrying new_node_key even if the agent is otherwise current.
func TestSnapshotRotationBypassesNotModified(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}
	s.SetClusterEnrollment(false, time.Hour, time.Hour)
	if err := st.CreateEnrollKey(uuid.NewString(), "k", hashKey("s3cr3t"), keyPrefix("s3cr3t"), "test", 0, 0); err != nil {
		t.Fatal(err)
	}
	k0 := jsonField(enroll(s, `{"name":"agent-01","token":"s3cr3t"}`).Body.String(), "key")
	if _, err := st.AddRule("deny", "ads.example.lan", "ads"); err != nil {
		t.Fatal(err)
	}
	node := mustNode(t, st, "agent-01")
	snap := decodeSnap(t, poll(s, pollOpts{key: k0}))
	if rr := poll(s, upToDate(k0, node, snap)); rr.Code != http.StatusNotModified {
		t.Fatalf("fresh key: status = %d, want 304", rr.Code)
	}

	s.keyMaxAge = time.Nanosecond // rotation now due
	got := decodeSnap(t, poll(s, upToDate(k0, node, snap)))
	if got.NewNodeKey == "" || got.NewNodeKey == k0 {
		t.Fatalf("rotated key must be delivered on the 304-eligible poll: %+v", got)
	}
	if len(got.Rules) != 1 || got.Version != snap.Version {
		t.Fatalf("rotation response must still be a complete snapshot: %+v", got)
	}

	// The agent "loses" the response and polls again with the old (grace) key:
	// the key is re-issued, again with a full snapshot rather than a 304.
	s.keyMaxAge = time.Hour
	again := decodeSnap(t, poll(s, upToDate(k0, node, snap)))
	if again.NewNodeKey == "" {
		t.Fatal("re-issued key must be delivered, not hidden behind a 304")
	}
	// Once it adopts the new key it is back to 304s.
	if rr := poll(s, upToDate(again.NewNodeKey, node, snap)); rr.Code != http.StatusNotModified {
		t.Fatalf("after adopting the key: status = %d, want 304", rr.Code)
	}
}

// seedRules adds n deny rules through a list (the blocklist-scale shape).
func seedRules(tb testing.TB, st *store.Store, n int) {
	tb.Helper()
	id, err := st.CreateList("blocklist", "url", "https://lists.example.lan/hosts", "ads", 0)
	if err != nil {
		tb.Fatal(err)
	}
	rules := make([]store.Rule, n)
	for i := range rules {
		rules[i] = store.Rule{Action: "deny", Domain: fmt.Sprintf("host-%06d.ads.example.lan", i)}
	}
	if _, err := st.ReplaceListRules(id, "ads", rules); err != nil {
		tb.Fatal(err)
	}
}

func allocatedBytes(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// The unchanged poll must not load or serialize the rule set: with 20k rules
// its allocations are a small fraction of a full snapshot's (which scales
// with the rule count), and it writes no body.
func TestSnapshotNotModifiedSkipsRuleSet(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)
	key := jsonField(enroll(s, `{"name":"agent-01","token":"s3cr3t"}`).Body.String(), "key")
	seedRules(t, st, 20000)
	node := mustNode(t, st, "agent-01")
	snap := decodeSnap(t, poll(s, pollOpts{key: key}))
	if len(snap.Rules) != 20000 {
		t.Fatalf("seeded %d rules, snapshot has %d", 20000, len(snap.Rules))
	}
	o := upToDate(key, node, snap)

	full := allocatedBytes(func() {
		if rr := poll(s, pollOpts{key: key, version: snap.Version}); rr.Code != http.StatusOK {
			t.Fatalf("full: %d", rr.Code)
		}
	})
	const polls = 10
	nm := allocatedBytes(func() {
		for i := 0; i < polls; i++ {
			if rr := poll(s, o); rr.Code != http.StatusNotModified {
				t.Fatalf("not-modified: %d", rr.Code)
			}
		}
	}) / polls
	t.Logf("allocated per poll: full=%d B, not-modified=%d B", full, nm)
	if nm*20 > full {
		t.Fatalf("not-modified poll allocated %d B, want < 5%% of a full snapshot (%d B)", nm, full)
	}
}

func BenchmarkClusterSnapshotPoll(b *testing.B) {
	st, err := store.Open(filepath.Join(b.TempDir(), "test.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	s := &Server{store: st}
	s.SetClusterEnrollment(false, 0, 0)
	if err := st.CreateEnrollKey(uuid.NewString(), "k", hashKey("s3cr3t"), keyPrefix("s3cr3t"), "test", 0, 0); err != nil {
		b.Fatal(err)
	}
	key := jsonField(enroll(s, `{"name":"agent-01","token":"s3cr3t"}`).Body.String(), "key")
	seedRules(b, st, 50000)
	node, _ := st.NodeByName("agent-01")
	var snap cluster.Snapshot
	_ = json.Unmarshal(poll(s, pollOpts{key: key}).Body.Bytes(), &snap)

	b.Run("full", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			poll(s, pollOpts{key: key, version: snap.Version})
		}
	})
	b.Run("not-modified", func(b *testing.B) {
		o := upToDate(key, node, snap)
		b.ReportAllocs()
		for b.Loop() {
			if rr := poll(s, o); rr.Code != http.StatusNotModified {
				b.Fatalf("status %d", rr.Code)
			}
		}
	})
}
