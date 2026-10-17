package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// A control-plane outage is recorded as a sync failure while the node keeps the
// config it already applied; the next successful poll is recorded as a success,
// with no restart in between.
func TestSyncHealthAcrossOutage(t *testing.T) {
	snap := Snapshot{
		Version:  "v1",
		Rewrites: []store.Rewrite{{Domain: "nas.lan", RRType: "A", Value: "10.0.0.5", Enabled: true, UpdatedAt: 1}},
	}
	var down atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			// Like a control plane behind a dead VPN: the request hangs until the
			// client gives up.
			<-r.Context().Done()
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

	ag := NewAgent(ts.URL, "", "tok", "", time.Second, st, func() error { return nil },
		func() store.NodeStats { return store.NodeStats{} }, nil, nil)
	h := &SyncHealth{}
	ag.SetSyncHealth(h)

	if s := h.Status(); !s.LastOK.IsZero() || !s.LastError.IsZero() {
		t.Fatalf("fresh status = %+v, want zero", s)
	}

	ag.syncOnce(context.Background())
	first := h.Status()
	if first.LastOK.IsZero() || !first.LastError.IsZero() {
		t.Fatalf("after a good sync: %+v", first)
	}

	down.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	ag.syncOnce(ctx)
	cancel()
	failed := h.Status()
	if failed.LastError.IsZero() || failed.Error == "" || !failed.LastOK.Equal(first.LastOK) {
		t.Fatalf("after a failed sync: %+v", failed)
	}
	if rws, _ := st.ListRewrites(); len(rws) != 1 || rws[0].Value != "10.0.0.5" {
		t.Fatalf("persisted rewrites lost during the outage: %+v", rws)
	}

	down.Store(false)
	time.Sleep(2 * time.Millisecond) // distinct millisecond timestamp
	ag.syncOnce(context.Background())
	if s := h.Status(); s.LastOK.Before(failed.LastError) {
		t.Fatalf("recovery not recorded: %+v", s)
	}
}
