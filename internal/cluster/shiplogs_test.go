package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// logCP accepts (or, with fail set, rejects) query-log posts and counts what
// it received; every other request gets an empty snapshot.
type logCP struct {
	mu       sync.Mutex
	fail     bool
	received []store.QueryLogEntry
}

func (c *logCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.URL.Path != "/api/cluster/log" {
		_ = json.NewEncoder(w).Encode(Snapshot{})
		return
	}
	if c.fail {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var es []store.QueryLogEntry
	_ = json.NewDecoder(r.Body).Decode(&es)
	c.received = append(c.received, es...)
	w.WriteHeader(http.StatusOK)
}

func (c *logCP) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.received)
}

func logEntries(n int) []store.QueryLogEntry {
	out := make([]store.QueryLogEntry, n)
	for i := range out {
		out[i] = store.QueryLogEntry{TS: int64(i), Name: "x.example", QType: "A", Action: "forward"}
	}
	return out
}

// Buffered entries go straight from memory to the control plane: the agent's
// database never sees them.
func TestShipLogsFromMemoryWritesNothing(t *testing.T) {
	cp := &logCP{}
	ag, st, _ := newAgentAgainst(t, cp)
	buf := store.NewQueryLogBuffer(st, 100000)
	t.Cleanup(buf.Close)
	ag.SetQueryLog(buf)
	for _, e := range logEntries(shipBatch + 7) {
		buf.Write(e)
	}
	ag.shipLogs(context.Background())
	if got := cp.count(); got != shipBatch+7 {
		t.Fatalf("control plane received %d entries, want %d", got, shipBatch+7)
	}
	if buf.Len() != 0 {
		t.Fatalf("%d entries left in memory after shipping", buf.Len())
	}
	if n, _ := st.CountQueryLog(); n != 0 {
		t.Fatalf("%d query-log rows written to the agent's database, want none", n)
	}
}

// A failed ship keeps the entries in memory for the next cycle.
func TestShipLogsKeepsEntriesWhenTheControlPlaneFails(t *testing.T) {
	cp := &logCP{fail: true}
	ag, st, _ := newAgentAgainst(t, cp)
	buf := store.NewQueryLogBuffer(st, 100000)
	t.Cleanup(buf.Close)
	ag.SetQueryLog(buf)
	for _, e := range logEntries(10) {
		buf.Write(e)
	}
	ag.shipLogs(context.Background())
	if buf.Len() != 10 {
		t.Fatalf("%d entries kept after a failed ship, want 10", buf.Len())
	}
	cp.mu.Lock()
	cp.fail = false
	cp.mu.Unlock()
	ag.shipLogs(context.Background())
	if got := cp.count(); got != 10 || buf.Len() != 0 {
		t.Fatalf("retry shipped %d (left %d), want all 10", got, buf.Len())
	}
}

// Rows in the database (spilled, or left by an older build) are shipped and
// then deleted: the agent keeps no copy of what the control plane holds.
func TestShipLogsDeletesShippedRows(t *testing.T) {
	cp := &logCP{}
	ag, st, _ := newAgentAgainst(t, cp)
	if err := st.InsertQueryLogBatch(logEntries(25)); err != nil {
		t.Fatal(err)
	}
	ag.shipLogs(context.Background())
	if got := cp.count(); got != 25 {
		t.Fatalf("control plane received %d entries, want 25", got)
	}
	if n, _ := st.CountQueryLog(); n != 0 {
		t.Fatalf("%d shipped rows still in the agent's database", n)
	}
}

// Rows an older build kept after shipping them are deleted on the first
// cycle, without shipping them again.
func TestShipLogsPurgesRowsShippedBefore(t *testing.T) {
	cp := &logCP{}
	ag, st, _ := newAgentAgainst(t, cp)
	if err := st.InsertQueryLogBatch(logEntries(30)); err != nil {
		t.Fatal(err)
	}
	ag.lastShipped, _ = st.MaxQueryLogID() // all of it already shipped
	ag.shipLogs(context.Background())
	if got := cp.count(); got != 0 {
		t.Fatalf("re-shipped %d entries the control plane already holds", got)
	}
	if n, _ := st.CountQueryLog(); n != 0 {
		t.Fatalf("%d already-shipped rows left in the agent's database", n)
	}
}

// Entries spilled at shutdown are shipped after a restart, even by a node
// whose cursor never moved (everything before went from memory).
func TestShipLogsAfterRestartShipsSpilledEntries(t *testing.T) {
	cp := &logCP{}
	ag, st, _ := newAgentAgainst(t, cp) // first run: cursor initialised at 0
	buf := store.NewQueryLogBuffer(st, 100000)
	ag.SetQueryLog(buf)
	for _, e := range logEntries(3) {
		buf.Write(e)
	}
	ag.shipLogs(context.Background()) // from memory: the cursor stays 0
	for _, e := range logEntries(4) {
		buf.Write(e)
	}
	buf.Close() // shutdown: the 4 unshipped entries go to the database

	// Restart: a new agent over the same database.
	ag2 := NewAgent(ag.masterURL, "", "tok", "", time.Second, st, nil, nil, nil, nil)
	ag2.shipLogs(context.Background())
	if got := cp.count(); got != 7 {
		t.Fatalf("control plane received %d entries, want 3 + 4 spilled", got)
	}
}

// Query logs go out every logShipInterval, not every sync cycle: fewer,
// larger batches cost the control plane far fewer index page writes. A
// buffer holding a full batch goes out at once, so a busy node never fills
// its buffer waiting.
func TestQueryLogsShipEveryInterval(t *testing.T) {
	cp := &logCP{}
	ag, st, _ := newAgentAgainst(t, cp)
	buf := store.NewQueryLogBuffer(st, 100000)
	t.Cleanup(buf.Close)
	ag.SetQueryLog(buf)
	now := time.Unix(1_700_000_000, 0)
	ag.now = func() time.Time { return now }

	if !ag.logsDue() {
		t.Fatal("the first cycle must ship")
	}
	now = now.Add(30 * time.Second)
	if ag.logsDue() {
		t.Fatal("30s later: not due yet")
	}
	for _, e := range logEntries(shipBatch) {
		buf.Write(e)
	}
	if !ag.logsDue() {
		t.Fatal("a full batch buffered must ship at once")
	}
	ag.shipLogs(context.Background())
	now = now.Add(logShipInterval - time.Second)
	if ag.logsDue() {
		t.Fatal("before the interval: not due")
	}
	now = now.Add(time.Second)
	if !ag.logsDue() {
		t.Fatal("after the interval: due")
	}
}
