package victorialogs

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// fakeVL records what it ingests; fail makes it answer 503.
type fakeVL struct {
	mu       sync.Mutex
	lines    []map[string]any
	requests int
	query    string
	user     string
	fail     bool
}

func (f *fakeVL) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if f.fail {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	f.query = r.URL.RawQuery
	f.user, _, _ = r.BasicAuth()
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			f.lines = append(f.lines, m)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func setup(t *testing.T) (*store.Store, *fakeVL, *httptest.Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fakeVL{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	return st, f, srv
}

func entries(n int, ts int64) []store.QueryLogEntry {
	out := make([]store.QueryLogEntry, n)
	for i := range out {
		out[i] = store.QueryLogEntry{TS: ts, Client: "10.0.0.1", Name: "www.facebook.com.", QType: "A", Action: "forward",
			Rcode: "NOERROR", ElapsedMS: 12.5, ContentCategory: "social"}
	}
	return out
}

// The first run starts from now (no backlog); entries logged after that ship
// with every field, the content category included.
func TestExporterShipsNewEntries(t *testing.T) {
	st, f, srv := setup(t)
	now := time.Now().UnixMilli()
	if err := st.InsertNodeQueryLog("oci-dns03", entries(3, now)); err != nil { // before: skipped
		t.Fatal(err)
	}
	e := NewExporter(nil, st)
	blocked := entries(1, now)
	blocked[0].Name, blocked[0].Action, blocked[0].Category, blocked[0].ContentCategory = "bet365.com.", "blocked", "gambling", "gambling"
	if err := st.InsertNodeQueryLog("oci-dns03", append(entries(1, now), blocked...)); err != nil {
		t.Fatal(err)
	}
	n, err := e.ship(context.Background(), Config{URL: srv.URL, Username: "vl"})
	if err != nil || n != 2 {
		t.Fatalf("shipped %d, err %v; want 2", n, err)
	}
	if len(f.lines) != 2 {
		t.Fatalf("ingested %d lines, want 2 (the backlog from before the first run is skipped)", len(f.lines))
	}
	b := f.lines[1]
	for k, want := range map[string]any{"node": "oci-dns03", "name": "bet365.com", "action": "blocked", "category": "gambling",
		"content_category": "gambling", "client": "10.0.0.1", "qtype": "A", "_msg": "blocked bet365.com A"} {
		if b[k] != want {
			t.Errorf("%s = %v, want %v", k, b[k], want)
		}
	}
	if !strings.Contains(f.query, "_stream_fields=node,action") || f.user != "vl" {
		t.Errorf("query %q user %q", f.query, f.user)
	}
	if n, _ := e.ship(context.Background(), Config{URL: srv.URL}); n != 0 {
		t.Errorf("re-shipped %d entries", n)
	}
}

// A backlog larger than one batch is shipped within one cycle, batch after
// batch, instead of one batch per interval.
func TestExporterCatchesUp(t *testing.T) {
	st, f, srv := setup(t)
	e := NewExporter(func() Config { return Config{Enabled: true, URL: srv.URL, Interval: time.Hour} }, st)
	if err := st.InsertNodeQueryLog("a", entries(2*shipBatch+2000, time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		f.mu.Lock()
		got := len(f.lines)
		f.mu.Unlock()
		if got == 2*shipBatch+2000 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("shipped %d of %d in the first cycle", got, 2*shipBatch+2000)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if f.requests != 3 {
		t.Errorf("requests = %d, want 3 batches", f.requests)
	}
}

// When VictoriaLogs fails, the cursor stays: nothing is lost, and nothing is
// sent twice once it's back.
func TestExporterKeepsCursorOnFailure(t *testing.T) {
	st, f, srv := setup(t)
	e := NewExporter(nil, st)
	if err := st.InsertNodeQueryLog("a", entries(5, time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	f.fail = true
	if _, err := e.ship(context.Background(), Config{URL: srv.URL}); err == nil {
		t.Fatal("want an error while VictoriaLogs is down")
	}
	f.fail = false
	if n, err := e.ship(context.Background(), Config{URL: srv.URL}); err != nil || n != 5 {
		t.Fatalf("after recovery: shipped %d, err %v; want 5", n, err)
	}
	// A new exporter (a restart) resumes from the persisted cursor.
	if n, _ := NewExporter(nil, st).ship(context.Background(), Config{URL: srv.URL}); n != 0 {
		t.Errorf("after restart re-shipped %d", n)
	}
	if len(f.lines) != 5 {
		t.Errorf("ingested %d lines, want 5", len(f.lines))
	}
}
