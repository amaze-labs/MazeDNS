package store

import (
	"errors"
	"testing"
	"time"
)

func nodeEntries(n int) []QueryLogEntry {
	out := make([]QueryLogEntry, n)
	for i := range out {
		out[i] = QueryLogEntry{TS: int64(i), Client: "c", Name: "x.example", QType: "A", Action: "forward"}
	}
	return out
}

// countByNode returns how many query-log rows each node has.
func countByNode(t *testing.T, s *Store) map[string]int {
	t.Helper()
	rows, err := s.read.Query(`SELECT node, COUNT(*) FROM query_log GROUP BY node`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var n string
		var c int
		if err := rows.Scan(&n, &c); err != nil {
			t.Fatal(err)
		}
		m[n] = c
	}
	return m
}

// Batches from several resolvers are written in one transaction, each tagged
// with its node.
func TestInsertNodeQueryLogsTagsEachBatch(t *testing.T) {
	s := openTestStore(t)
	if err := s.InsertNodeQueryLogs([]NodeQueryLog{{"r1", nodeEntries(3)}, {"r2", nodeEntries(2)}}); err != nil {
		t.Fatal(err)
	}
	if got := countByNode(t, s); got["r1"] != 3 || got["r2"] != 2 {
		t.Fatalf("rows by node = %v, want r1:3 r2:2", got)
	}
}

// The ingest buffer holds what resolvers ship and writes it all in one
// transaction per flush; Close writes what is left.
func TestIngestBufferCoalesces(t *testing.T) {
	s := openTestStore(t)
	b := NewIngestBuffer(s, time.Hour) // no timed flush during the test
	b.Add("r1", nodeEntries(3))
	b.Add("r2", nodeEntries(2))
	b.Add("r1", nodeEntries(1))
	if n, _ := s.CountQueryLog(); n != 0 {
		t.Fatalf("%d rows written before a flush, want 0", n)
	}
	if b.Pending() != 6 {
		t.Fatalf("pending = %d, want 6", b.Pending())
	}
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := countByNode(t, s); got["r1"] != 4 || got["r2"] != 2 {
		t.Fatalf("after flush rows by node = %v, want r1:4 r2:2", got)
	}
	b.Add("r3", nodeEntries(5))
	b.Close()
	if got := countByNode(t, s); got["r3"] != 5 {
		t.Fatalf("after Close rows by node = %v, want r3:5", got)
	}
	// After Close, batches are written at once (nothing would flush them).
	b.Add("r4", nodeEntries(1))
	if got := countByNode(t, s); got["r4"] != 1 {
		t.Fatalf("add after Close: rows by node = %v, want r4:1", got)
	}
}

// A buffer holding maxIngestPending entries flushes without waiting for the
// timer, so a burst can't grow it without bound.
func TestIngestBufferFlushesWhenFull(t *testing.T) {
	s := openTestStore(t)
	b := NewIngestBuffer(s, time.Hour)
	defer b.Close()
	b.Add("r1", nodeEntries(maxIngestPending))
	waitRows(t, s, int64(maxIngestPending))
}

// A batch the database keeps refusing is dropped after a few attempts and
// never holds back the other resolvers' batches.
func TestIngestBufferDropsAPoisonBatch(t *testing.T) {
	s := openTestStore(t)
	b := NewIngestBuffer(s, time.Hour)
	defer b.Close()
	b.insert = func(batches []NodeQueryLog) error {
		for _, x := range batches {
			if x.Node == "bad" {
				return errors.New("refused")
			}
		}
		return s.InsertNodeQueryLogs(batches)
	}
	_ = b.Add("good", nodeEntries(2))
	_ = b.Add("bad", nodeEntries(1))
	_ = b.Flush()
	if got := countByNode(t, s); got["good"] != 2 {
		t.Fatalf("rows by node = %v: the good batch must be written despite the bad one", got)
	}
	// Other resolvers keep shipping; the refused batch is dropped once it
	// failed ingestAttempts flushes that wrote theirs.
	for i := 1; i < ingestAttempts; i++ {
		_ = b.Add("good", nodeEntries(1))
		_ = b.Flush()
	}
	if b.Pending() != 0 {
		t.Fatalf("%d entries still pending: the refused batch must be dropped after %d attempts", b.Pending(), ingestAttempts)
	}
	if got := countByNode(t, s); got["good"] != 2+ingestAttempts-1 {
		t.Fatalf("rows by node = %v", got)
	}
}

// While the database refuses everything, the buffer holds a bounded amount
// and then refuses new batches (the resolver keeps them and ships again).
func TestIngestBufferRefusesWhenFull(t *testing.T) {
	s := openTestStore(t)
	b := NewIngestBuffer(s, time.Hour)
	defer b.Close()
	b.insert = func([]NodeQueryLog) error { return errors.New("database down") }
	if err := b.Add("r1", nodeEntries(MaxIngestHeld)); err != nil {
		t.Fatalf("up to the limit: %v", err)
	}
	if err := b.Add("r1", nodeEntries(1)); !errors.Is(err, ErrIngestFull) {
		t.Fatalf("past the limit: err = %v, want ErrIngestFull", err)
	}
	// A database that is down drops nothing: every batch fails alike.
	for i := 0; i < ingestAttempts+1; i++ {
		_ = b.Flush()
	}
	if b.Pending() != MaxIngestHeld {
		t.Fatalf("pending = %d after failed flushes, want %d kept", b.Pending(), MaxIngestHeld)
	}
	b.insert = s.InsertNodeQueryLogs // let Close write
}
