package store

import (
	"fmt"
	"testing"
	"time"
)

func entries(from, n int) []QueryLogEntry {
	out := make([]QueryLogEntry, n)
	for i := range out {
		out[i] = QueryLogEntry{TS: int64(from + i), Name: fmt.Sprintf("n%d.example", from+i), QType: "A", Action: "forward"}
	}
	return out
}

func tsOf(es []QueryLogEntry) []int64 {
	out := make([]int64, len(es))
	for i, e := range es {
		out[i] = e.TS
	}
	return out
}

// Entries wait in memory, oldest first, and touch the database only once
// memory is full.
func TestQueryLogBufferHoldsEntriesInMemory(t *testing.T) {
	s := openTestStore(t)
	b := NewQueryLogBuffer(s, 10)
	for _, e := range entries(0, 5) {
		b.Write(e)
	}
	if got := tsOf(b.Take(3)); fmt.Sprint(got) != "[0 1 2]" {
		t.Fatalf("Take(3) = %v, want the 3 oldest", got)
	}
	// A failed ship puts its entries back ahead of the newer ones.
	b.Requeue(entries(1, 2))
	if got := tsOf(b.Take(100)); fmt.Sprint(got) != "[1 2 3 4]" {
		t.Fatalf("after Requeue, Take = %v, want [1 2 3 4]", got)
	}
	if n, _ := s.CountQueryLog(); n != 0 {
		t.Fatalf("%d rows written to the database, want none", n)
	}
	b.Close()
}

// When memory fills (the control plane is not taking entries), the whole
// buffer goes to the database in one batch.
func TestQueryLogBufferSpillsWhenFull(t *testing.T) {
	s := openTestStore(t)
	b := NewQueryLogBuffer(s, 10)
	for _, e := range entries(0, 25) {
		b.Write(e)
	}
	waitRows(t, s, 20)
	if got := b.Len(); got != 5 {
		t.Fatalf("%d entries left in memory, want 5", got)
	}
	// Close keeps the rest: it goes to the database too.
	b.Close()
	if n, _ := s.CountQueryLog(); n != 25 {
		t.Fatalf("after Close: %d rows, want 25", n)
	}
	// After Close, a requeued batch still reaches the database.
	b.Requeue(entries(100, 2))
	if n, _ := s.CountQueryLog(); n != 27 {
		t.Fatalf("requeue after Close: %d rows, want 27", n)
	}
	if b.Dropped() != 0 {
		t.Fatalf("dropped %d, want 0", b.Dropped())
	}
	// A write after Close has nowhere to go.
	b.Write(entries(200, 1)[0])
	if b.Dropped() != 1 {
		t.Fatalf("dropped %d after a write past Close, want 1", b.Dropped())
	}
}

func waitRows(t *testing.T, s *Store, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n, _ := s.CountQueryLog()
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d rows in the database, want %d", n, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
