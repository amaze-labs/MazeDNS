package store

import (
	"errors"
	"log/slog"
	"sync"
	"time"
)

// NodeQueryLog is a batch of query-log entries one resolver shipped.
type NodeQueryLog struct {
	Node    string
	Entries []QueryLogEntry
}

// InsertNodeQueryLogs writes batches from any number of resolvers in a single
// transaction, each entry tagged with its resolver's node name (preserving
// the original timestamps).
func (s *Store) InsertNodeQueryLogs(batches []NodeQueryLog) error {
	n := 0
	for _, b := range batches {
		n += len(b.Entries)
	}
	if n == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO query_log(ts, client, name, qtype, action, category, rcode, elapsed_ms, node, content_category, upstream, forwarder)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, b := range batches {
		for _, e := range b.Entries {
			if _, err := stmt.Exec(e.TS, e.Client, e.Name, e.QType, e.Action, e.Category, e.Rcode, e.ElapsedMS, b.Node, e.ContentCategory, e.Upstream, e.Forwarder); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	return tx.Commit()
}

// maxIngestPending is how many entries the ingest buffer holds before it
// writes them without waiting for its timer (a few MB).
const maxIngestPending = 50000

// MaxIngestHeld bounds what the ingest buffer holds while the database
// refuses writes: past it, Add returns ErrIngestFull and the resolver keeps
// its batch to ship again.
const MaxIngestHeld = 4 * maxIngestPending

// ingestAttempts is how many flushes a batch may fail, while the database
// takes the other batches, before it is dropped as one it will never take.
const ingestAttempts = 3

// ErrIngestFull is returned by IngestBuffer.Add when the buffer holds
// MaxIngestHeld entries.
var ErrIngestFull = errors.New("query log ingest buffer full")

// IngestBuffer collects the query-log batches resolvers ship and writes all
// of them in one transaction every flush interval.
//
// Each commit to query_log rewrites the newest leaf page of every index for
// every client, category and action it touches, however few rows it adds. One
// commit per shipped batch, per resolver, rewrote those pages once per
// resolver every time any of them shipped; one commit for all of them
// rewrites each once per interval.
//
// A batch the database refuses never holds back the others: a failed commit
// is retried batch by batch, and a batch refused ingestAttempts times while
// the others go through is dropped. While the database refuses everything,
// nothing is dropped and the buffer stops taking batches at MaxIngestHeld.
//
// The trade-off: entries acknowledged to a resolver wait in memory until the
// next flush, so a control plane that dies without shutting down loses up to
// one interval of them (Close writes them on a clean shutdown), and the
// dashboard trails by as much.
type IngestBuffer struct {
	st      *Store
	insert  func([]NodeQueryLog) error // tests replace it
	mu      sync.Mutex
	pending []*heldBatch
	n       int
	closed  bool
	full    chan struct{}
	done    chan struct{}
	stopped chan struct{}
}

type heldBatch struct {
	NodeQueryLog
	strikes int // flushes it failed while others were written
}

// NewIngestBuffer returns a buffer that writes to s every interval.
func NewIngestBuffer(s *Store, every time.Duration) *IngestBuffer {
	b := &IngestBuffer{st: s, insert: s.InsertNodeQueryLogs,
		full: make(chan struct{}, 1), done: make(chan struct{}), stopped: make(chan struct{})}
	go b.run(every)
	return b
}

func (b *IngestBuffer) run(every time.Duration) {
	defer close(b.stopped)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-t.C:
		case <-b.full:
		}
		if err := b.Flush(); err != nil {
			slog.Warn("query log ingest flush failed; retrying", "err", err, "pending", b.Pending())
		}
	}
}

// Add queues a resolver's batch. It returns ErrIngestFull when the buffer
// already holds MaxIngestHeld entries. After Close the batch is written at
// once.
func (b *IngestBuffer) Add(node string, entries []QueryLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return b.insert([]NodeQueryLog{{node, entries}})
	}
	if b.n+len(entries) > MaxIngestHeld {
		b.mu.Unlock()
		return ErrIngestFull
	}
	b.pending = append(b.pending, &heldBatch{NodeQueryLog: NodeQueryLog{node, entries}})
	b.n += len(entries)
	full := b.n >= maxIngestPending
	b.mu.Unlock()
	if full {
		select {
		case b.full <- struct{}{}:
		default:
		}
	}
	return nil
}

// Pending returns how many entries wait for the next flush.
func (b *IngestBuffer) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// Flush writes everything pending, in one transaction when the database takes
// it all. Batches that fail stay pending for the next flush, unless dropped
// (see IngestBuffer).
func (b *IngestBuffer) Flush() error {
	b.mu.Lock()
	held := b.pending
	b.pending, b.n = nil, 0
	b.mu.Unlock()
	if len(held) == 0 {
		return nil
	}
	all := make([]NodeQueryLog, len(held))
	for i, h := range held {
		all[i] = h.NodeQueryLog
	}
	err := b.insert(all)
	if err == nil {
		return nil
	}
	// One batch at a time, so one the database refuses can't hold back the
	// others.
	var failed []*heldBatch
	wrote := false
	for _, h := range held {
		if b.insert([]NodeQueryLog{h.NodeQueryLog}) != nil {
			failed = append(failed, h)
		} else {
			wrote = true
		}
	}
	keep := failed[:0]
	for _, h := range failed {
		if wrote {
			h.strikes++ // refused while the database took others
		}
		if h.strikes >= ingestAttempts {
			slog.Warn("query log batch refused repeatedly; dropped", "node", h.Node, "entries", len(h.Entries), "err", err)
			continue
		}
		keep = append(keep, h)
	}
	if len(keep) == 0 {
		return nil
	}
	n := 0
	for _, h := range keep {
		n += len(h.Entries)
	}
	b.mu.Lock()
	b.pending = append(keep, b.pending...)
	b.n += n
	b.mu.Unlock()
	return err
}

// Close stops the timer and writes what is pending. Later batches are written
// as they arrive.
func (b *IngestBuffer) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	b.mu.Unlock()
	close(b.done)
	<-b.stopped
	if err := b.Flush(); err != nil {
		slog.Warn("query log ingest flush at shutdown failed", "err", err, "dropped", b.Pending())
	}
}
