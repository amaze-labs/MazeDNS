package store

import (
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

// IngestBuffer collects the query-log batches resolvers ship and writes all
// of them in one transaction every flush interval.
//
// Each commit to query_log rewrites the newest leaf page of every index for
// every client, category and action it touches, however few rows it adds. One
// commit per shipped batch, per resolver, rewrote those pages once per
// resolver every time any of them shipped; one commit for all of them
// rewrites each once per interval.
//
// The trade-off: entries acknowledged to a resolver wait in memory until the
// next flush, so a control plane that dies without shutting down loses up to
// one interval of them (Close writes them on a clean shutdown), and the
// dashboard trails by as much.
type IngestBuffer struct {
	st      *Store
	mu      sync.Mutex
	pending []NodeQueryLog
	n       int
	closed  bool
	full    chan struct{}
	done    chan struct{}
	stopped chan struct{}
}

// NewIngestBuffer returns a buffer that writes to s every interval.
func NewIngestBuffer(s *Store, every time.Duration) *IngestBuffer {
	b := &IngestBuffer{st: s, full: make(chan struct{}, 1), done: make(chan struct{}), stopped: make(chan struct{})}
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

// Add queues a resolver's batch. After Close it is written at once.
func (b *IngestBuffer) Add(node string, entries []QueryLogEntry) {
	if len(entries) == 0 {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		if err := b.st.InsertNodeQueryLogs([]NodeQueryLog{{node, entries}}); err != nil {
			slog.Warn("query log ingest failed", "err", err, "dropped", len(entries))
		}
		return
	}
	b.pending = append(b.pending, NodeQueryLog{node, entries})
	b.n += len(entries)
	full := b.n >= maxIngestPending
	b.mu.Unlock()
	if full {
		select {
		case b.full <- struct{}{}:
		default:
		}
	}
}

// Pending returns how many entries wait for the next flush.
func (b *IngestBuffer) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// Flush writes everything pending in one transaction. On failure the batches
// are kept for the next attempt.
func (b *IngestBuffer) Flush() error {
	b.mu.Lock()
	batches, n := b.pending, b.n
	b.pending, b.n = nil, 0
	b.mu.Unlock()
	if n == 0 {
		return nil
	}
	if err := b.st.InsertNodeQueryLogs(batches); err != nil {
		b.mu.Lock()
		b.pending = append(batches, b.pending...)
		b.n += n
		b.mu.Unlock()
		return err
	}
	return nil
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
