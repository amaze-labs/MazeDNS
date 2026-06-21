package store

import (
	"log/slog"
	"time"
)

// QueryLogEntry is one logged DNS query.
type QueryLogEntry struct {
	ID        int64  `json:"id"`
	TS        int64  `json:"ts"` // unix millis
	Client    string `json:"client"`
	Name      string `json:"name"`
	QType     string `json:"qtype"`
	Action    string `json:"action"`
	Rcode     string `json:"rcode"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

// InsertQueryLogBatch writes multiple entries in a single transaction.
func (s *Store) InsertQueryLogBatch(entries []QueryLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO query_log(ts, client, name, qtype, action, rcode, elapsed_ms) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(e.TS, e.Client, e.Name, e.QType, e.Action, e.Rcode, e.ElapsedMS); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// RecentQueryLog returns up to limit most recent entries (newest first).
func (s *Store) RecentQueryLog(limit int) ([]QueryLogEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, ts, client, name, qtype, action, rcode, elapsed_ms
		 FROM query_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueryLogEntry
	for rows.Next() {
		var e QueryLogEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Client, &e.Name, &e.QType, &e.Action, &e.Rcode, &e.ElapsedMS); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountQueryLog returns the total number of logged queries.
func (s *Store) CountQueryLog() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM query_log`).Scan(&n)
	return n, err
}

// QueryLogWriter batches query-log entries and writes them asynchronously so the
// DNS hot path never blocks on the database.
type QueryLogWriter struct {
	ch   chan QueryLogEntry
	done chan struct{}
}

// NewQueryLogWriter starts a background writer. Entries are dropped if the buffer
// is full — logging must never stall DNS resolution.
func NewQueryLogWriter(s *Store, buffer int) *QueryLogWriter {
	if buffer <= 0 {
		buffer = 4096
	}
	w := &QueryLogWriter{
		ch:   make(chan QueryLogEntry, buffer),
		done: make(chan struct{}),
	}
	go w.run(s)
	return w
}

func (w *QueryLogWriter) run(s *Store) {
	defer close(w.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	batch := make([]QueryLogEntry, 0, 256)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.InsertQueryLogBatch(batch); err != nil {
			slog.Warn("query log flush failed", "err", err, "dropped", len(batch))
		}
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= 256 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Write enqueues an entry, dropping it if the buffer is full.
func (w *QueryLogWriter) Write(e QueryLogEntry) {
	select {
	case w.ch <- e:
	default: // buffer full: drop rather than block the DNS path
	}
}

// Close stops the writer, flushing any buffered entries.
func (w *QueryLogWriter) Close() {
	close(w.ch)
	<-w.done
}
