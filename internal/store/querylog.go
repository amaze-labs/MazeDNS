package store

import (
	"log/slog"
	"strings"
	"time"
)

// QueryLogEntry is one logged DNS query. Node is the resolver that handled it
// ("" = this node / master; otherwise a worker name shipped to the master).
type QueryLogEntry struct {
	ID        int64  `json:"id"`
	TS        int64  `json:"ts"` // unix millis
	Client    string `json:"client"`
	Name      string `json:"name"`
	QType     string `json:"qtype"`
	Action    string `json:"action"`
	Category  string `json:"category"`
	Rcode     string  `json:"rcode"`
	ElapsedMS float64 `json:"elapsed_ms"` // milliseconds, sub-ms precision
	Node      string  `json:"node"`
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
		`INSERT INTO query_log(ts, client, name, qtype, action, category, rcode, elapsed_ms) VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(e.TS, e.Client, e.Name, e.QType, e.Action, e.Category, e.Rcode, e.ElapsedMS); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// InsertNodeQueryLog writes a batch of entries received from a worker, tagged
// with the worker's node name (preserving the original timestamps).
func (s *Store) InsertNodeQueryLog(node string, entries []QueryLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO query_log(ts, client, name, qtype, action, category, rcode, elapsed_ms, node)
		 VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(e.TS, e.Client, e.Name, e.QType, e.Action, e.Category, e.Rcode, e.ElapsedMS, node); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// QueryLogSince returns up to limit entries with id greater than afterID
// (oldest first) and the highest id returned — used by workers to ship new
// entries to the master incrementally.
func (s *Store) QueryLogSince(afterID int64, limit int) ([]QueryLogEntry, int64, error) {
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	rows, err := s.db.Query(
		`SELECT id, ts, client, name, qtype, action, category, rcode, elapsed_ms
		 FROM query_log WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, afterID, err
	}
	defer rows.Close()
	var out []QueryLogEntry
	maxID := afterID
	for rows.Next() {
		var e QueryLogEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Client, &e.Name, &e.QType, &e.Action, &e.Category, &e.Rcode, &e.ElapsedMS); err != nil {
			return nil, afterID, err
		}
		if e.ID > maxID {
			maxID = e.ID
		}
		out = append(out, e)
	}
	return out, maxID, rows.Err()
}

// MaxQueryLogID returns the highest query-log id (0 if empty).
func (s *Store) MaxQueryLogID() (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM query_log`).Scan(&id)
	return id, err
}

// PruneQueryLog deletes entries older than beforeMs (unix millis).
func (s *Store) PruneQueryLog(beforeMs int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM query_log WHERE ts < ?`, beforeMs)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CountQueryLog returns the total number of logged queries.
func (s *Store) CountQueryLog() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM query_log`).Scan(&n)
	return n, err
}

// SearchQueryLog returns a page of query-log entries (newest first), optionally
// filtered by a substring match on name or client, plus the total match count.
func (s *Store) SearchQueryLog(search string, limit, offset int, nodes []string) ([]QueryLogEntry, int64, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var conds []string
	var args []any
	if search != "" {
		conds = append(conds, "(name LIKE ? OR client LIKE ?)")
		like := "%" + search + "%"
		args = append(args, like, like)
	}
	if len(nodes) > 0 {
		ph := make([]string, len(nodes))
		for i, n := range nodes {
			ph[i] = "?"
			args = append(args, n)
		}
		conds = append(conds, "node IN ("+strings.Join(ph, ",")+")")
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM query_log`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(
		`SELECT id, ts, client, name, qtype, action, category, rcode, elapsed_ms, node
		 FROM query_log`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []QueryLogEntry
	for rows.Next() {
		var e QueryLogEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Client, &e.Name, &e.QType, &e.Action, &e.Category, &e.Rcode, &e.ElapsedMS, &e.Node); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
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
