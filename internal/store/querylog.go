package store

import (
	"log/slog"
	"strings"
	"time"
)

// QueryLogEntry is one logged DNS query. Node is the resolver that handled it
// ("" = this node / master; otherwise a worker name shipped to the master).
type QueryLogEntry struct {
	ID        int64   `json:"id"`
	TS        int64   `json:"ts"` // unix millis
	Client    string  `json:"client"`
	Name      string  `json:"name"`
	QType     string  `json:"qtype"`
	Action    string  `json:"action"`
	Category  string  `json:"category"`
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

// QueryLogQuery describes a filtered, sorted, paginated query-log lookup.
type QueryLogQuery struct {
	Search  string   // substring match on name or client
	Action  string   // exact action filter ("" = all)
	QType   string   // exact query-type filter ("" = all)
	Nodes   []string // node filter (empty = all)
	SinceMs int64    // only entries with ts >= SinceMs (0 = no lower bound)
	Sort    string   // column key (see queryLogSortColumns); default newest-first
	Desc    bool     // sort descending
	Limit   int
	Offset  int
}

// queryLogSortColumns whitelists the user-facing sort keys -> SQL columns, so the
// ORDER BY clause can never be injected.
var queryLogSortColumns = map[string]string{
	"time":   "id", // id is monotonic, a stable proxy for arrival time
	"name":   "name",
	"client": "client",
	"qtype":  "qtype",
	"action": "action",
	"rcode":  "rcode",
	"ms":     "elapsed_ms",
	"node":   "node",
}

// SearchQueryLog returns a filtered, sorted page of query-log entries plus the
// total match count. Defaults to newest-first.
func (s *Store) SearchQueryLog(q QueryLogQuery) ([]QueryLogEntry, int64, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	var conds []string
	var args []any
	if q.SinceMs > 0 {
		conds = append(conds, "ts >= ?")
		args = append(args, q.SinceMs)
	}
	if q.Search != "" {
		conds = append(conds, "(name LIKE ? OR client LIKE ?)")
		like := "%" + q.Search + "%"
		args = append(args, like, like)
	}
	if q.Action != "" {
		conds = append(conds, "action = ?")
		args = append(args, q.Action)
	}
	if q.QType != "" {
		conds = append(conds, "qtype = ?")
		args = append(args, q.QType)
	}
	if len(q.Nodes) > 0 {
		ph := make([]string, len(q.Nodes))
		for i, n := range q.Nodes {
			ph[i] = "?"
			args = append(args, n)
		}
		conds = append(conds, "node IN ("+strings.Join(ph, ",")+")")
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	col, ok := queryLogSortColumns[q.Sort]
	if !ok {
		col = "id"
	}
	dir := "DESC"
	if !q.Desc && q.Sort != "" {
		dir = "ASC"
	}
	// Tie-break on id so paging is stable when the sort column has duplicates.
	orderBy := " ORDER BY " + col + " " + dir
	if col != "id" {
		orderBy += ", id DESC"
	}

	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM query_log`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(
		`SELECT id, ts, client, name, qtype, action, category, rcode, elapsed_ms, node
		 FROM query_log`+where+orderBy+` LIMIT ? OFFSET ?`,
		append(args, q.Limit, q.Offset)...)
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
