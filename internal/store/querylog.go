package store

import (
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
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
	// ContentCategory is what the domain is (social, shopping, …), labelled on
	// the control plane as the entry arrives; Category is the block reason.
	ContentCategory string `json:"content_category"`
	// Upstream is the upstream that answered a forwarded query, as configured,
	// and Forwarder the conditional forwarder's suffix that routed it ("" =
	// the default upstreams). Empty for other actions, and for entries from an
	// agent too old to report them.
	Upstream  string `json:"upstream,omitempty"`
	Forwarder string `json:"forwarder,omitempty"`
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
		`INSERT INTO query_log(ts, client, name, qtype, action, category, rcode, elapsed_ms, upstream, forwarder)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(e.TS, e.Client, e.Name, e.QType, e.Action, e.Category, e.Rcode, e.ElapsedMS, e.Upstream, e.Forwarder); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// InsertNodeQueryLog writes a batch of entries received from a worker, tagged
// with the worker's node name (preserving the original timestamps).
func (s *Store) InsertNodeQueryLog(node string, entries []QueryLogEntry) error {
	return s.InsertNodeQueryLogs([]NodeQueryLog{{node, entries}})
}

// QueryLogSince returns up to limit entries with id greater than afterID
// (oldest first) and the highest id returned — used by workers to ship new
// entries to the master incrementally.
func (s *Store) QueryLogSince(afterID int64, limit int) ([]QueryLogEntry, int64, error) {
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	rows, err := s.read.Query(
		`SELECT id, ts, client, name, qtype, action, category, rcode, elapsed_ms, node, content_category, upstream, forwarder
		 FROM query_log WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, afterID, err
	}
	defer rows.Close()
	var out []QueryLogEntry
	maxID := afterID
	for rows.Next() {
		var e QueryLogEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Client, &e.Name, &e.QType, &e.Action, &e.Category, &e.Rcode, &e.ElapsedMS, &e.Node, &e.ContentCategory, &e.Upstream, &e.Forwarder); err != nil {
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
	err := s.read.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM query_log`).Scan(&id)
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
	err := s.read.QueryRow(`SELECT COUNT(*) FROM query_log`).Scan(&n)
	return n, err
}

// QueryLogQuery describes a filtered, sorted, paginated query-log lookup.
type QueryLogQuery struct {
	Search   string // substring match on name or client
	Action   string // exact action filter ("" = all)
	QType    string // exact query-type filter ("" = all)
	Category string // exact block-reason category filter ("" = all)
	Content  string // exact content-category filter ("" = all)
	// Upstream filters on the upstream that answered ("" = all), and Forwarder
	// further on the conditional forwarder that routed it ("" = any).
	Upstream  string
	Forwarder string
	Nodes     []string // node filter (empty = all)
	SinceMs   int64    // only entries with ts >= SinceMs (0 = no lower bound)
	Sort      string   // column key (see queryLogSortColumns); default newest-first
	Desc      bool     // sort descending
	Limit     int
	Offset    int
}

// queryLogSortColumns whitelists the user-facing sort keys -> SQL columns, so the
// ORDER BY clause can never be injected.
var queryLogSortColumns = map[string]string{
	"time":     "id", // id is monotonic, a stable proxy for arrival time
	"name":     "name",
	"client":   "client",
	"qtype":    "qtype",
	"action":   "action",
	"category": "category",
	"content":  "content_category",
	"rcode":    "rcode",
	"ms":       "elapsed_ms",
	"node":     "node",
	"upstream": "upstream",
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
	if q.Category != "" {
		conds = append(conds, "category = ?")
		args = append(args, q.Category)
	}
	if q.Content != "" {
		conds = append(conds, "content_category = ?")
		args = append(args, q.Content)
	}
	if q.Upstream != "" {
		conds = append(conds, "upstream = ?")
		args = append(args, q.Upstream)
		if q.Forwarder != "" {
			conds = append(conds, "forwarder = ?")
			args = append(args, q.Forwarder)
		}
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
	if err := s.read.QueryRow(`SELECT COUNT(*) FROM query_log`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.read.Query(
		`SELECT id, ts, client, name, qtype, action, category, rcode, elapsed_ms, node, content_category, upstream, forwarder
		 FROM query_log`+where+orderBy+` LIMIT ? OFFSET ?`,
		append(args, q.Limit, q.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []QueryLogEntry
	for rows.Next() {
		var e QueryLogEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Client, &e.Name, &e.QType, &e.Action, &e.Category, &e.Rcode, &e.ElapsedMS, &e.Node, &e.ContentCategory, &e.Upstream, &e.Forwarder); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// QueryLogBuffer is a resolver's query-log outbox. Entries wait in memory until
// the cluster agent takes them to ship to the control plane, which holds the
// cluster-wide log; the database only receives what memory can't hold. That
// is a full buffer (the control plane is unreachable, or this node runs
// standalone), or whatever is still buffered at shutdown, and it goes in one
// large batch, which the agent ships from the database later. A node that
// ships on time writes no query log to disk at all.
//
// Committing every entry within a second, as before, cost far more than the
// entries themselves: each small commit rewrote whole pages of the table and
// its indexes, twice with the WAL checkpoint.
//
// The trade-off: if the process dies without shutting down, it loses what is
// buffered: one ship interval's worth when the control plane is reachable.
type QueryLogBuffer struct {
	mu      sync.Mutex
	pending []QueryLogEntry
	max     int
	closed  bool
	st      *Store
	spill   chan []QueryLogEntry
	done    chan struct{}
	dropped atomic.Uint64
}

// DefaultQueryLogBuffer is how many entries a resolver holds in memory
// (a few MB) before spilling them to the database.
const DefaultQueryLogBuffer = 50000

// NewQueryLogBuffer returns a buffer holding up to max entries in memory
// before it spills them to s.
func NewQueryLogBuffer(s *Store, max int) *QueryLogBuffer {
	if max <= 0 {
		max = DefaultQueryLogBuffer
	}
	b := &QueryLogBuffer{max: max, st: s, spill: make(chan []QueryLogEntry, 4), done: make(chan struct{})}
	go b.runSpill()
	return b
}

func (b *QueryLogBuffer) runSpill() {
	defer close(b.done)
	for batch := range b.spill {
		b.insert(batch)
	}
}

func (b *QueryLogBuffer) insert(batch []QueryLogEntry) {
	if err := b.st.InsertQueryLogBatch(batch); err != nil {
		b.dropped.Add(uint64(len(batch)))
		slog.Warn("query log spill failed", "err", err, "dropped", len(batch))
	}
}

// toDiskLocked hands a batch to the spill goroutine without waiting on the
// database: if it is still busy with earlier batches, this one is dropped
// (logging must never stall DNS resolution). b.mu must be held and the buffer
// open.
func (b *QueryLogBuffer) toDiskLocked(batch []QueryLogEntry) {
	select {
	case b.spill <- batch:
	default:
		b.dropped.Add(uint64(len(batch)))
	}
}

// Write appends an entry. It never waits on the database.
func (b *QueryLogBuffer) Write(e QueryLogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		b.dropped.Add(1)
		return
	}
	b.pending = append(b.pending, e)
	if len(b.pending) >= b.max {
		b.toDiskLocked(b.pending)
		b.pending = nil
	}
}

// Take removes and returns up to n of the oldest entries.
func (b *QueryLogBuffer) Take(n int) []QueryLogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := min(n, len(b.pending))
	if k == 0 {
		return nil
	}
	out := make([]QueryLogEntry, k)
	copy(out, b.pending)
	if k == len(b.pending) {
		b.pending = nil // let the backing array go
	} else {
		b.pending = b.pending[k:]
	}
	return out
}

// Requeue puts back entries taken for a ship that failed, ahead of the newer
// ones. Once the buffer is closed they go straight to the database.
func (b *QueryLogBuffer) Requeue(entries []QueryLogEntry) {
	if len(entries) == 0 {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		b.insert(entries)
		return
	}
	defer b.mu.Unlock()
	b.pending = append(append(make([]QueryLogEntry, 0, len(entries)+len(b.pending)), entries...), b.pending...)
	if len(b.pending) >= b.max {
		b.toDiskLocked(b.pending)
		b.pending = nil
	}
}

// Len returns how many entries are held in memory.
func (b *QueryLogBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// Dropped returns the number of entries lost: the spill could not keep up, or
// the database refused them. Exposed as the mazedns_querylog_dropped_total
// metric so sustained overload (the dashboard undercounting) is observable
// rather than silent.
func (b *QueryLogBuffer) Dropped() uint64 { return b.dropped.Load() }

// Close writes everything still in memory to the database and waits for it.
// Later writes are dropped; later requeues go to the database directly.
func (b *QueryLogBuffer) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	rest := b.pending
	b.pending = nil
	b.mu.Unlock()
	// No other sender can reach the channel now that closed is set.
	if len(rest) > 0 {
		b.spill <- rest
	}
	close(b.spill)
	<-b.done
}
