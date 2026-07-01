package store

import (
	"sort"
	"time"
)

// rollupCursorKey tracks how far query_log has been folded into the rollups.
const rollupCursorKey = "rollup_cursor_id"

// RollupAdvance folds the next batch of new query_log rows (id in (cursor, upto])
// into the rollup tables, advancing the cursor atomically in the same transaction
// (so a row is counted exactly once — never double-counted on retry). Returns
// whether more rows remain, so the caller can loop to backfill then idle. Runs on
// the master, whose query_log is cluster-wide.
func (s *Store) RollupAdvance(batch int) (more bool, err error) {
	if batch <= 0 {
		batch = 50000
	}
	cursor, _ := s.GetMetaInt(rollupCursorKey)
	maxID, err := s.MaxQueryLogID()
	if err != nil {
		return false, err
	}
	if cursor >= maxID {
		return false, nil
	}
	upto := cursor + int64(batch)
	if upto > maxID {
		upto = maxID
	}

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(
		`INSERT INTO query_rollup(bucket, node, action, cnt, lat_sum)
		 SELECT ts/60000, node, action, COUNT(*), COALESCE(SUM(elapsed_ms), 0)
		 FROM query_log WHERE id > ? AND id <= ?
		 GROUP BY ts/60000, node, action
		 ON CONFLICT(bucket, node, action) DO UPDATE SET
		   cnt = cnt + excluded.cnt, lat_sum = lat_sum + excluded.lat_sum`,
		cursor, upto); err != nil {
		_ = tx.Rollback()
		return false, err
	}
	if _, err = tx.Exec(
		`INSERT INTO client_rollup(hour, node, client, cnt, blocked)
		 SELECT ts/3600000, node, client, COUNT(*), COALESCE(SUM(action='blocked'), 0)
		 FROM query_log WHERE id > ? AND id <= ? AND client <> ''
		 GROUP BY ts/3600000, node, client
		 ON CONFLICT(hour, node, client) DO UPDATE SET
		   cnt = cnt + excluded.cnt, blocked = blocked + excluded.blocked`,
		cursor, upto); err != nil {
		_ = tx.Rollback()
		return false, err
	}
	if _, err = tx.Exec(
		`INSERT INTO meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, rollupCursorKey, upto); err != nil {
		_ = tx.Rollback()
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return upto < maxID, nil
}

// PruneRollups drops rollup buckets older than beforeMs.
func (s *Store) PruneRollups(beforeMs int64) error {
	if _, err := s.db.Exec(`DELETE FROM query_rollup WHERE bucket < ?`, beforeMs/60000); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM client_rollup WHERE hour < ?`, beforeMs/3600000)
	return err
}

// RollupTimeSeries returns per-bucket query counts from the rollup, re-bucketed to
// stepSec, with empty buckets filled in. Mirrors QueryTimeSeries but reads the
// pre-aggregated table instead of scanning query_log.
func (s *Store) RollupTimeSeries(sinceMs int64, stepSec int, nodes []string) ([]SeriesPoint, error) {
	if stepSec <= 0 {
		stepSec = 3600
	}
	step := int64(stepSec)
	nf, nargs := nodeFilterSQL(nodes)
	rows, err := s.read.Query(
		`SELECT ((bucket*60)/?)*? AS b, action, SUM(cnt), SUM(lat_sum)
		 FROM query_rollup WHERE bucket >= ?`+nf+` GROUP BY b, action`,
		append([]any{step, step, sinceMs / 60000}, nargs...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64]*SeriesPoint{}
	elapsed := map[int64]float64{}
	for rows.Next() {
		var bucket, count int64
		var sumElapsed float64
		var action string
		if err := rows.Scan(&bucket, &action, &count, &sumElapsed); err != nil {
			return nil, err
		}
		p := m[bucket]
		if p == nil {
			p = &SeriesPoint{TS: bucket}
			m[bucket] = p
		}
		p.Total += count
		elapsed[bucket] += sumElapsed
		switch action {
		case "blocked":
			p.Blocked += count
		case "forward":
			p.Forwarded += count
		case "cache":
			p.Cached += count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for b, p := range m {
		if p.Total > 0 {
			p.AvgLatencyMS = elapsed[b] / float64(p.Total)
		}
	}
	start := (sinceMs / 1000 / step) * step
	// End at the last COMPLETE bucket. The current in-progress bucket only holds
	// partial data (and may not be rolled up yet), so including it makes the newest
	// point dip toward zero every time a bucket rolls over. Cutting it keeps the
	// line continuous — the same way dashboards drop the current incomplete interval.
	end := (time.Now().Unix()/step)*step - step
	if end < start {
		end = start
	}
	out := make([]SeriesPoint, 0, (end-start)/step+1)
	for b := start; b <= end; b += step {
		if p := m[b]; p != nil {
			out = append(out, *p)
		} else {
			out = append(out, SeriesPoint{TS: b})
		}
	}
	return out, nil
}

// RollupLatency returns mean latency per bucket (overall + per node) from the
// rollup. Mirrors LatencyTimeSeries.
func (s *Store) RollupLatency(sinceMs int64, stepSec int, nodes []string) ([]LatencyPoint, []string, error) {
	if stepSec <= 0 {
		stepSec = 3600
	}
	step := int64(stepSec)
	nf, nargs := nodeFilterSQL(nodes)
	rows, err := s.read.Query(
		`SELECT ((bucket*60)/?)*? AS b, CASE WHEN node='' THEN 'master' ELSE node END AS n,
		        SUM(cnt), SUM(lat_sum)
		 FROM query_rollup WHERE bucket >= ?`+nf+` GROUP BY b, n`,
		append([]any{step, step, sinceMs / 60000}, nargs...)...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	type agg struct {
		cnt int64
		sum float64
	}
	byBucket := map[int64]map[string]*agg{}
	overall := map[int64]*agg{}
	nodeSet := map[string]struct{}{}
	for rows.Next() {
		var bucket, cnt int64
		var n string
		var sum float64
		if err := rows.Scan(&bucket, &n, &cnt, &sum); err != nil {
			return nil, nil, err
		}
		nodeSet[n] = struct{}{}
		if byBucket[bucket] == nil {
			byBucket[bucket] = map[string]*agg{}
		}
		byBucket[bucket][n] = &agg{cnt, sum}
		o := overall[bucket]
		if o == nil {
			o = &agg{}
			overall[bucket] = o
		}
		o.cnt += cnt
		o.sum += sum
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(nodeSet))
	for n := range nodeSet {
		names = append(names, n)
	}
	sort.Strings(names)

	start := (sinceMs / 1000 / step) * step
	// End at the last COMPLETE bucket (see RollupTimeSeries): the in-progress bucket
	// would otherwise pull the newest latency point toward zero each rollover.
	end := (time.Now().Unix()/step)*step - step
	if end < start {
		end = start
	}
	out := make([]LatencyPoint, 0, (end-start)/step+1)
	for b := start; b <= end; b += step {
		p := LatencyPoint{TS: b, ByNode: map[string]float64{}}
		if o := overall[b]; o != nil && o.cnt > 0 {
			p.Overall = o.sum / float64(o.cnt)
		}
		for n, a := range byBucket[b] {
			if a.cnt > 0 {
				p.ByNode[n] = a.sum / float64(a.cnt)
			}
		}
		out = append(out, p)
	}
	return out, names, nil
}

// RollupSummary returns the windowed totals, unique-client count, and mean latency
// from the rollups in two small reads. Mirrors WindowSummary.
func (s *Store) RollupSummary(sinceMs int64, nodes []string) (WindowSummary, error) {
	nf, nargs := nodeFilterSQL(nodes)
	var ws WindowSummary
	rows, err := s.read.Query(
		`SELECT action, SUM(cnt), SUM(lat_sum) FROM query_rollup WHERE bucket >= ?`+nf+` GROUP BY action`,
		append([]any{sinceMs / 60000}, nargs...)...)
	if err != nil {
		return ws, err
	}
	defer rows.Close()
	var latSum float64
	for rows.Next() {
		var action string
		var cnt int64
		var ls float64
		if err := rows.Scan(&action, &cnt, &ls); err != nil {
			return ws, err
		}
		ws.Totals.Total += cnt
		latSum += ls
		switch action {
		case "blocked":
			ws.Totals.Blocked += cnt
		case "cache":
			ws.Totals.Cached += cnt
		case "forward":
			ws.Totals.Forwarded += cnt
		case "rewrite":
			ws.Totals.Rewritten += cnt
		case "error":
			ws.Totals.Errors += cnt
		}
	}
	if err := rows.Err(); err != nil {
		return ws, err
	}
	if ws.Totals.Total > 0 {
		ws.AvgLatencyMS = latSum / float64(ws.Totals.Total)
	}
	// Unique clients (hour granularity from client_rollup).
	if err := s.read.QueryRow(
		`SELECT COUNT(DISTINCT client) FROM client_rollup WHERE hour >= ?`+nf,
		append([]any{sinceMs / 3600000}, nargs...)...).Scan(&ws.UniqueClients); err != nil {
		return ws, err
	}
	return ws, nil
}

// RollupByNode returns total/blocked per node from the rollup. Mirrors QueriesByNode.
func (s *Store) RollupByNode(sinceMs int64, nodes []string) ([]NodeQueryCount, error) {
	nf, nargs := nodeFilterSQL(nodes)
	rows, err := s.read.Query(
		`SELECT CASE WHEN node='' THEN 'master' ELSE node END AS n,
		        SUM(cnt), SUM(CASE WHEN action='blocked' THEN cnt ELSE 0 END)
		 FROM query_rollup WHERE bucket >= ?`+nf+` GROUP BY n ORDER BY SUM(cnt) DESC`,
		append([]any{sinceMs / 60000}, nargs...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeQueryCount
	for rows.Next() {
		var c NodeQueryCount
		if err := rows.Scan(&c.Node, &c.Total, &c.Blocked); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RollupTopClients returns the top clients by volume from the client_rollup.
// Mirrors QueriesByClient.
func (s *Store) RollupTopClients(sinceMs int64, limit int, nodes []string) ([]ClientStat, error) {
	if limit <= 0 {
		limit = 10
	}
	nf, nargs := nodeFilterSQL(nodes)
	args := append([]any{sinceMs / 3600000}, nargs...)
	args = append(args, limit)
	rows, err := s.read.Query(
		`SELECT client, SUM(cnt) AS total, SUM(blocked)
		 FROM client_rollup WHERE hour >= ?`+nf+`
		 GROUP BY client ORDER BY total DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientStat
	for rows.Next() {
		var c ClientStat
		if err := rows.Scan(&c.Client, &c.Total, &c.Blocked); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
