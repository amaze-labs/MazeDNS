package store

import (
	"database/sql"
	"time"
)

// ClientStat is per-client query volume.
type ClientStat struct {
	Client  string `json:"client"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
}

// DomainStat is a per-name query count.
type DomainStat struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// TypeStat is a per-query-type count.
type TypeStat struct {
	QType string `json:"qtype"`
	Count int64  `json:"count"`
}

// SeriesPoint is a time bucket with per-action query counts.
type SeriesPoint struct {
	TS        int64 `json:"ts"` // bucket start, unix seconds
	Total     int64 `json:"total"`
	Blocked   int64 `json:"blocked"`
	Forwarded int64 `json:"forwarded"`
	Cached    int64 `json:"cached"`
}

// CategoryCount is a blocked-query count for a category.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// QueryTimeSeries returns per-bucket query counts (bucket size = stepSec) from
// sinceMs (unix millis) to now, with empty buckets filled in so the series is
// continuous.
func (s *Store) QueryTimeSeries(sinceMs int64, stepSec int) ([]SeriesPoint, error) {
	if stepSec <= 0 {
		stepSec = 3600
	}
	step := int64(stepSec)
	rows, err := s.db.Query(
		`SELECT (ts/1000/?)*? AS bucket, action, COUNT(*)
		 FROM query_log WHERE ts >= ? GROUP BY bucket, action`, step, step, sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64]*SeriesPoint{}
	for rows.Next() {
		var bucket, count int64
		var action string
		if err := rows.Scan(&bucket, &action, &count); err != nil {
			return nil, err
		}
		p := m[bucket]
		if p == nil {
			p = &SeriesPoint{TS: bucket}
			m[bucket] = p
		}
		p.Total += count
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
	start := (sinceMs / 1000 / step) * step
	end := (time.Now().Unix() / step) * step
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

// BlockedByCategory returns blocked-query counts grouped by category since sinceMs.
func (s *Store) BlockedByCategory(sinceMs int64) ([]CategoryCount, error) {
	rows, err := s.db.Query(
		`SELECT CASE WHEN category='' THEN 'custom' ELSE category END AS cat, COUNT(*)
		 FROM query_log WHERE action='blocked' AND ts >= ? GROUP BY cat ORDER BY COUNT(*) DESC`, sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CategoryCount
	for rows.Next() {
		var c CategoryCount
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// QueriesByClient returns the top clients by query volume since sinceMs, with
// how many of each client's queries were blocked.
func (s *Store) QueriesByClient(sinceMs int64, limit int) ([]ClientStat, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.Query(
		`SELECT client,
		        COUNT(*) AS total,
		        SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked
		 FROM query_log WHERE ts >= ? AND client <> ''
		 GROUP BY client ORDER BY total DESC LIMIT ?`, sinceMs, limit)
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

// TopDomains returns the most-queried names since sinceMs; blockedOnly limits
// the result to blocked queries.
func (s *Store) TopDomains(sinceMs int64, limit int, blockedOnly bool) ([]DomainStat, error) {
	if limit <= 0 {
		limit = 10
	}
	q := `SELECT name, COUNT(*) c FROM query_log WHERE ts >= ?`
	if blockedOnly {
		q += ` AND action='blocked'`
	}
	q += ` GROUP BY name ORDER BY c DESC LIMIT ?`
	rows, err := s.db.Query(q, sinceMs, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainStat
	for rows.Next() {
		var d DomainStat
		if err := rows.Scan(&d.Name, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// QueryTypeBreakdown returns query counts grouped by record type since sinceMs.
func (s *Store) QueryTypeBreakdown(sinceMs int64) ([]TypeStat, error) {
	rows, err := s.db.Query(
		`SELECT qtype, COUNT(*) c FROM query_log WHERE ts >= ? GROUP BY qtype ORDER BY c DESC`, sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TypeStat
	for rows.Next() {
		var t TypeStat
		if err := rows.Scan(&t.QType, &t.Count); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ClientCount returns the number of distinct clients seen since sinceMs.
func (s *Store) ClientCount(sinceMs int64) (int64, error) {
	var n int64
	err := s.db.QueryRow(
		`SELECT COUNT(DISTINCT client) FROM query_log WHERE ts >= ? AND client <> ''`, sinceMs).Scan(&n)
	return n, err
}

// AvgLatencyMS returns the mean query latency (ms) since sinceMs (0 if no rows).
func (s *Store) AvgLatencyMS(sinceMs int64) (float64, error) {
	var v sql.NullFloat64
	if err := s.db.QueryRow(
		`SELECT AVG(elapsed_ms) FROM query_log WHERE ts >= ?`, sinceMs).Scan(&v); err != nil {
		return 0, err
	}
	return v.Float64, nil
}
