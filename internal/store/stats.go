package store

import "time"

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
