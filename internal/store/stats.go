package store

import (
	"database/sql"
	"sort"
	"strings"
	"time"
)

// nodeFilterSQL builds an " AND node IN (?,...)" clause for the given nodes
// (empty = no filter). The master's entries are stored with node="", so pass ""
// to select the master.
func nodeFilterSQL(nodes []string) (string, []any) {
	if len(nodes) == 0 {
		return "", nil
	}
	ph := make([]string, len(nodes))
	args := make([]any, len(nodes))
	for i, n := range nodes {
		ph[i] = "?"
		args[i] = n
	}
	return " AND node IN (" + strings.Join(ph, ",") + ")", args
}

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

// NodeQueryCount is a per-node query/blocked count (for the cluster distribution).
type NodeQueryCount struct {
	Node    string `json:"node"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
}

// SeriesPoint is a time bucket with per-action query counts and mean latency.
type SeriesPoint struct {
	TS           int64   `json:"ts"` // bucket start, unix seconds
	Total        int64   `json:"total"`
	Blocked      int64   `json:"blocked"`
	Forwarded    int64   `json:"forwarded"`
	Cached       int64   `json:"cached"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
}

// Insights bundles the windowed dashboard breakdowns so they can be computed on
// any node and merged cluster-wide.
type Insights struct {
	UniqueClients int64        `json:"unique_clients"`
	AvgLatencyMS  float64      `json:"avg_latency_ms"`
	Clients       []ClientStat `json:"clients"`
	TopQueried    []DomainStat `json:"top_queried"`
	TopBlocked    []DomainStat `json:"top_blocked"`
	QTypes        []TypeStat   `json:"qtypes"`
}

// ComputeInsights gathers all windowed breakdowns since sinceMs (top `limit`
// clients/domains). Slices are never nil.
func (s *Store) ComputeInsights(sinceMs int64, limit int, nodes []string) (Insights, error) {
	var in Insights
	var err error
	if in.Clients, err = s.QueriesByClient(sinceMs, limit, nodes); err != nil {
		return in, err
	}
	if in.TopQueried, err = s.TopDomains(sinceMs, limit, false, nodes); err != nil {
		return in, err
	}
	if in.TopBlocked, err = s.TopDomains(sinceMs, limit, true, nodes); err != nil {
		return in, err
	}
	if in.QTypes, err = s.QueryTypeBreakdown(sinceMs, nodes); err != nil {
		return in, err
	}
	if in.UniqueClients, err = s.ClientCount(sinceMs, nodes); err != nil {
		return in, err
	}
	if in.AvgLatencyMS, err = s.AvgLatencyMS(sinceMs, nodes); err != nil {
		return in, err
	}
	if in.Clients == nil {
		in.Clients = []ClientStat{}
	}
	if in.TopQueried == nil {
		in.TopQueried = []DomainStat{}
	}
	if in.TopBlocked == nil {
		in.TopBlocked = []DomainStat{}
	}
	if in.QTypes == nil {
		in.QTypes = []TypeStat{}
	}
	return in, nil
}

// CategoryCount is a blocked-query count for a category.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// QueryTimeSeries returns per-bucket query counts (bucket size = stepSec) from
// sinceMs (unix millis) to now, with empty buckets filled in so the series is
// continuous.
func (s *Store) QueryTimeSeries(sinceMs int64, stepSec int, nodes []string) ([]SeriesPoint, error) {
	if stepSec <= 0 {
		stepSec = 3600
	}
	step := int64(stepSec)
	nf, nargs := nodeFilterSQL(nodes)
	rows, err := s.db.Query(
		`SELECT (ts/1000/?)*? AS bucket, action, COUNT(*), COALESCE(SUM(elapsed_ms),0)
		 FROM query_log WHERE ts >= ?`+nf+` GROUP BY bucket, action`,
		append([]any{step, step, sinceMs}, nargs...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64]*SeriesPoint{}
	elapsed := map[int64]float64{} // bucket -> summed latency, for the mean
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

// LatencyPoint is mean latency (ms) in a time bucket: overall plus per node.
type LatencyPoint struct {
	TS      int64              `json:"ts"`
	Overall float64            `json:"overall"`
	ByNode  map[string]float64 `json:"by_node"`
}

// LatencyTimeSeries returns mean latency per bucket, both overall and split by
// node ("" => "master"), honouring the node filter. The second return is the
// sorted set of node names that appear, for the caller to draw a line each.
func (s *Store) LatencyTimeSeries(sinceMs int64, stepSec int, nodes []string) ([]LatencyPoint, []string, error) {
	if stepSec <= 0 {
		stepSec = 3600
	}
	step := int64(stepSec)
	nf, nargs := nodeFilterSQL(nodes)
	rows, err := s.db.Query(
		`SELECT (ts/1000/?)*? AS bucket, CASE WHEN node='' THEN 'master' ELSE node END AS n,
		        COUNT(*), COALESCE(SUM(elapsed_ms),0)
		 FROM query_log WHERE ts >= ?`+nf+` GROUP BY bucket, n`,
		append([]any{step, step, sinceMs}, nargs...)...)
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
	end := (time.Now().Unix() / step) * step
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

// BlockedByCategory returns blocked-query counts grouped by category since sinceMs.
func (s *Store) BlockedByCategory(sinceMs int64, nodes []string) ([]CategoryCount, error) {
	nf, nargs := nodeFilterSQL(nodes)
	rows, err := s.db.Query(
		`SELECT CASE WHEN category='' THEN 'custom' ELSE category END AS cat, COUNT(*)
		 FROM query_log WHERE action='blocked' AND ts >= ?`+nf+` GROUP BY cat ORDER BY COUNT(*) DESC`,
		append([]any{sinceMs}, nargs...)...)
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
func (s *Store) QueriesByClient(sinceMs int64, limit int, nodes []string) ([]ClientStat, error) {
	if limit <= 0 {
		limit = 10
	}
	nf, nargs := nodeFilterSQL(nodes)
	args := append([]any{sinceMs}, nargs...)
	args = append(args, limit)
	rows, err := s.db.Query(
		`SELECT client,
		        COUNT(*) AS total,
		        SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked
		 FROM query_log WHERE ts >= ? AND client <> ''`+nf+`
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

// TopDomains returns the most-queried names since sinceMs; blockedOnly limits
// the result to blocked queries.
func (s *Store) TopDomains(sinceMs int64, limit int, blockedOnly bool, nodes []string) ([]DomainStat, error) {
	if limit <= 0 {
		limit = 10
	}
	nf, nargs := nodeFilterSQL(nodes)
	q := `SELECT name, COUNT(*) c FROM query_log WHERE ts >= ?`
	if blockedOnly {
		q += ` AND action='blocked'`
	}
	q += nf + ` GROUP BY name ORDER BY c DESC LIMIT ?`
	args := append([]any{sinceMs}, nargs...)
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
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
func (s *Store) QueryTypeBreakdown(sinceMs int64, nodes []string) ([]TypeStat, error) {
	nf, nargs := nodeFilterSQL(nodes)
	rows, err := s.db.Query(
		`SELECT qtype, COUNT(*) c FROM query_log WHERE ts >= ?`+nf+` GROUP BY qtype ORDER BY c DESC`,
		append([]any{sinceMs}, nargs...)...)
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

// QueriesByNode returns per-node query and blocked counts since sinceMs from the
// unified log ("" node is reported as "master").
func (s *Store) QueriesByNode(sinceMs int64, nodes []string) ([]NodeQueryCount, error) {
	nf, nargs := nodeFilterSQL(nodes)
	rows, err := s.db.Query(
		`SELECT CASE WHEN node='' THEN 'master' ELSE node END AS n,
		        COUNT(*),
		        SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END)
		 FROM query_log WHERE ts >= ?`+nf+` GROUP BY n ORDER BY COUNT(*) DESC`,
		append([]any{sinceMs}, nargs...)...)
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

// ClientCount returns the number of distinct clients seen since sinceMs.
func (s *Store) ClientCount(sinceMs int64, nodes []string) (int64, error) {
	nf, nargs := nodeFilterSQL(nodes)
	var n int64
	err := s.db.QueryRow(
		`SELECT COUNT(DISTINCT client) FROM query_log WHERE ts >= ? AND client <> ''`+nf,
		append([]any{sinceMs}, nargs...)...).Scan(&n)
	return n, err
}

// AvgLatencyMS returns the mean query latency (ms) since sinceMs (0 if no rows).
func (s *Store) AvgLatencyMS(sinceMs int64, nodes []string) (float64, error) {
	nf, nargs := nodeFilterSQL(nodes)
	var v sql.NullFloat64
	if err := s.db.QueryRow(
		`SELECT AVG(elapsed_ms) FROM query_log WHERE ts >= ?`+nf,
		append([]any{sinceMs}, nargs...)...).Scan(&v); err != nil {
		return 0, err
	}
	return v.Float64, nil
}
