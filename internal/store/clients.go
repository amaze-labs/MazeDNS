package store

// Per-client query-log aggregations powering the Clients tab. The master's
// query_log is already cluster-wide (workers ship their entries via
// InsertNodeQueryLog), so these need no cluster merge — just an optional node
// filter, like the dashboard insights in stats.go.

// ClientRow is one row of the client list: query volume, how much was blocked,
// and when the client was last seen.
type ClientRow struct {
	Client   string `json:"client"`
	Total    int64  `json:"total"`
	Blocked  int64  `json:"blocked"`
	LastSeen int64  `json:"last_seen"` // unix millis
}

// ClientList returns the top clients by query volume since sinceMs (with the
// optional node filter), newest activity first as a tie-break is not needed
// since we order by volume.
func (s *Store) ClientList(sinceMs int64, limit int, nodes []string) ([]ClientRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	nf, nargs := nodeFilterSQL(nodes)
	args := append([]any{sinceMs}, nargs...)
	args = append(args, limit)
	rows, err := s.db.Query(
		`SELECT client,
		        COUNT(*) AS total,
		        SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked,
		        MAX(ts) AS last_seen
		 FROM query_log WHERE ts >= ? AND client <> ''`+nf+`
		 GROUP BY client ORDER BY total DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientRow{}
	for rows.Next() {
		var c ClientRow
		if err := rows.Scan(&c.Client, &c.Total, &c.Blocked, &c.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClientDetail is the per-client breakdown shown in the inspect modal.
type ClientDetail struct {
	Totals        WindowTotals    `json:"totals"`
	UniqueDomains int64           `json:"unique_domains"`
	LastSeen      int64           `json:"last_seen"`
	AvgLatencyMS  float64         `json:"avg_latency_ms"`
	Actions       []CategoryCount `json:"actions"`    // all traffic, grouped by action (for the donut)
	Categories    []CategoryCount `json:"categories"` // blocked traffic, grouped by block category (for the bar)
	TopDomains    []DomainStat    `json:"top_domains"`
	TopBlocked    []DomainStat    `json:"top_blocked"`
}

// ClientDetailStats gathers every per-client breakdown for one client since
// sinceMs (with the optional node filter). Slices are never nil.
func (s *Store) ClientDetailStats(client string, sinceMs int64, nodes []string) (ClientDetail, error) {
	d := ClientDetail{Actions: []CategoryCount{}, Categories: []CategoryCount{}, TopDomains: []DomainStat{}, TopBlocked: []DomainStat{}}
	nf, nargs := nodeFilterSQL(nodes)
	// Base args shared by every query: ts lower-bound, the node filter, the client.
	base := func() []any {
		a := append([]any{sinceMs}, nargs...)
		return append(a, client)
	}
	where := ` FROM query_log WHERE ts >= ?` + nf + ` AND client = ?`

	// Per-action totals + unique domains + avg latency + last seen, in one pass.
	err := s.db.QueryRow(
		`SELECT
		   COUNT(*),
		   COALESCE(SUM(action='blocked'), 0),
		   COALESCE(SUM(action='cache'), 0),
		   COALESCE(SUM(action='forward'), 0),
		   COALESCE(SUM(action='rewrite'), 0),
		   COALESCE(SUM(action='error'), 0),
		   COUNT(DISTINCT name),
		   COALESCE(AVG(elapsed_ms), 0),
		   COALESCE(MAX(ts), 0)`+where,
		base()...,
	).Scan(&d.Totals.Total, &d.Totals.Blocked, &d.Totals.Cached, &d.Totals.Forwarded,
		&d.Totals.Rewritten, &d.Totals.Errors, &d.UniqueDomains, &d.AvgLatencyMS, &d.LastSeen)
	if err != nil {
		return d, err
	}

	// Action breakdown (all traffic) for the donut.
	if d.Actions, err = scanCategoryCounts(s, `SELECT action, COUNT(*)`+where+` GROUP BY action ORDER BY COUNT(*) DESC`, base()); err != nil {
		return d, err
	}
	// Blocked-by-category for the bar (mirrors BlockedByCategory's empty->custom).
	catArgs := base()
	if d.Categories, err = scanCategoryCounts(s,
		`SELECT CASE WHEN category='' THEN 'custom' ELSE category END AS cat, COUNT(*)`+where+
			` AND action='blocked' GROUP BY cat ORDER BY COUNT(*) DESC`, catArgs); err != nil {
		return d, err
	}
	// Top queried + top blocked domains.
	if d.TopDomains, err = scanDomainStats(s, `SELECT name, COUNT(*) c`+where+` GROUP BY name ORDER BY c DESC LIMIT 10`, base()); err != nil {
		return d, err
	}
	if d.TopBlocked, err = scanDomainStats(s, `SELECT name, COUNT(*) c`+where+` AND action='blocked' GROUP BY name ORDER BY c DESC LIMIT 10`, base()); err != nil {
		return d, err
	}
	return d, nil
}

// scanCategoryCounts runs a "label, count" query into []CategoryCount.
func scanCategoryCounts(s *Store, query string, args []any) ([]CategoryCount, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CategoryCount{}
	for rows.Next() {
		var c CategoryCount
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// scanDomainStats runs a "name, count" query into []DomainStat.
func scanDomainStats(s *Store, query string, args []any) ([]DomainStat, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DomainStat{}
	for rows.Next() {
		var d DomainStat
		if err := rows.Scan(&d.Name, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
