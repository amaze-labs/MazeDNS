package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Classification is an AI verdict for a registered domain.
type Classification struct {
	Domain     string          `json:"domain"`
	Category   string          `json:"category"` // ads|trackers|malware|phishing|clean|other
	Block      bool            `json:"block"`
	Status     string          `json:"status"` // suggested|approved|rejected|auto|clean
	Confidence float64         `json:"confidence"`
	Score      int             `json:"score"`             // legitimacy 0–100 (100 = fully legit; low = risky)
	Factors    json.RawMessage `json:"factors,omitempty"` // the score breakdown ([]classifier.Factor as JSON)
	Reason     string          `json:"reason"`
	Model      string          `json:"model"`
	Trusted    bool            `json:"trusted"` // on the trusted list — not blocked
	Threat     bool            `json:"threat"`  // corroborated by a threat-intel list
	UpdatedAt  int64           `json:"updated_at"`
}

// DomainClient is one client that queried a (typically flagged) domain, with how
// often and when it was last seen — so an operator can see who's affected.
type DomainClient struct {
	Client   string `json:"client"`
	Name     string `json:"name"`   // enriched display name (Netbird peer / reverse-DNS), filled by the API
	Source   string `json:"source"` // where Name came from ("netbird" | "rdns" | "")
	Count    int64  `json:"count"`
	Blocked  int64  `json:"blocked"`
	LastSeen int64  `json:"last_seen"`
}

// Enforced classification statuses block at the resolver; the rest are
// informational or pending a human decision.
const (
	ClassApproved  = "approved"  // user approved a suggestion
	ClassRejected  = "rejected"  // user rejected — never block
	ClassAuto      = "auto"      // auto-block mode applied the verdict
	ClassSuggested = "suggested" // model says block, awaiting approval
	ClassClean     = "clean"     // model says not malicious
)

// GetMeta reads a text app-setting (empty string if unset).
func (s *Store) GetMeta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM app_meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetMeta writes a text app-setting.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO app_meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// IsClassified reports whether a domain already has a verdict (so the worker
// classifies each registered domain at most once).
func (s *Store) IsClassified(domain string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM classifications WHERE domain = ?`, domain).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// InsertClassification stores a new verdict, leaving any existing row (and its
// human decision) untouched. Returns whether a row was inserted.
func (s *Store) InsertClassification(c Classification) (bool, error) {
	factors := string(c.Factors)
	if factors == "" {
		factors = "[]"
	}
	res, err := s.db.Exec(
		`INSERT INTO classifications(domain, category, block, status, confidence, score, factors, reason, model, trusted, threat, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(domain) DO NOTHING`,
		c.Domain, c.Category, boolToInt(c.Block), c.Status, c.Confidence, c.Score, factors, c.Reason, c.Model, boolToInt(c.Trusted), boolToInt(c.Threat), time.Now().UnixMilli())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetClassificationStatus updates a verdict's status (approve/reject from the UI).
func (s *Store) SetClassificationStatus(domain, status string) error {
	_, err := s.db.Exec(
		`UPDATE classifications SET status = ?, updated_at = ? WHERE domain = ?`,
		status, time.Now().UnixMilli(), domain)
	return err
}

// DeleteClassification removes a verdict entirely, so the domain can be
// re-classified the next time it's seen ("dismiss once").
func (s *Store) DeleteClassification(domain string) error {
	_, err := s.db.Exec(`DELETE FROM classifications WHERE domain = ?`, domain)
	return err
}

// DeleteAllClassifications wipes every AI verdict (a clean-slate reset). Returns
// the number removed.
func (s *Store) DeleteAllClassifications() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM classifications`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListClassifications returns a page of verdicts, optionally filtered by status,
// newest first.
func (s *Store) ListClassifications(status string, limit, offset int) ([]Classification, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT domain, category, block, status, confidence, score, factors, reason, model, trusted, threat, updated_at
	      FROM classifications`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY updated_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Classification
	for rows.Next() {
		var c Classification
		var block, trusted, threat int
		var factors string
		if err := rows.Scan(&c.Domain, &c.Category, &block, &c.Status, &c.Confidence, &c.Score, &factors, &c.Reason, &c.Model, &trusted, &threat, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Block = block != 0
		c.Trusted = trusted != 0
		c.Threat = threat != 0
		if factors != "" {
			c.Factors = json.RawMessage(factors)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClientsForDomain returns the clients that queried a registered domain (or any
// of its subdomains), most active first — so an operator can see who is reaching
// a flagged domain. Names carry a trailing dot in the log, so match both forms.
func (s *Store) ClientsForDomain(domain string, limit int) ([]DomainClient, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT client, COUNT(*) c, SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END), MAX(ts)
		 FROM query_log
		 WHERE name = ? OR name = ? OR name LIKE ? OR name LIKE ?
		 GROUP BY client ORDER BY c DESC LIMIT ?`,
		domain, domain+".", "%."+domain, "%."+domain+".", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainClient
	for rows.Next() {
		var dc DomainClient
		var blocked sql.NullInt64
		if err := rows.Scan(&dc.Client, &dc.Count, &blocked, &dc.LastSeen); err != nil {
			return nil, err
		}
		dc.Blocked = blocked.Int64
		out = append(out, dc)
	}
	return out, rows.Err()
}

// ActiveAIBlocked returns the domains whose verdict is currently enforced
// (auto-blocked or user-approved). Used when building the resolver policy.
func (s *Store) ActiveAIBlocked() ([]Classification, error) {
	rows, err := s.db.Query(
		`SELECT domain, category FROM classifications
		 WHERE block = 1 AND status IN ('approved', 'auto')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Classification
	for rows.Next() {
		var c Classification
		if err := rows.Scan(&c.Domain, &c.Category); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClassificationCounts returns the number of verdicts per status.
func (s *Store) ClassificationCounts() (map[string]int, error) {
	return s.countClassificationsBy("status")
}

// ClassificationCategoryCounts returns the number of verdicts per category, for
// the traffic-by-category breakdown (social, streaming, ads, …).
func (s *Store) ClassificationCategoryCounts() (map[string]int, error) {
	return s.countClassificationsBy("category")
}

func (s *Store) countClassificationsBy(column string) (map[string]int, error) {
	// column is a fixed identifier (never user input), so it's safe to interpolate.
	rows, err := s.db.Query(`SELECT ` + column + `, COUNT(*) FROM classifications GROUP BY ` + column)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// ClassificationCategoryMap returns registered-domain -> category for every
// verdict, so query volume can be folded into categories.
func (s *Store) ClassificationCategoryMap() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT domain, category FROM classifications`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var d, c string
		if err := rows.Scan(&d, &c); err != nil {
			return nil, err
		}
		out[d] = c
	}
	return out, rows.Err()
}

// NameCount is a per-name query count.
type NameCount struct {
	Name  string
	Count int64
}

// TopQueryNames returns the most-queried names since sinceMs (grouped by name),
// for folding query volume into categories. limited to the top `limit`.
func (s *Store) TopQueryNames(sinceMs int64, nodes []string, limit int) ([]NameCount, error) {
	if limit <= 0 || limit > 50000 {
		limit = 10000
	}
	nf, nargs := nodeFilterSQL(nodes)
	args := append([]any{sinceMs}, nargs...)
	args = append(args, limit)
	rows, err := s.db.Query(
		`SELECT name, COUNT(*) c FROM query_log WHERE ts >= ?`+nf+`
		 GROUP BY name ORDER BY c DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NameCount
	for rows.Next() {
		var n NameCount
		if err := rows.Scan(&n.Name, &n.Count); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
