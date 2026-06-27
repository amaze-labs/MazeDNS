package store

import (
	"database/sql"
	"errors"
	"time"
)

// Classification is an AI verdict for a registered domain.
type Classification struct {
	Domain     string  `json:"domain"`
	Category   string  `json:"category"` // ads|trackers|malware|phishing|clean|other
	Block      bool    `json:"block"`
	Status     string  `json:"status"` // suggested|approved|rejected|auto|clean
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Model      string  `json:"model"`
	Trusted    bool    `json:"trusted"` // on the trusted list — flagged for review, not auto-blocked
	UpdatedAt  int64   `json:"updated_at"`
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
	res, err := s.db.Exec(
		`INSERT INTO classifications(domain, category, block, status, confidence, reason, model, trusted, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(domain) DO NOTHING`,
		c.Domain, c.Category, boolToInt(c.Block), c.Status, c.Confidence, c.Reason, c.Model, boolToInt(c.Trusted), time.Now().UnixMilli())
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

// ListClassifications returns verdicts, optionally filtered by status, newest
// first.
func (s *Store) ListClassifications(status string, limit int) ([]Classification, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT domain, category, block, status, confidence, reason, model, trusted, updated_at
	      FROM classifications`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Classification
	for rows.Next() {
		var c Classification
		var block, trusted int
		if err := rows.Scan(&c.Domain, &c.Category, &block, &c.Status, &c.Confidence, &c.Reason, &c.Model, &trusted, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Block = block != 0
		c.Trusted = trusted != 0
		out = append(out, c)
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

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
