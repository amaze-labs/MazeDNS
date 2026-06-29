package store

import (
	"database/sql"
	"errors"
	"time"
)

// List is a named, managed collection of rules (imported from a file, pasted
// text, or a remote URL that can be auto-refreshed).
type List struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Source      string `json:"source"` // "file" | "paste" | "url"
	URL         string `json:"url"`
	Category    string `json:"category"`
	Enabled     bool   `json:"enabled"`
	IntervalSec int    `json:"interval_sec"` // url auto-refresh; 0 = manual
	LastFetch   int64  `json:"last_fetch"`
	LastError   string `json:"last_error"`
	RuleCount   int64  `json:"rule_count"`
	UpdatedAt   int64  `json:"updated_at"`
}

// CreateList inserts a list and returns its id.
func (s *Store) CreateList(name, source, url, category string, intervalSec int) (int64, error) {
	if category == "" {
		category = "custom"
	}
	res, err := s.db.Exec(
		`INSERT INTO lists(name, source, url, category, enabled, interval_sec, updated_at)
		 VALUES(?,?,?,?,1,?,?)`,
		name, source, url, category, intervalSec, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListLists returns all lists (with a live rule count) ordered by name.
func (s *Store) ListLists() ([]List, error) {
	rows, err := s.read.Query(
		`SELECT l.id, l.name, l.source, l.url, l.category, l.enabled, l.interval_sec,
		        l.last_fetch, l.last_error, l.updated_at,
		        (SELECT COUNT(*) FROM rules r WHERE r.list_id = l.id) AS rule_count
		 FROM lists l ORDER BY l.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []List
	for rows.Next() {
		var l List
		if err := rows.Scan(&l.ID, &l.Name, &l.Source, &l.URL, &l.Category, &l.Enabled, &l.IntervalSec,
			&l.LastFetch, &l.LastError, &l.UpdatedAt, &l.RuleCount); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// GetList returns one list, or (nil, nil) if not found.
func (s *Store) GetList(id int64) (*List, error) {
	l := &List{}
	err := s.read.QueryRow(
		`SELECT id, name, source, url, category, enabled, interval_sec, last_fetch, last_error, updated_at
		 FROM lists WHERE id=?`, id).
		Scan(&l.ID, &l.Name, &l.Source, &l.URL, &l.Category, &l.Enabled, &l.IntervalSec,
			&l.LastFetch, &l.LastError, &l.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return l, nil
}

// DueURLLists returns enabled URL lists whose refresh interval has elapsed.
func (s *Store) DueURLLists(now int64) ([]List, error) {
	rows, err := s.read.Query(
		`SELECT id, name, source, url, category, enabled, interval_sec, last_fetch, last_error, updated_at
		 FROM lists
		 WHERE source='url' AND enabled=1 AND interval_sec > 0 AND (last_fetch + interval_sec) <= ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []List
	for rows.Next() {
		var l List
		if err := rows.Scan(&l.ID, &l.Name, &l.Source, &l.URL, &l.Category, &l.Enabled, &l.IntervalSec,
			&l.LastFetch, &l.LastError, &l.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SetListEnabled toggles a list on/off.
func (s *Store) SetListEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE lists SET enabled=?, updated_at=? WHERE id=?`, enabled, time.Now().Unix(), id)
	return err
}

// UpdateListInterval changes a URL list's auto-refresh interval (seconds; 0 = manual).
func (s *Store) UpdateListInterval(id int64, intervalSec int) error {
	_, err := s.db.Exec(`UPDATE lists SET interval_sec=?, updated_at=? WHERE id=?`, intervalSec, time.Now().Unix(), id)
	return err
}

// MarkListFetched records the outcome of a (re)fetch: timestamp and any error.
func (s *Store) MarkListFetched(id int64, errMsg string) error {
	_, err := s.db.Exec(`UPDATE lists SET last_fetch=?, last_error=?, updated_at=? WHERE id=?`,
		time.Now().Unix(), errMsg, time.Now().Unix(), id)
	return err
}

// DeleteList removes a list and all of its rules.
func (s *Store) DeleteList(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM rules WHERE list_id=?`, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM lists WHERE id=?`, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ReplaceListRules replaces all rules owned by a list with the given set,
// returning the number applied. Domains already present (possibly from another
// list) are reassigned to this list.
func (s *Store) ReplaceListRules(listID int64, category string, rules []Rule) (int, error) {
	if category == "" {
		category = "custom"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM rules WHERE list_id=?`, listID); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO rules(action, domain, category, enabled, list_id, updated_at) VALUES(?,?,?,1,?,?)
		 ON CONFLICT(action, domain) DO UPDATE SET category=excluded.category, enabled=1,
		   list_id=excluded.list_id, updated_at=excluded.updated_at`)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	n := 0
	for _, r := range rules {
		if _, err := stmt.Exec(r.Action, r.Domain, category, listID, now); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// RulesByList returns the rules owned by a list, ordered by domain.
func (s *Store) RulesByList(listID int64) ([]Rule, error) {
	rows, err := s.read.Query(
		`SELECT id, action, domain, category, enabled, list_id, updated_at
		 FROM rules WHERE list_id=? ORDER BY domain`, listID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Action, &r.Domain, &r.Category, &r.Enabled, &r.ListID, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ManualRules returns rules that are not part of any list (list_id = 0).
func (s *Store) ManualRules() ([]Rule, error) {
	rows, err := s.read.Query(
		`SELECT id, action, domain, category, enabled, list_id, updated_at
		 FROM rules WHERE list_id=0 ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Action, &r.Domain, &r.Category, &r.Enabled, &r.ListID, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveRules returns the rules that should be enforced: enabled, and either
// manual (list_id=0) or belonging to an enabled list.
func (s *Store) ActiveRules() ([]Rule, error) {
	rows, err := s.read.Query(
		`SELECT r.id, r.action, r.domain, r.category, r.enabled, r.list_id, r.updated_at
		 FROM rules r LEFT JOIN lists l ON r.list_id = l.id
		 WHERE r.enabled=1 AND (r.list_id=0 OR l.enabled=1)
		 ORDER BY r.domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Action, &r.Domain, &r.Category, &r.Enabled, &r.ListID, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetMetaInt returns an integer meta value (0 if the key is absent).
func (s *Store) GetMetaInt(key string) (int64, error) {
	var v int64
	err := s.read.QueryRow(`SELECT value FROM meta WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

// SetMetaInt upserts an integer meta value.
func (s *Store) SetMetaInt(key string, v int64) error {
	_, err := s.db.Exec(
		`INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, v)
	return err
}

// GetBlockPausedUntil returns the unix time until which blocking is paused (0 = active).
func (s *Store) GetBlockPausedUntil() (int64, error) {
	var v int64
	err := s.read.QueryRow(`SELECT value FROM meta WHERE key='block_paused_until'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

// SetBlockPausedUntil persists the block-pause deadline (0 = active).
func (s *Store) SetBlockPausedUntil(ts int64) error {
	_, err := s.db.Exec(
		`INSERT INTO meta(key, value) VALUES('block_paused_until', ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, ts)
	return err
}
