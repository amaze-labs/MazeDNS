package store

import (
	"database/sql"
	"errors"
)

// GetConfigVersion returns the monotonic config version, bumped on each mutation.
func (s *Store) GetConfigVersion() (int64, error) {
	var v int64
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key='config_version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

// BumpConfigVersion increments the config version. Call after every mutation so
// worker nodes can detect that they need to re-sync.
func (s *Store) BumpConfigVersion() error {
	_, err := s.db.Exec(`UPDATE meta SET value = value + 1 WHERE key='config_version'`)
	return err
}

// ApplySnapshot replaces all rules and rewrites with the given set and records
// the master's config version. Used by worker nodes during replication.
func (s *Store) ApplySnapshot(version int64, rules []Rule, rewrites []Rewrite) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	exec := func(q string, args ...any) error {
		_, e := tx.Exec(q, args...)
		return e
	}
	if err := exec(`DELETE FROM rules`); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, r := range rules {
		if err := exec(`INSERT INTO rules(action, domain, enabled, updated_at) VALUES(?,?,?,?)`,
			r.Action, r.Domain, r.Enabled, r.UpdatedAt); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := exec(`DELETE FROM rewrites`); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, rw := range rewrites {
		if err := exec(`INSERT INTO rewrites(domain, rrtype, value, enabled, updated_at) VALUES(?,?,?,?,?)`,
			rw.Domain, rw.RRType, rw.Value, rw.Enabled, rw.UpdatedAt); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := exec(`UPDATE meta SET value=? WHERE key='config_version'`, version); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
