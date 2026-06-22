package store

import (
	"database/sql"
	"errors"
	"time"
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
		cat := r.Category
		if cat == "" {
			cat = "custom"
		}
		if err := exec(`INSERT INTO rules(action, domain, category, enabled, updated_at) VALUES(?,?,?,?,?)`,
			r.Action, r.Domain, cat, r.Enabled, r.UpdatedAt); err != nil {
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

// Node is a cluster worker enrolled on the master. The API key itself is never
// stored — only its hash (for auth) and a short prefix (for display).
type Node struct {
	Name      string `json:"name"`
	KeyPrefix string `json:"key_prefix"`
	Address   string `json:"address"`
	Version   int64  `json:"version"`
	LastSeen  int64  `json:"last_seen"`
	CreatedAt int64  `json:"created_at"`
}

// CreateNode enrolls a new node with the given API key hash and display prefix.
func (s *Store) CreateNode(name, keyHash, keyPrefix string) error {
	_, err := s.db.Exec(
		`INSERT INTO nodes(name, key_hash, key_prefix, address, version, last_seen, created_at)
		 VALUES(?,?,?,'',0,0,?)`,
		name, keyHash, keyPrefix, time.Now().Unix())
	return err
}

// NodeByKeyHash returns the node whose key hash matches, or (nil, nil) if none.
func (s *Store) NodeByKeyHash(keyHash string) (*Node, error) {
	if keyHash == "" {
		return nil, nil
	}
	n := &Node{}
	err := s.db.QueryRow(
		`SELECT name, key_prefix, address, version, last_seen, created_at
		 FROM nodes WHERE key_hash=?`, keyHash).
		Scan(&n.Name, &n.KeyPrefix, &n.Address, &n.Version, &n.LastSeen, &n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return n, nil
}

// TouchNode refreshes a node's last-seen address and config version.
func (s *Store) TouchNode(name, address string, version int64) error {
	_, err := s.db.Exec(
		`UPDATE nodes SET address=?, version=?, last_seen=? WHERE name=?`,
		address, version, time.Now().Unix(), name)
	return err
}

// ListNodes returns all enrolled nodes ordered by name.
func (s *Store) ListNodes() ([]Node, error) {
	rows, err := s.db.Query(
		`SELECT name, key_prefix, address, version, last_seen, created_at FROM nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.Name, &n.KeyPrefix, &n.Address, &n.Version, &n.LastSeen, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteNode revokes a node (removing its key).
func (s *Store) DeleteNode(name string) error {
	_, err := s.db.Exec(`DELETE FROM nodes WHERE name=?`, name)
	return err
}
