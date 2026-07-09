package store

import (
	"encoding/json"
	"errors"
	"time"
)

// Forwarder is a centrally-managed conditional forwarder: a domain suffix
// routed to specific upstreams, scoped to all nodes, a node list, or sites.
// It lives only on the control plane; agents receive pre-filtered ForwardSpecs.
type Forwarder struct {
	ID          int64    `json:"id"`
	Suffix      string   `json:"suffix"`
	Upstreams   []string `json:"upstreams"`
	ScopeType   string   `json:"scope_type"`
	ScopeValues []string `json:"scope_values"`
	Enabled     bool     `json:"enabled"`
	UpdatedAt   int64    `json:"updated_at"`
}

// ListForwarders returns all forwarders ordered by suffix.
func (s *Store) ListForwarders() ([]Forwarder, error) {
	rows, err := s.read.Query(`SELECT id, suffix, upstreams, scope_type, scope_values, enabled, updated_at FROM forwarders ORDER BY suffix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Forwarder{}
	for rows.Next() {
		var f Forwarder
		var ups, vals string
		if err := rows.Scan(&f.ID, &f.Suffix, &ups, &f.ScopeType, &vals, &f.Enabled, &f.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(ups), &f.Upstreams)
		_ = json.Unmarshal([]byte(vals), &f.ScopeValues)
		out = append(out, f)
	}
	return out, rows.Err()
}

// AddForwarder inserts or updates a forwarder (upsert key: suffix + scope).
func (s *Store) AddForwarder(suffix string, upstreams []string, scopeType string, scopeValues []string) (int64, error) {
	st, vals, err := CanonicalScope(scopeType, scopeValues)
	if err != nil {
		return 0, err
	}
	ups, err := json.Marshal(upstreams)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec(
		`INSERT INTO forwarders(suffix, upstreams, scope_type, scope_values, enabled, updated_at) VALUES(?,?,?,?,1,?)
		 ON CONFLICT(suffix, scope_type, scope_values) DO UPDATE SET upstreams=excluded.upstreams, enabled=1, updated_at=excluded.updated_at`,
		suffix, string(ups), st, vals, now,
	); err != nil {
		return 0, err
	}
	var id int64
	err = s.read.QueryRow(`SELECT id FROM forwarders WHERE suffix=? AND scope_type=? AND scope_values=?`, suffix, st, vals).Scan(&id)
	return id, err
}

// AddForwardersBulk upserts many forwarders (config-bundle import), honoring
// each entry's enabled flag. Returns the count applied.
func (s *Store) AddForwardersBulk(fws []Forwarder) (int, error) {
	n := 0
	for _, f := range fws {
		id, err := s.AddForwarder(f.Suffix, f.Upstreams, f.ScopeType, f.ScopeValues)
		if err != nil {
			return n, err
		}
		if !f.Enabled {
			if err := s.UpdateForwarder(id, f.Upstreams, false, f.ScopeType, f.ScopeValues); err != nil {
				return n, err
			}
		}
		n++
	}
	return n, nil
}

// UpdateForwarder edits a forwarder's upstreams, enabled flag, and scope.
func (s *Store) UpdateForwarder(id int64, upstreams []string, enabled bool, scopeType string, scopeValues []string) error {
	st, vals, err := CanonicalScope(scopeType, scopeValues)
	if err != nil {
		return err
	}
	ups, err := json.Marshal(upstreams)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE forwarders SET upstreams=?, enabled=?, scope_type=?, scope_values=?, updated_at=? WHERE id=?`,
		string(ups), boolToInt(enabled), st, vals, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("forwarder not found")
	}
	return nil
}

// DeleteForwarder removes a forwarder by id.
func (s *Store) DeleteForwarder(id int64) error {
	_, err := s.db.Exec(`DELETE FROM forwarders WHERE id=?`, id)
	return err
}

// ClearForwarders removes every forwarder (used by a "replace" config import).
func (s *Store) ClearForwarders() error {
	_, err := s.db.Exec(`DELETE FROM forwarders`)
	return err
}

// ForwarderScopeConflict mirrors RewriteScopeConflict for forwarder suffixes.
func (s *Store) ForwarderScopeConflict(suffix, scopeType, valuesJSON string, excludeID int64) (bool, error) {
	if scopeType == ScopeAll {
		return false, nil
	}
	rows, err := s.read.Query(`SELECT id, scope_values FROM forwarders WHERE suffix=? AND scope_type=?`, suffix, scopeType)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var vals string
		if err := rows.Scan(&id, &vals); err != nil {
			return false, err
		}
		if id != excludeID && vals != valuesJSON && scopeValuesIntersect(vals, valuesJSON) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// clusterForwardersMeta is the app_meta key under which an AGENT persists the
// central forwarders it last received, so boot works offline and the agent's
// ConfigVersion hash covers them (drift detection).
const clusterForwardersMeta = "cluster_forwarders"

// ClusterForwarders returns the centrally-pushed forwarders persisted on this
// agent (empty on the control plane and on standalone nodes).
func (s *Store) ClusterForwarders() ([]ForwardSpec, error) {
	raw, err := s.GetMeta(clusterForwardersMeta)
	if err != nil || raw == "" {
		return nil, err
	}
	var out []ForwardSpec
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetClusterForwarders persists the centrally-pushed forwarders on this agent.
func (s *Store) SetClusterForwarders(fws []ForwardSpec) error {
	if fws == nil {
		fws = []ForwardSpec{}
	}
	b, err := json.Marshal(fws)
	if err != nil {
		return err
	}
	return s.SetMeta(clusterForwardersMeta, string(b))
}
