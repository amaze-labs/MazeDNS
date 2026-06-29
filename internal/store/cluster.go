package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReplicatedRules returns the deny/allow rules workers should enforce: the
// active rules plus enforced AI verdicts (auto-blocked or user-approved) as
// synthetic "deny" rules tagged with the model's category. This is what makes AI
// auto-blocks apply on worker nodes too — they arrive through the normal
// rule-replication path.
func (s *Store) ReplicatedRules() ([]Rule, error) {
	rules, err := s.ActiveRules()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if r.Action == "deny" {
			seen[r.Domain] = true
		}
	}
	ai, err := s.ActiveAIBlocked()
	if err != nil {
		return nil, err
	}
	for _, c := range ai {
		if seen[c.Domain] {
			continue // already a deny rule — avoid a duplicate (action,domain)
		}
		seen[c.Domain] = true
		// Tag with the model's own category so worker query logs attribute the block
		// to the real category (ads/malware/…) rather than a generic "ai" bucket.
		cat := c.Category
		if cat == "" {
			cat = "ai"
		}
		rules = append(rules, Rule{Action: "deny", Domain: c.Domain, Category: cat, Enabled: true})
	}
	return rules, nil
}

// ConfigVersion returns a short content hash of the replicated config (rules +
// rewrites). It changes only when that content changes and is identical on any
// node holding the same config, so a worker detects drift by comparing its own
// hash to the master's — no monotonic counter needed.
func (s *Store) ConfigVersion() (string, error) {
	rules, err := s.ReplicatedRules()
	if err != nil {
		return "", err
	}
	rewrites, err := s.ListRewrites()
	if err != nil {
		return "", err
	}
	lines := make([]string, 0, len(rules)+len(rewrites))
	for _, r := range rules {
		lines = append(lines, fmt.Sprintf("R|%s|%s|%s|%t", r.Action, r.Domain, r.Category, r.Enabled))
	}
	for _, rw := range rewrites {
		lines = append(lines, fmt.Sprintf("W|%s|%s|%s|%t", rw.Domain, rw.RRType, rw.Value, rw.Enabled))
	}
	sort.Strings(lines) // order-independent: same content -> same hash on every node
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])[:12], nil
}

// ApplySnapshot replaces all rules and rewrites with the given set. Used by
// worker nodes during replication.
func (s *Store) ApplySnapshot(rules []Rule, rewrites []Rewrite) error {
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
	return tx.Commit()
}

// NodeStats is a worker's query counters, reported to the master on each poll.
type NodeStats struct {
	Total     int64 `json:"total"`
	Blocked   int64 `json:"blocked"`
	Cached    int64 `json:"cached"`
	Forwarded int64 `json:"forwarded"`
	Rewritten int64 `json:"rewritten"`
	Errors    int64 `json:"errors"`
}

// Node is a cluster worker enrolled on the master. The API key itself is never
// stored — only its hash (for auth) and a short prefix (for display).
type Node struct {
	Name        string `json:"name"`
	KeyPrefix   string `json:"key_prefix"`
	Address     string `json:"address"`
	Version     string `json:"version"` // short content hash the node last reported
	LastSeen    int64  `json:"last_seen"`
	CreatedAt   int64  `json:"created_at"`
	IsMaster    bool   `json:"is_master"`   // the master node (always online; no key to renew)
	Maintenance bool   `json:"maintenance"` // drained: this node answers SERVFAIL
	NodeStats
}

// masterMaintenanceKey holds the master's own drain flag (the master isn't a row
// in the nodes table — it's synthesized in the API), as 0/1 in app_meta.
const masterMaintenanceKey = "master_maintenance"

// MasterMaintenance reports whether the master is drained (answering SERVFAIL).
func (s *Store) MasterMaintenance() bool {
	v, _ := s.GetMetaInt(masterMaintenanceKey)
	return v != 0
}

// SetMasterMaintenance persists the master's drain flag.
func (s *Store) SetMasterMaintenance(on bool) error {
	return s.SetMetaInt(masterMaintenanceKey, int64(boolToInt(on)))
}

// SetNodeMaintenance toggles a worker node's drain (maintenance) flag. The worker
// picks it up on its next config poll and starts/stops answering SERVFAIL.
func (s *Store) SetNodeMaintenance(name string, on bool) error {
	res, err := s.db.Exec(`UPDATE nodes SET maintenance=? WHERE name=?`, boolToInt(on), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("node not found")
	}
	return nil
}

// UpdateNodeKey rotates an enrolled node's API key (hash + display prefix).
func (s *Store) UpdateNodeKey(name, keyHash, keyPrefix string) error {
	res, err := s.db.Exec(`UPDATE nodes SET key_hash=?, key_prefix=? WHERE name=?`, keyHash, keyPrefix, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("node not found")
	}
	return nil
}

// CreateNode enrolls a new node with the given API key hash and display prefix.
func (s *Store) CreateNode(name, keyHash, keyPrefix string) error {
	_, err := s.db.Exec(
		`INSERT INTO nodes(name, key_hash, key_prefix, address, version, last_seen, created_at)
		 VALUES(?,?,?,'','',0,?)`,
		name, keyHash, keyPrefix, time.Now().Unix())
	return err
}

// EnsureNode creates a node or, if the name already exists, updates its key.
// Used to pre-provision nodes from configuration (the key is authoritative);
// existing stats are preserved. Idempotent across restarts.
func (s *Store) EnsureNode(name, keyHash, keyPrefix string) error {
	_, err := s.db.Exec(
		`INSERT INTO nodes(name, key_hash, key_prefix, address, version, last_seen, created_at)
		 VALUES(?,?,?,'','',0,?)
		 ON CONFLICT(name) DO UPDATE SET key_hash=excluded.key_hash, key_prefix=excluded.key_prefix`,
		name, keyHash, keyPrefix, time.Now().Unix())
	return err
}

// NodeByKeyHash returns the node whose key hash matches, or (nil, nil) if none.
func (s *Store) NodeByKeyHash(keyHash string) (*Node, error) {
	if keyHash == "" {
		return nil, nil
	}
	n := &Node{}
	var maintenance int
	err := s.read.QueryRow(
		`SELECT name, key_prefix, address, version, last_seen, created_at, maintenance
		 FROM nodes WHERE key_hash=?`, keyHash).
		Scan(&n.Name, &n.KeyPrefix, &n.Address, &n.Version, &n.LastSeen, &n.CreatedAt, &maintenance)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.Maintenance = maintenance != 0
	return n, nil
}

// TouchNode refreshes a node's last-seen address, config version, and stats.
func (s *Store) TouchNode(name, address, version string, st NodeStats) error {
	_, err := s.db.Exec(
		`UPDATE nodes SET address=?, version=?, last_seen=?,
		   q_total=?, q_blocked=?, q_cached=?, q_forwarded=?, q_rewritten=?, q_errors=?
		 WHERE name=?`,
		address, version, time.Now().Unix(),
		st.Total, st.Blocked, st.Cached, st.Forwarded, st.Rewritten, st.Errors, name)
	return err
}

// SetNodeInsights stores a node's latest reported insights (JSON).
func (s *Store) SetNodeInsights(name, data string) error {
	_, err := s.db.Exec(`UPDATE nodes SET insights=? WHERE name=?`, data, name)
	return err
}

// AllNodeInsights returns the latest insights reported by each node, keyed by
// node name (skipping nodes that haven't reported any).
func (s *Store) AllNodeInsights() (map[string]Insights, error) {
	rows, err := s.read.Query(`SELECT name, insights FROM nodes WHERE insights <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Insights{}
	for rows.Next() {
		var name, data string
		if err := rows.Scan(&name, &data); err != nil {
			return nil, err
		}
		var in Insights
		if json.Unmarshal([]byte(data), &in) == nil {
			out[name] = in
		}
	}
	return out, rows.Err()
}

// ListNodes returns all enrolled nodes (with their latest stats) ordered by name.
func (s *Store) ListNodes() ([]Node, error) {
	rows, err := s.read.Query(
		`SELECT name, key_prefix, address, version, last_seen, created_at,
		        q_total, q_blocked, q_cached, q_forwarded, q_rewritten, q_errors, maintenance
		 FROM nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var maintenance int
		if err := rows.Scan(&n.Name, &n.KeyPrefix, &n.Address, &n.Version, &n.LastSeen, &n.CreatedAt,
			&n.Total, &n.Blocked, &n.Cached, &n.Forwarded, &n.Rewritten, &n.Errors, &maintenance); err != nil {
			return nil, err
		}
		n.Maintenance = maintenance != 0
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteNode revokes a node (removing its key).
func (s *Store) DeleteNode(name string) error {
	_, err := s.db.Exec(`DELETE FROM nodes WHERE name=?`, name)
	return err
}
