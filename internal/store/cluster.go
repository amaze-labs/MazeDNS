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

	"github.com/google/uuid"
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
	ID               string `json:"id"`   // immutable UUIDv4 (identity; read-only in the UI)
	Name             string `json:"name"` // mutable, unique display label
	KeyHash          string `json:"-"`    // sha256 of the API key; never serialized (used for ownership proof)
	KeyPrefix        string `json:"key_prefix"`
	KeyIssuedAt      int64  `json:"key_issued_at"` // when the current key was issued (for rotation display)
	PrevKeyHash      string `json:"-"`             // previous key accepted during the rotation grace window
	PrevKeyExpiresAt int64  `json:"-"`             // grace deadline for prev_key_hash (0 = none)
	Address          string `json:"address"`
	Version          string `json:"version"` // short content hash the node last reported
	LastSeen         int64  `json:"last_seen"`
	CreatedAt        int64  `json:"created_at"`
	IsMaster         bool   `json:"is_master"`          // the master node (always online; no key to renew)
	Maintenance      bool   `json:"maintenance"`        // drained: this node answers SERVFAIL
	ControlPlaneOnly bool   `json:"control_plane_only"` // master only: coordinates the cluster but serves no DNS (answers REFUSED)
	Site             string `json:"site"`               // site grouping ('' = unassigned)
	Role             string `json:"role"`               // '' | 'primary' | 'backup' (advisory: both serve DNS)
	Approved         bool   `json:"approved"`           // admitted to the cluster (false = pending admin approval)
	NodeStats
}

// masterMaintenanceKey holds the master's own drain flag (the master isn't a row
// in the nodes table — it's synthesized in the API), as 0/1 in app_meta.
const masterMaintenanceKey = "master_maintenance"

// masterControlPlaneOnlyKey holds the master's DNS-role flag: when set the master
// runs as a control plane only (coordinates the cluster, serves no DNS).
const masterControlPlaneOnlyKey = "master_control_plane_only"

// MasterMaintenance reports whether the master is drained (answering SERVFAIL).
func (s *Store) MasterMaintenance() bool {
	v, _ := s.GetMetaInt(masterMaintenanceKey)
	return v != 0
}

// SetMasterMaintenance persists the master's drain flag.
func (s *Store) SetMasterMaintenance(on bool) error {
	return s.SetMetaInt(masterMaintenanceKey, int64(boolToInt(on)))
}

// masterAdvertiseAddrKey holds the master's own site-reachable address
// (MAZEDNS_ADVERTISE_ADDR), shown as its node address and in client config.
const masterAdvertiseAddrKey = "master_advertise_addr"

// MasterAdvertiseAddr / SetMasterAdvertiseAddr read and persist the master's
// advertised DNS address.
func (s *Store) MasterAdvertiseAddr() string { v, _ := s.GetMeta(masterAdvertiseAddrKey); return v }
func (s *Store) SetMasterAdvertiseAddr(addr string) error {
	return s.SetMeta(masterAdvertiseAddrKey, strings.TrimSpace(addr))
}

// MasterControlPlaneOnly reports whether the master is running as a control plane
// only (no DNS — every query is answered REFUSED).
func (s *Store) MasterControlPlaneOnly() bool {
	v, _ := s.GetMetaInt(masterControlPlaneOnlyKey)
	return v != 0
}

// SetMasterControlPlaneOnly persists the master's control-plane-only flag.
func (s *Store) SetMasterControlPlaneOnly(on bool) error {
	return s.SetMetaInt(masterControlPlaneOnlyKey, int64(boolToInt(on)))
}

// SetNodeMaintenance toggles a worker node's drain (maintenance) flag. The worker
// picks it up on its next config poll and starts/stops answering SERVFAIL.
func (s *Store) SetNodeMaintenance(id string, on bool) error {
	res, err := s.db.Exec(`UPDATE nodes SET maintenance=? WHERE id=?`, boolToInt(on), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("node not found")
	}
	return nil
}

// UpdateNodeKey rotates an enrolled node's API key (hash + display prefix), keyed
// by its immutable id. The rotation clock (key_issued_at) is reset and any pending
// grace key is cleared — the new key is delivered directly to the caller, so no
// overlap window is needed. For a zero-downtime server-driven rotation that keeps
// the old key valid for a grace window, use RotateNodeKey instead.
func (s *Store) UpdateNodeKey(id, keyHash, keyPrefix string) error {
	res, err := s.db.Exec(
		`UPDATE nodes SET key_hash=?, key_prefix=?, key_issued_at=?, prev_key_hash='', prev_key_expires_at=0 WHERE id=?`,
		keyHash, keyPrefix, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("node not found")
	}
	return nil
}

// RotateNodeKeyByID is an alias for UpdateNodeKey used on the ownership-proven
// re-enroll path: an agent that presented its id and current key gets a fresh key
// while its identity, name, stats, site, role, and approval are preserved.
func (s *Store) RotateNodeKeyByID(id, keyHash, keyPrefix string) error {
	return s.UpdateNodeKey(id, keyHash, keyPrefix)
}

// RotateNodeKey sets a node's current key while keeping a previous key valid until
// prevExpires (the grace overlap). It is the store primitive for zero-downtime
// server-driven rotation: the caller passes the previous key hash to accept during
// the window and the new issue time. All fields are set atomically.
func (s *Store) RotateNodeKey(id, keyHash, keyPrefix, prevHash string, prevExpires, issuedAt int64) error {
	res, err := s.db.Exec(
		`UPDATE nodes SET key_hash=?, key_prefix=?, key_issued_at=?, prev_key_hash=?, prev_key_expires_at=? WHERE id=?`,
		keyHash, keyPrefix, issuedAt, prevHash, prevExpires, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("node not found")
	}
	return nil
}

// ConfirmKeyRotation retires a node's previous (grace) key immediately — called
// once the agent is seen authenticating with the new current key, so the old key
// stops working "on first use of the new key" rather than lingering until its
// grace deadline.
func (s *Store) ConfirmKeyRotation(id string) error {
	_, err := s.db.Exec(`UPDATE nodes SET prev_key_hash='', prev_key_expires_at=0 WHERE id=?`, id)
	return err
}

// CreateNode enrolls a new node with a freshly generated id and the given API key
// hash and display prefix, returning the id. name must be unique.
func (s *Store) CreateNode(name, keyHash, keyPrefix string) (string, error) {
	id := uuid.NewString()
	return id, s.CreateNodeWithID(id, name, keyHash, keyPrefix, true)
}

// CreateNodeWithID inserts a new node row with the given immutable id. The caller
// owns id generation (server-side) and name de-duplication. approved sets whether
// the node is immediately admitted or held pending an admin's approval.
func (s *Store) CreateNodeWithID(id, name, keyHash, keyPrefix string, approved bool) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(
		`INSERT INTO nodes(id, name, key_hash, key_prefix, address, version, last_seen, created_at, approved, key_issued_at)
		 VALUES(?,?,?,?,'','',0,?,?,?)`,
		id, name, keyHash, keyPrefix, now, boolToInt(approved), now)
	return err
}

// SetNodeApproved admits (or re-holds) an enrolled node. A pending node's config
// pulls and log shipments are refused until it is approved.
func (s *Store) SetNodeApproved(id string, approved bool) error {
	res, err := s.db.Exec(`UPDATE nodes SET approved=? WHERE id=?`, boolToInt(approved), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("node not found")
	}
	return nil
}

// EnsureNode pre-provisions a node with a fixed key (dev/automation bootstrap). If
// a node with that name already exists its key is updated in place (identity/stats
// preserved); otherwise a new node with a fresh id is created. Idempotent across
// restarts.
func (s *Store) EnsureNode(name, keyHash, keyPrefix string) error {
	existing, err := s.NodeByName(name)
	if err != nil {
		return err
	}
	if existing != nil {
		return s.UpdateNodeKey(existing.ID, keyHash, keyPrefix)
	}
	return s.CreateNodeWithID(uuid.NewString(), name, keyHash, keyPrefix, true)
}

// RenameNode changes a node's display label without changing its identity. The new
// name propagates to historical rows tagged by name (query_log + rollups) in the
// same transaction so a rename never splits a node's history. name must be unique.
func (s *Store) RenameNode(id, newName string) error {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return errors.New("name is required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	var old string
	if err := tx.QueryRow(`SELECT name FROM nodes WHERE id=?`, id).Scan(&old); err != nil {
		_ = tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("node not found")
		}
		return err
	}
	if old == newName {
		_ = tx.Rollback()
		return nil
	}
	if _, err := tx.Exec(`UPDATE nodes SET name=? WHERE id=?`, newName, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	// Cascade to history so charts/logs stay under one label. Names are unique among
	// live nodes, so these updates don't collide with another live node's rows.
	for _, q := range []string{
		`UPDATE query_log SET node=? WHERE node=?`,
		`UPDATE query_rollup SET node=? WHERE node=?`,
		`UPDATE client_rollup SET node=? WHERE node=?`,
	} {
		if _, err := tx.Exec(q, newName, old); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// NodeByKeyHash returns the node whose key hash matches, or (nil, nil) if none.
func (s *Store) NodeByKeyHash(keyHash string) (*Node, error) {
	if keyHash == "" {
		return nil, nil
	}
	return s.nodeBy(`key_hash=?`, keyHash)
}

// NodeByID returns the node with the given immutable id, or (nil, nil) if none.
func (s *Store) NodeByID(id string) (*Node, error) {
	if id == "" {
		return nil, nil
	}
	return s.nodeBy(`id=?`, id)
}

// NodeByAnyKeyHash authenticates a node by a presented key hash, accepting either
// the current key or the previous key while it is still within its rotation grace
// window. viaCurrent reports whether the match was the current key (false = the
// grace key, i.e. the agent has not yet adopted a rotated key). Returns (nil,
// false, nil) when no node matches.
func (s *Store) NodeByAnyKeyHash(keyHash string) (n *Node, viaCurrent bool, err error) {
	if keyHash == "" {
		return nil, false, nil
	}
	if n, err = s.NodeByKeyHash(keyHash); err != nil || n != nil {
		return n, n != nil, err
	}
	// Not the current key of any node — try the grace (previous) key.
	n, err = s.nodeBy(`prev_key_hash=? AND prev_key_expires_at>?`, keyHash, time.Now().Unix())
	return n, false, err
}

// NodeByName returns the node with the given display label, or (nil, nil) if none.
func (s *Store) NodeByName(name string) (*Node, error) {
	if name == "" {
		return nil, nil
	}
	return s.nodeBy(`name=?`, name)
}

// nodeBy loads a single node by an arbitrary WHERE predicate and bound args.
func (s *Store) nodeBy(where string, args ...any) (*Node, error) {
	n := &Node{}
	var maintenance, approved int
	err := s.read.QueryRow(
		`SELECT id, name, key_hash, key_prefix, address, version, last_seen, created_at, maintenance, approved,
		        key_issued_at, prev_key_hash, prev_key_expires_at
		 FROM nodes WHERE `+where, args...).
		Scan(&n.ID, &n.Name, &n.KeyHash, &n.KeyPrefix, &n.Address, &n.Version, &n.LastSeen, &n.CreatedAt, &maintenance, &approved,
			&n.KeyIssuedAt, &n.PrevKeyHash, &n.PrevKeyExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.Maintenance = maintenance != 0
	n.Approved = approved != 0
	return n, nil
}

// TouchNode refreshes a node's last-seen address, config version, and stats.
func (s *Store) TouchNode(id, address, version string, st NodeStats) error {
	_, err := s.db.Exec(
		`UPDATE nodes SET address=?, version=?, last_seen=?,
		   q_total=?, q_blocked=?, q_cached=?, q_forwarded=?, q_rewritten=?, q_errors=?
		 WHERE id=?`,
		address, version, time.Now().Unix(),
		st.Total, st.Blocked, st.Cached, st.Forwarded, st.Rewritten, st.Errors, id)
	return err
}

// SetNodeInsights stores a node's latest reported insights (JSON).
func (s *Store) SetNodeInsights(id, data string) error {
	_, err := s.db.Exec(`UPDATE nodes SET insights=? WHERE id=?`, data, id)
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
		`SELECT id, name, key_prefix, address, version, last_seen, created_at,
		        q_total, q_blocked, q_cached, q_forwarded, q_rewritten, q_errors, maintenance, site, role, approved, key_issued_at
		 FROM nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var maintenance, approved int
		if err := rows.Scan(&n.ID, &n.Name, &n.KeyPrefix, &n.Address, &n.Version, &n.LastSeen, &n.CreatedAt,
			&n.Total, &n.Blocked, &n.Cached, &n.Forwarded, &n.Rewritten, &n.Errors, &maintenance, &n.Site, &n.Role, &approved, &n.KeyIssuedAt); err != nil {
			return nil, err
		}
		n.Maintenance = maintenance != 0
		n.Approved = approved != 0
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteNode revokes a node (removing its key), keyed by its immutable id. Its
// historical rows (tagged by name) are left in place.
func (s *Store) DeleteNode(id string) error {
	_, err := s.db.Exec(`DELETE FROM nodes WHERE id=?`, id)
	return err
}
