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

// ruleLine, rewriteLine, and forwardLine are the single source of truth for
// the hashed line formats (R|, W|, F|) shared by configHash and the batched
// ConfigVersionsForNodes — they are frozen: changing them desynchronizes
// every agent at once.
func ruleLine(r Rule) string {
	return fmt.Sprintf("R|%s|%s|%s|%t", r.Action, r.Domain, r.Category, r.Enabled)
}

func rewriteLine(rw Rewrite) string {
	return fmt.Sprintf("W|%s|%s|%s|%t", rw.Domain, rw.RRType, rw.Value, rw.Enabled)
}

func forwardLine(f ForwardSpec) string {
	return fmt.Sprintf("F|%s|%s", f.Suffix, strings.Join(f.Upstreams, ","))
}

// configHash is the shared content hash both sides compute from their own
// data: the master over a node's filtered view, the agent over its local
// tables + persisted forwarders blob.
func configHash(rules []Rule, rewrites []Rewrite, fws []ForwardSpec) string {
	lines := make([]string, 0, len(rules)+len(rewrites)+len(fws))
	for _, r := range rules {
		lines = append(lines, ruleLine(r))
	}
	for _, rw := range rewrites {
		lines = append(lines, rewriteLine(rw))
	}
	for _, f := range fws {
		lines = append(lines, forwardLine(f))
	}
	sort.Strings(lines) // order-independent: same content -> same hash on every node
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])[:12]
}

// ConfigVersion returns a short content hash of the replicated config this
// node holds (rules + rewrites + centrally-pushed forwarders). A worker
// detects drift by comparing its own hash to the per-node hash the master
// advertises — no monotonic counter needed.
func (s *Store) ConfigVersion() (string, error) {
	rules, err := s.ReplicatedRules()
	if err != nil {
		return "", err
	}
	rewrites, err := s.ListRewrites()
	if err != nil {
		return "", err
	}
	fws, err := s.ClusterForwarders()
	if err != nil {
		return "", err
	}
	return configHash(rules, rewrites, fws), nil
}

// ConfigVersionForNode is the master-side counterpart of an agent's
// ConfigVersion: the hash of exactly the content served to that node.
func (s *Store) ConfigVersionForNode(nodeName, nodeSite string) (string, error) {
	rules, err := s.ReplicatedRules()
	if err != nil {
		return "", err
	}
	rws, err := s.ListRewritesForNode(nodeName, nodeSite)
	if err != nil {
		return "", err
	}
	fws, err := s.ListForwardersForNode(nodeName, nodeSite)
	if err != nil {
		return "", err
	}
	return configHash(rules, rws, fws), nil
}

// filterRewritesForNode is the per-node filtering body shared by
// ListRewritesForNode and the batched ConfigVersionsForNodes: it resolves
// precedence over an already-loaded slice to a single winner per
// domain+rrtype, with scope fields zeroed — the served set is scope-free by
// design, so agents need no scope logic and old agents keep working. The
// rule: the most specific enabled entry wins; a disabled entry is served
// only when nothing enabled matches — so disabling an override falls back
// to the broader scope, matching forwarder behavior.
func filterRewritesForNode(all []Rewrite, nodeName, nodeSite string) []Rewrite {
	type key struct{ domain, rrtype string }
	best := map[key]Rewrite{}
	rank := map[key]int{}
	for _, rw := range all {
		valsJSON := "[]"
		if len(rw.ScopeValues) > 0 {
			b, _ := json.Marshal(rw.ScopeValues)
			valsJSON = string(b)
		}
		if !ScopeMatches(rw.ScopeType, valsJSON, nodeName, nodeSite) {
			continue
		}
		k := key{rw.Domain, rw.RRType}
		// Enabled always beats disabled (any enabled rank 1..3 plus 3 exceeds any
		// disabled rank 1..3); among same enabled-ness, higher scope rank wins.
		// Ties within the same effectiveRank can't happen: write-time overlap
		// rejection guarantees at most one match per (key, scope rank).
		effectiveRank := scopeRank(rw.ScopeType)
		if rw.Enabled {
			effectiveRank += 3
		}
		if effectiveRank > rank[k] {
			rank[k] = effectiveRank
			rw.ScopeType, rw.ScopeValues = "", nil
			best[k] = rw
		}
	}
	out := make([]Rewrite, 0, len(best))
	for _, rw := range best {
		out = append(out, rw)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].RRType < out[j].RRType
	})
	return out
}

// ListRewritesForNode returns the rewrites that apply to one node, precedence
// resolved to a single winner per domain+rrtype. See filterRewritesForNode
// for the precedence rule.
func (s *Store) ListRewritesForNode(nodeName, nodeSite string) ([]Rewrite, error) {
	all, err := s.ListRewrites()
	if err != nil {
		return nil, err
	}
	return filterRewritesForNode(all, nodeName, nodeSite), nil
}

// filterForwardersForNode is the per-node filtering body shared by
// ListForwardersForNode and the batched ConfigVersionsForNodes: only enabled
// entries that match the node are considered, precedence resolved to a
// single winner per suffix, as lean ForwardSpecs.
func filterForwardersForNode(all []Forwarder, nodeName, nodeSite string) []ForwardSpec {
	best := map[string]ForwardSpec{}
	rank := map[string]int{}
	for _, f := range all {
		if !f.Enabled {
			continue
		}
		valsJSON := "[]"
		if len(f.ScopeValues) > 0 {
			b, _ := json.Marshal(f.ScopeValues)
			valsJSON = string(b)
		}
		if !ScopeMatches(f.ScopeType, valsJSON, nodeName, nodeSite) {
			continue
		}
		if r := scopeRank(f.ScopeType); r > rank[f.Suffix] {
			rank[f.Suffix] = r
			best[f.Suffix] = ForwardSpec{Suffix: f.Suffix, Upstreams: f.Upstreams}
		}
	}
	out := make([]ForwardSpec, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Suffix < out[j].Suffix })
	return out
}

// ListForwardersForNode returns the enabled forwarders that apply to one node,
// precedence resolved to a single winner per suffix, as lean ForwardSpecs.
func (s *Store) ListForwardersForNode(nodeName, nodeSite string) ([]ForwardSpec, error) {
	all, err := s.ListForwarders()
	if err != nil {
		return nil, err
	}
	return filterForwardersForNode(all, nodeName, nodeSite), nil
}

// ConfigVersionsForNodes computes every node's expected config version in one
// pass: rules, rewrites, and forwarders are each loaded and formatted once,
// and nodes that resolve to the same filtered view share one hash computation
// (the common case — nodes with no node-specific scopes in the same site).
// The result is byte-identical to calling ConfigVersionForNode(n.Name, n.Site)
// for each node individually. Returned map is keyed by node name.
func (s *Store) ConfigVersionsForNodes(nodes []Node) (map[string]string, error) {
	rules, err := s.ReplicatedRules()
	if err != nil {
		return nil, err
	}
	rewrites, err := s.ListRewrites()
	if err != nil {
		return nil, err
	}
	fwds, err := s.ListForwarders()
	if err != nil {
		return nil, err
	}

	ruleLines := make([]string, 0, len(rules))
	for _, r := range rules {
		ruleLines = append(ruleLines, ruleLine(r))
	}

	memo := map[string]string{} // keyed by the node-specific lines, joined
	out := make(map[string]string, len(nodes))
	for _, n := range nodes {
		rws := filterRewritesForNode(rewrites, n.Name, n.Site)
		fws := filterForwardersForNode(fwds, n.Name, n.Site)
		nodeLines := make([]string, 0, len(rws)+len(fws))
		for _, rw := range rws {
			nodeLines = append(nodeLines, rewriteLine(rw))
		}
		for _, f := range fws {
			nodeLines = append(nodeLines, forwardLine(f))
		}
		memoKey := strings.Join(nodeLines, "\n")
		hash, ok := memo[memoKey]
		if !ok {
			lines := make([]string, 0, len(ruleLines)+len(nodeLines))
			lines = append(lines, ruleLines...)
			lines = append(lines, nodeLines...)
			sort.Strings(lines)
			sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
			hash = hex.EncodeToString(sum[:])[:12]
			memo[memoKey] = hash
		}
		out[n.Name] = hash
	}
	return out, nil
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
	Version          string `json:"version"`     // replicated-CONFIG hash the node last reported (rules sync state)
	AppVersion       string `json:"app_version"` // running binary build version the node last reported
	LastSeen         int64  `json:"last_seen"`
	CreatedAt        int64  `json:"created_at"`
	IsMaster         bool   `json:"is_master"`          // the master node (always online; no key to renew)
	Maintenance      bool   `json:"maintenance"`        // drained: this node answers SERVFAIL
	ControlPlaneOnly bool   `json:"control_plane_only"` // master only: coordinates the cluster but serves no DNS (answers REFUSED)
	Site             string `json:"site"`               // site grouping ('' = unassigned)
	Role             string `json:"role"`               // '' | 'primary' | 'secondary' | 'backup' (advisory: all serve DNS)
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
	// The nodes.name UNIQUE constraint only collides with a *live* node (a deleted
	// node's row is gone; only its history lingers). Reject that up front with a
	// friendly message so the API surfaces a clean 400 instead of a raw constraint
	// error from the UPDATE below.
	var live int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM nodes WHERE name=? AND id<>?`, newName, id).Scan(&live); err != nil {
		_ = tx.Rollback()
		return err
	}
	if live > 0 {
		_ = tx.Rollback()
		return errors.New("name in use by another node")
	}
	if _, err := tx.Exec(`UPDATE nodes SET name=? WHERE id=?`, newName, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	// Cascade to history so charts/logs stay under one label. query_log has no
	// uniqueness on node, so a plain UPDATE is fine. The rollup tables are keyed by
	// (bucket/hour, node, ...), and a DELETED node's orphaned history can already
	// occupy the target buckets under newName — so a blind UPDATE would violate the
	// PK. MERGE instead: fold the old-name rows into any existing newName rows
	// (summing the counters), then drop the old-name rows. All in this tx.
	if _, err := tx.Exec(`UPDATE query_log SET node=? WHERE node=?`, newName, old); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO query_rollup(bucket, node, action, cnt, lat_sum)
		 SELECT bucket, ?, action, cnt, lat_sum FROM query_rollup WHERE node=?
		 ON CONFLICT(bucket, node, action) DO UPDATE SET
		   cnt = cnt + excluded.cnt, lat_sum = lat_sum + excluded.lat_sum`,
		newName, old); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM query_rollup WHERE node=?`, old); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO client_rollup(hour, node, client, cnt, blocked)
		 SELECT hour, ?, client, cnt, blocked FROM client_rollup WHERE node=?
		 ON CONFLICT(hour, node, client) DO UPDATE SET
		   cnt = cnt + excluded.cnt, blocked = blocked + excluded.blocked`,
		newName, old); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM client_rollup WHERE node=?`, old); err != nil {
		_ = tx.Rollback()
		return err
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
		`SELECT id, name, key_hash, key_prefix, address, version, last_seen, created_at, maintenance, site, role, approved,
		        key_issued_at, prev_key_hash, prev_key_expires_at
		 FROM nodes WHERE `+where, args...).
		Scan(&n.ID, &n.Name, &n.KeyHash, &n.KeyPrefix, &n.Address, &n.Version, &n.LastSeen, &n.CreatedAt, &maintenance, &n.Site, &n.Role, &approved,
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

// TouchNode refreshes a node's last-seen address, config version, app (build)
// version, and stats.
func (s *Store) TouchNode(id, address, version, appVersion string, st NodeStats) error {
	_, err := s.db.Exec(
		`UPDATE nodes SET address=?, version=?, app_version=?, last_seen=?,
		   q_total=?, q_blocked=?, q_cached=?, q_forwarded=?, q_rewritten=?, q_errors=?
		 WHERE id=?`,
		address, version, appVersion, time.Now().Unix(),
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
		`SELECT id, name, key_prefix, address, version, app_version, last_seen, created_at,
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
		if err := rows.Scan(&n.ID, &n.Name, &n.KeyPrefix, &n.Address, &n.Version, &n.AppVersion, &n.LastSeen, &n.CreatedAt,
			&n.Total, &n.Blocked, &n.Cached, &n.Forwarded, &n.Rewritten, &n.Errors, &maintenance, &n.Site, &n.Role, &approved, &n.KeyIssuedAt); err != nil {
			return nil, err
		}
		n.Maintenance = maintenance != 0
		n.Approved = approved != 0
		out = append(out, n)
	}
	return out, rows.Err()
}

// RevokedNode is a tombstone for a node removed with revocation.
type RevokedNode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	RevokedAt int64  `json:"revoked_at"`
	RevokedBy string `json:"revoked_by"`
}

// DeleteNode removes a node by its immutable id. Its historical rows (tagged by
// name) are left in place. When revoke is true, a tombstone is written in the SAME
// transaction as the row delete, so a still-running agent presenting this id at
// re-enrollment is refused rather than self-healing into a new node (see
// clusterEnroll). When revoke is false the node is only removed (agent replacement:
// the agent may re-enroll as a brand-new node). revokedBy is the acting admin.
func (s *Store) DeleteNode(id string, revoke bool, revokedBy string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	var name string
	// Capture the current name for the tombstone (best effort; empty if already gone).
	_ = tx.QueryRow(`SELECT name FROM nodes WHERE id=?`, id).Scan(&name)
	if _, err := tx.Exec(`DELETE FROM nodes WHERE id=?`, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	if revoke {
		if _, err := tx.Exec(
			`INSERT INTO revoked_nodes(id, name, revoked_at, revoked_by) VALUES(?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET name=excluded.name, revoked_at=excluded.revoked_at, revoked_by=excluded.revoked_by`,
			id, name, time.Now().Unix(), revokedBy); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// IsNodeRevoked reports whether the given node id has a revocation tombstone.
func (s *Store) IsNodeRevoked(id string) (bool, error) {
	if id == "" {
		return false, nil
	}
	var n int
	err := s.read.QueryRow(`SELECT COUNT(*) FROM revoked_nodes WHERE id=?`, id).Scan(&n)
	return n > 0, err
}

// RevokedNodeByID returns a node's tombstone, or (nil, nil) if it isn't revoked.
func (s *Store) RevokedNodeByID(id string) (*RevokedNode, error) {
	rn := &RevokedNode{}
	err := s.read.QueryRow(
		`SELECT id, name, revoked_at, revoked_by FROM revoked_nodes WHERE id=?`, id).
		Scan(&rn.ID, &rn.Name, &rn.RevokedAt, &rn.RevokedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rn, nil
}

// ListRevokedNodes returns all revocation tombstones, newest first.
func (s *Store) ListRevokedNodes() ([]RevokedNode, error) {
	rows, err := s.read.Query(
		`SELECT id, name, revoked_at, revoked_by FROM revoked_nodes ORDER BY revoked_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RevokedNode{}
	for rows.Next() {
		var rn RevokedNode
		if err := rows.Scan(&rn.ID, &rn.Name, &rn.RevokedAt, &rn.RevokedBy); err != nil {
			return nil, err
		}
		out = append(out, rn)
	}
	return out, rows.Err()
}

// UnrevokeNode deletes a node's tombstone, letting its agent rejoin (as a new node)
// on the next enrollment attempt. Returns whether a tombstone was removed.
func (s *Store) UnrevokeNode(id string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM revoked_nodes WHERE id=?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
