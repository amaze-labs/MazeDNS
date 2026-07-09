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

// configHash is the shared content hash both sides compute from their own
// data: the master over a node's filtered view, the agent over its local
// tables + persisted forwarders blob. Line formats are frozen (R|, W|, F|) —
// changing them desynchronizes every agent at once.
func configHash(rules []Rule, rewrites []Rewrite, fws []ForwardSpec) string {
	lines := make([]string, 0, len(rules)+len(rewrites)+len(fws))
	for _, r := range rules {
		lines = append(lines, fmt.Sprintf("R|%s|%s|%s|%t", r.Action, r.Domain, r.Category, r.Enabled))
	}
	for _, rw := range rewrites {
		lines = append(lines, fmt.Sprintf("W|%s|%s|%s|%t", rw.Domain, rw.RRType, rw.Value, rw.Enabled))
	}
	for _, f := range fws {
		lines = append(lines, fmt.Sprintf("F|%s|%s", f.Suffix, strings.Join(f.Upstreams, ",")))
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

// ListRewritesForNode returns the rewrites that apply to one node, precedence
// resolved (nodes > sites > all) to a single winner per domain+rrtype, with
// scope fields zeroed — the served set is scope-free by design, so agents
// need no scope logic and old agents keep working.
func (s *Store) ListRewritesForNode(nodeName, nodeSite string) ([]Rewrite, error) {
	all, err := s.ListRewrites()
	if err != nil {
		return nil, err
	}
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
		if r := scopeRank(rw.ScopeType); r > rank[k] {
			rank[k] = r
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
	return out, nil
}

// ListForwardersForNode returns the enabled forwarders that apply to one node,
// precedence resolved to a single winner per suffix, as lean ForwardSpecs.
func (s *Store) ListForwardersForNode(nodeName, nodeSite string) ([]ForwardSpec, error) {
	all, err := s.ListForwarders()
	if err != nil {
		return nil, err
	}
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
	Name             string `json:"name"`
	KeyPrefix        string `json:"key_prefix"`
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

// EnrollNode admits a token-joining agent: it creates the node with the given
// API key hash + display prefix, or if the name already exists rotates its key in
// place (existing stats/site/role are preserved). approved sets whether the node
// is immediately admitted or left pending an admin's approval. Used by the
// self-service /api/cluster/enroll flow.
func (s *Store) EnrollNode(name, keyHash, keyPrefix string, approved bool) error {
	_, err := s.db.Exec(
		`INSERT INTO nodes(name, key_hash, key_prefix, address, version, last_seen, created_at, approved)
		 VALUES(?,?,?,'','',0,?,?)
		 ON CONFLICT(name) DO UPDATE SET key_hash=excluded.key_hash, key_prefix=excluded.key_prefix`,
		name, keyHash, keyPrefix, time.Now().Unix(), boolToInt(approved))
	return err
}

// SetNodeApproved admits (or re-holds) an enrolled node. A pending node's config
// pulls and log shipments are refused until it is approved.
func (s *Store) SetNodeApproved(name string, approved bool) error {
	res, err := s.db.Exec(`UPDATE nodes SET approved=? WHERE name=?`, boolToInt(approved), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("node not found")
	}
	return nil
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
	var maintenance, approved int
	err := s.read.QueryRow(
		`SELECT name, key_prefix, address, version, last_seen, created_at, maintenance, site, role, approved
		 FROM nodes WHERE key_hash=?`, keyHash).
		Scan(&n.Name, &n.KeyPrefix, &n.Address, &n.Version, &n.LastSeen, &n.CreatedAt, &maintenance, &n.Site, &n.Role, &approved)
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
		        q_total, q_blocked, q_cached, q_forwarded, q_rewritten, q_errors, maintenance, site, role, approved
		 FROM nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var maintenance, approved int
		if err := rows.Scan(&n.Name, &n.KeyPrefix, &n.Address, &n.Version, &n.LastSeen, &n.CreatedAt,
			&n.Total, &n.Blocked, &n.Cached, &n.Forwarded, &n.Rewritten, &n.Errors, &maintenance, &n.Site, &n.Role, &approved); err != nil {
			return nil, err
		}
		n.Maintenance = maintenance != 0
		n.Approved = approved != 0
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteNode revokes a node (removing its key).
func (s *Store) DeleteNode(name string) error {
	_, err := s.db.Exec(`DELETE FROM nodes WHERE name=?`, name)
	return err
}
