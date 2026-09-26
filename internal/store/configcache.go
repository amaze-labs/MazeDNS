package store

import (
	"sync"
	"time"
)

// configVersionTTL bounds how long a cached config version is trusted even
// when no write was observed. The generation counter already invalidates the
// cache on every write made through this Store; the TTL is a safety net for a
// change it cannot see (the database edited from outside the process, e.g. a
// manual SQL fix or a restored backup), so agents converge within minutes
// instead of never.
var configVersionTTL = 5 * time.Minute

// versionCache memoizes config versions (per node, and the global one) for
// the current config generation.
//
// Correctness argument: a caller reads the generation g BEFORE loading the
// data it hashes, and the entry is stored under g only if the generation is
// still g. Every write bumps the generation strictly AFTER it is visible to
// readers (see dbh/txh). So if an entry for g is returned, no bump happened
// since g was read; any write visible to the lookup had its bump before g was
// read, and therefore was already visible when the data was loaded. The only
// window is between a write's commit and its bump (a few instructions), in
// which a poll may still see the previous version — the next poll sees the
// new one.
type versionCache struct {
	mu      sync.Mutex
	gen     uint64 // generation the entries were computed at
	entries map[string]cachedVersion
	now     func() time.Time // test hook; nil = time.Now
}

type cachedVersion struct {
	version string
	at      time.Time
}

func (c *versionCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// get returns the cached version for key if it was computed at generation
// cur and is younger than configVersionTTL.
func (c *versionCache) get(cur uint64, key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != cur {
		if cur > c.gen {
			c.gen, c.entries = cur, nil // the config changed: drop everything
		}
		return "", false
	}
	e, ok := c.entries[key]
	if !ok || c.clock().Sub(e.at) >= configVersionTTL {
		return "", false
	}
	return e.version, true
}

// put stores a version computed from data loaded after reading generation
// gen, unless the generation has moved on since (cur != gen): the data may
// predate a newer write, so it is dropped rather than cached.
func (c *versionCache) put(cur, gen uint64, key, version string) {
	if cur != gen {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen || c.entries == nil {
		c.gen, c.entries = gen, map[string]cachedVersion{}
	}
	c.entries[key] = cachedVersion{version: version, at: c.clock()}
}

// nodeVersionKey keys a per-node version by exactly the inputs besides the
// config tables that the per-node content depends on: the node's name and
// site (scope matching). A rename or site move is a different key, so it
// never needs an explicit invalidation.
func nodeVersionKey(name, site string) string { return "n\x00" + name + "\x00" + site }

// globalVersionKey keys the cluster-wide ConfigVersion.
const globalVersionKey = "g"

// NodeSnapshot is the replicated content served to one node, with the version
// hash computed from exactly that content.
type NodeSnapshot struct {
	Rules      []Rule
	Rewrites   []Rewrite
	Forwarders []ForwardSpec
	Version    string
}

// SnapshotForNode loads the content served to one node and hashes it in the
// same pass — the rule set is read once, not once for the payload and again
// for the version — and refreshes that node's cached version.
func (s *Store) SnapshotForNode(nodeName, nodeSite string) (NodeSnapshot, error) {
	gen := s.configGen.Load()
	rules, err := s.ReplicatedRules()
	if err != nil {
		return NodeSnapshot{}, err
	}
	rws, err := s.ListRewritesForNode(nodeName, nodeSite)
	if err != nil {
		return NodeSnapshot{}, err
	}
	fws, err := s.ListForwardersForNode(nodeName, nodeSite)
	if err != nil {
		return NodeSnapshot{}, err
	}
	v := configHash(rules, rws, fws)
	s.versions.put(s.configGen.Load(), gen, nodeVersionKey(nodeName, nodeSite), v)
	return NodeSnapshot{Rules: rules, Rewrites: rws, Forwarders: fws, Version: v}, nil
}

// CachedConfigVersionForNode is ConfigVersionForNode served from the version
// cache: while the config is unchanged it costs a map lookup instead of
// loading and hashing every rule.
func (s *Store) CachedConfigVersionForNode(nodeName, nodeSite string) (string, error) {
	key := nodeVersionKey(nodeName, nodeSite)
	gen := s.configGen.Load()
	if v, ok := s.versions.get(gen, key); ok {
		return v, nil
	}
	v, err := s.ConfigVersionForNode(nodeName, nodeSite)
	if err != nil {
		return "", err
	}
	s.versions.put(s.configGen.Load(), gen, key, v)
	return v, nil
}

// CachedConfigVersion is ConfigVersion served from the version cache.
func (s *Store) CachedConfigVersion() (string, error) {
	gen := s.configGen.Load()
	if v, ok := s.versions.get(gen, globalVersionKey); ok {
		return v, nil
	}
	v, err := s.ConfigVersion()
	if err != nil {
		return "", err
	}
	s.versions.put(s.configGen.Load(), gen, globalVersionKey, v)
	return v, nil
}

// ConfigVersionsForNodes computes every node's expected config version,
// serving nodes whose version is cached for the current generation from the
// cache and computing the rest in one batched pass (see
// configVersionsForNodes). The result is byte-identical to calling
// ConfigVersionForNode(n.Name, n.Site) for each node. Keyed by node name.
func (s *Store) ConfigVersionsForNodes(nodes []Node) (map[string]string, error) {
	gen := s.configGen.Load()
	out := make(map[string]string, len(nodes))
	var missing []Node
	for _, n := range nodes {
		if v, ok := s.versions.get(gen, nodeVersionKey(n.Name, n.Site)); ok {
			out[n.Name] = v
		} else {
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 {
		return out, nil
	}
	computed, err := s.configVersionsForNodes(missing)
	if err != nil {
		return nil, err
	}
	cur := s.configGen.Load()
	for _, n := range missing {
		v := computed[n.Name]
		out[n.Name] = v
		s.versions.put(cur, gen, nodeVersionKey(n.Name, n.Site), v)
	}
	return out, nil
}
