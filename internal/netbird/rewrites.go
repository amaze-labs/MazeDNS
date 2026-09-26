package netbird

import (
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// rewriteIndex maps client IPs to the host names the operator gave them through
// Local DNS rewrites (enabled, non-wildcard A/AAAA records). Names in every
// slice are deduplicated and sorted preferred-first (see sortNames).
type rewriteIndex struct {
	// all covers every enabled rewrite regardless of scope: the fallback when the
	// client's node is unknown or serves no rewrite for that IP.
	all map[string][]string
	// byNode holds, per known node, exactly the rewrites that node serves (scope
	// precedence resolved), so a split-horizon name is picked from the node
	// that actually answers the client.
	byNode map[string]map[string][]string
}

// buildRewriteIndex derives the reverse (IP -> names) index from the full
// rewrite table and the node list (for per-node scoping).
func buildRewriteIndex(all []store.Rewrite, nodes []store.Node) rewriteIndex {
	idx := rewriteIndex{all: reverseRewrites(all), byNode: make(map[string]map[string][]string, len(nodes))}
	for _, n := range nodes {
		idx.byNode[n.Name] = reverseRewrites(store.FilterRewritesForNode(all, n.Name, n.Site))
	}
	return idx
}

// reverseRewrites builds IP -> sorted names from the enabled, non-wildcard
// A/AAAA rewrites in rws. Scope fields are ignored: callers pre-filter.
func reverseRewrites(rws []store.Rewrite) map[string][]string {
	sets := map[string]map[string]bool{}
	for _, rw := range rws {
		if !rw.Enabled {
			continue
		}
		name := filter.Normalize(rw.Domain)
		if name == "" || strings.Contains(name, "*") {
			continue
		}
		ip, ok := rewriteIP(rw.RRType, rw.Value)
		if !ok {
			continue
		}
		if sets[ip] == nil {
			sets[ip] = map[string]bool{}
		}
		sets[ip][name] = true
	}
	out := make(map[string][]string, len(sets))
	for ip, set := range sets {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sortNames(names)
		out[ip] = names
	}
	return out
}

// rewriteIP returns the canonical address an A/AAAA rewrite points to. An A
// record must hold an IPv4 address and an AAAA record a genuine IPv6 address
// (IPv4 values in AAAA records are skipped, matching what a PTR for them would
// have to be).
func rewriteIP(rrtype, value string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return "", false
	}
	switch strings.ToUpper(rrtype) {
	case "A":
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), true
		}
	case "AAAA":
		if ip.To4() == nil {
			return ip.String(), true
		}
	}
	return "", false
}

// canonicalIP normalizes a client IP string so it compares equal to the index
// keys (e.g. an expanded IPv6 address, or an IPv4-mapped IPv6 one).
func canonicalIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// sortNames orders names preferred-first: shortest, then alphabetical. The
// same rule picks the PTR answer the resolver synthesizes from rewrites.
func sortNames(names []string) {
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
}

// RefreshRewrites rebuilds the rewrite-derived name index from the store. It is
// called on every refresh tick and by the API after any config mutation, so an
// added, edited, disabled or deleted rewrite is reflected immediately.
func (e *Enricher) RefreshRewrites() {
	if e.store == nil {
		return
	}
	rws, err := e.store.ListRewrites()
	if err != nil {
		slog.Warn("client names: load rewrites", "err", err)
		return // keep the previous index
	}
	nodes, err := e.store.ListNodes()
	if err != nil {
		slog.Warn("client names: load nodes", "err", err)
		nodes = nil // still usable: every client falls back to the unscoped index
	}
	idx := buildRewriteIndex(rws, nodes)
	e.mu.Lock()
	e.rewrites = idx
	e.mu.Unlock()
}

// rewriteNames returns the rewrite names for a client IP, preferred first. The
// rewrites served by the client's node win; otherwise any enabled rewrite
// pointing at the IP (whatever its scope) names it. Caller must not hold e.mu.
func (e *Enricher) rewriteNames(ip string) []string {
	key := canonicalIP(ip)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if node := e.cnode[ip]; node != "" {
		if names := e.rewrites.byNode[node][key]; len(names) > 0 {
			return names
		}
	}
	return e.rewrites.all[key]
}
