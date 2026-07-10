package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Scope types for rewrites and forwarders. Scope metadata exists only on the
// control plane: agents receive per-node pre-filtered, scope-free entries.
const (
	ScopeAll   = "all"   // every node
	ScopeNodes = "nodes" // an explicit list of node names
	ScopeSites = "sites" // one or more sites (named node groups)
)

// ForwardSpec is the lean forwarder shape replicated to agents and hashed into
// the config version: just the routing fact, no scope, no enabled flag
// (disabled entries are never served).
type ForwardSpec struct {
	Suffix    string   `json:"suffix"`
	Upstreams []string `json:"upstreams"`
}

// CanonicalScope validates a scope and returns its normalized type plus the
// canonical JSON encoding of its values (trimmed, deduped, sorted — so equal
// scopes always serialize identically, which the UNIQUE constraints rely on).
func CanonicalScope(scopeType string, values []string) (string, string, error) {
	switch scopeType {
	case "", ScopeAll:
		return ScopeAll, "[]", nil
	case ScopeNodes, ScopeSites:
	default:
		return "", "", fmt.Errorf("scope_type must be all, nodes, or sites")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		return "", "", fmt.Errorf("scope_values required for scope_type %q", scopeType)
	}
	sort.Strings(out)
	b, err := json.Marshal(out)
	if err != nil {
		return "", "", err
	}
	return scopeType, string(b), nil
}

// scopeRank orders scopes by specificity: node-scoped beats site-scoped beats all.
func scopeRank(scopeType string) int {
	switch scopeType {
	case ScopeNodes:
		return 3
	case ScopeSites:
		return 2
	default:
		return 1
	}
}

// ScopeMatches reports whether an entry with the given scope applies to a node.
func ScopeMatches(scopeType, valuesJSON, nodeName, nodeSite string) bool {
	switch scopeType {
	case ScopeNodes:
		return scopeContains(valuesJSON, nodeName)
	case ScopeSites:
		return nodeSite != "" && scopeContains(valuesJSON, nodeSite)
	default: // "" or "all"
		return true
	}
}

func scopeContains(valuesJSON, want string) bool {
	var vals []string
	if json.Unmarshal([]byte(valuesJSON), &vals) != nil {
		return false
	}
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

// scopeValuesIntersect reports whether two canonical value lists share a member —
// the write-time overlap check that keeps same-specificity winners unique.
func scopeValuesIntersect(aJSON, bJSON string) bool {
	var a, b []string
	if json.Unmarshal([]byte(aJSON), &a) != nil || json.Unmarshal([]byte(bJSON), &b) != nil {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if set[v] {
			return true
		}
	}
	return false
}
