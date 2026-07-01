// Package filter matches DNS query names against categorized blocklists.
package filter

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Engine holds blocked domains, each tagged with a category. Blocking a domain
// also blocks all of its subdomains.
//
// Lifecycle: an Engine is built (Add/LoadHostsFile), then Seal()ed and published
// read-only (the resolver swaps it in via an atomic pointer). After Seal the
// lookup path is lock-free — the map is never mutated again and the atomic publish
// provides the happens-before barrier — which removes two RWMutex operations from
// every query. Before Seal, reads take the lock so build-time reads stay safe.
type Engine struct {
	mu      sync.RWMutex
	blocked map[string]string // normalized domain -> category
	sealed  atomic.Bool
}

// New returns an empty Engine.
func New() *Engine {
	return &Engine{blocked: make(map[string]string)}
}

// Add inserts a single domain with a category ("" becomes "custom").
func (e *Engine) Add(domain, category string) {
	d := normalize(domain)
	if d == "" {
		return
	}
	if category == "" {
		category = "custom"
	}
	e.mu.Lock()
	e.blocked[d] = category
	e.mu.Unlock()
}

// LoadHostsFile parses a hosts-format or plain domain-list file, tagging entries
// with category, and returns the number of new domains added.
func (e *Engine) LoadHostsFile(path, category string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if category == "" {
		category = "custom"
	}

	count := 0
	e.mu.Lock()
	defer e.mu.Unlock()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		domain := fields[0]
		if len(fields) > 1 { // hosts format: "<ip> <domain>"
			if net.ParseIP(fields[0]) == nil {
				continue
			}
			domain = fields[1]
		}
		domain = normalize(domain)
		if domain == "" || domain == "localhost" {
			continue
		}
		if _, exists := e.blocked[domain]; !exists {
			e.blocked[domain] = category
			count++
		}
	}
	return count, sc.Err()
}

// Seal marks the engine immutable so the lookup path can read the map without
// locking. Call it once after the engine is fully built and before publishing it
// to the resolver. Add/LoadHostsFile must not be called after Seal.
func (e *Engine) Seal() { e.sealed.Store(true) }

// Match returns the category of the matching (sub)domain and true if name, or any
// of its parent domains, is blocked. name is normalized here; hot-path callers
// that already hold a normalized name should use MatchNormalized.
func (e *Engine) Match(name string) (string, bool) {
	return e.lookup(normalize(name))
}

// MatchNormalized is Match for a caller that already holds the normalized name
// (lowercased, no trailing dot), avoiding a redundant normalization per query.
func (e *Engine) MatchNormalized(name string) (string, bool) {
	return e.lookup(name)
}

// lookup walks name and its parent suffixes against the blocked map. Once the
// engine is sealed it reads lock-free; before that it takes the read lock.
func (e *Engine) lookup(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if e.sealed.Load() {
		return matchMap(e.blocked, name)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return matchMap(e.blocked, name)
}

func matchMap(blocked map[string]string, name string) (string, bool) {
	if len(blocked) == 0 {
		return "", false
	}
	for {
		if cat, ok := blocked[name]; ok {
			return cat, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", false
		}
		name = name[i+1:]
	}
}

// IsBlocked reports whether name, or any parent domain, is blocked.
func (e *Engine) IsBlocked(name string) bool {
	_, ok := e.Match(name)
	return ok
}

// IsBlockedNormalized is IsBlocked for an already-normalized name (hot path).
func (e *Engine) IsBlockedNormalized(name string) bool {
	_, ok := e.MatchNormalized(name)
	return ok
}

// Len returns the number of blocked domains.
func (e *Engine) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.blocked)
}

func normalize(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// Normalize lowercases a domain and strips a trailing dot. Exported so callers
// can build policy keys (e.g. rewrites) consistently with the matcher.
func Normalize(domain string) string { return normalize(domain) }
