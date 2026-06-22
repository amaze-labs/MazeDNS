// Package filter matches DNS query names against categorized blocklists.
package filter

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
)

// Engine holds blocked domains, each tagged with a category. Blocking a domain
// also blocks all of its subdomains.
type Engine struct {
	mu      sync.RWMutex
	blocked map[string]string // normalized domain -> category
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

// Match returns the category of the matching (sub)domain and true if name, or
// any of its parent domains, is blocked.
func (e *Engine) Match(name string) (string, bool) {
	name = normalize(name)
	if name == "" {
		return "", false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.blocked) == 0 {
		return "", false
	}
	for {
		if cat, ok := e.blocked[name]; ok {
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
