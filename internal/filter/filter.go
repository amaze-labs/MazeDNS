// Package filter matches DNS query names against blocklists.
package filter

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
)

// Engine holds a set of blocked domains. Blocking a domain also blocks all of
// its subdomains.
type Engine struct {
	mu      sync.RWMutex
	blocked map[string]struct{}
}

// New returns an empty Engine.
func New() *Engine {
	return &Engine{blocked: make(map[string]struct{})}
}

// Add inserts a single domain into the blocklist.
func (e *Engine) Add(domain string) {
	d := normalize(domain)
	if d == "" {
		return
	}
	e.mu.Lock()
	e.blocked[d] = struct{}{}
	e.mu.Unlock()
}

// LoadHostsFile parses a hosts-format or plain domain-list file and returns the
// number of new domains added. Lines may be "0.0.0.0 domain", "127.0.0.1 domain",
// or just "domain"; "#" starts a comment.
func (e *Engine) LoadHostsFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

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
			e.blocked[domain] = struct{}{}
			count++
		}
	}
	return count, sc.Err()
}

// IsBlocked reports whether name, or any of its parent domains, is blocked.
func (e *Engine) IsBlocked(name string) bool {
	name = normalize(name)
	if name == "" {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.blocked) == 0 {
		return false
	}
	for {
		if _, ok := e.blocked[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
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
