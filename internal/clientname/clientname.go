// Package clientname enriches a client IP with a human-friendly identity.
// Sources, in order: an operator-assigned static name, the Local DNS rewrites
// that point at the IP, and finally a reverse-DNS (PTR) lookup. This is what
// turns a bare "10.x.y.z" in the query log into "alice-laptop" in the UI.
package clientname

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// LegacyNetbirdSettingsKey is the app_meta key where earlier versions stored
// the removed NetBird integration's settings, its API token included. The
// control plane deletes it at startup so the token doesn't linger.
const LegacyNetbirdSettingsKey = "netbird_settings"

// Identity is the resolved name for a client IP.
type Identity struct {
	Name   string `json:"name"`   // display name (static name, rewrite name or PTR hostname)
	Source string `json:"source"` // "manual" | "rewrite" | "rdns" | ""
	// Aliases are the other names the same source knows for the IP (today only
	// "rewrite": several rewrites pointing at one address), preferred-first.
	Aliases []string `json:"aliases,omitempty"`
}

// Enricher holds the static names, the rewrite-derived name index and the
// reverse-DNS cache, all keyed by client IP. For reverse-DNS it also tracks
// which node serves each client, so an internal client is resolved against that
// node's site resolver (nodes can be in different sites).
type Enricher struct {
	resolvers func() map[string]string // node name -> internal DNS resolver
	store     *store.Store

	mu     sync.RWMutex
	cnode  map[string]string // client ip -> node that serves it
	manual map[string]string // client ip -> operator-assigned static hostname
	// rewrites is the IP -> names index derived from Local DNS rewrites.
	rewrites rewriteIndex

	rdnsMu sync.Mutex
	rdns   map[string]rdnsEntry // ip -> cached PTR lookup
}

type rdnsEntry struct {
	name string
	exp  time.Time
}

// NewEnricher builds an enricher. resolvers supplies the per-node internal DNS
// resolver map; st supplies the static names, the rewrites and which node
// serves each client (for picking that node's resolver).
func NewEnricher(resolvers func() map[string]string, st *store.Store) *Enricher {
	return &Enricher{
		resolvers: resolvers, store: st,
		cnode: map[string]string{}, manual: map[string]string{}, rdns: map[string]rdnsEntry{},
	}
}

// Run refreshes the client->node map, the static names and the rewrite index
// periodically until ctx is cancelled.
func (e *Enricher) Run(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	e.refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.refresh()
		}
	}
}

func (e *Enricher) refresh() {
	if e.store == nil {
		return
	}
	// Refresh which node serves each client (used to pick that node's resolver
	// for internal reverse-DNS); keep the previous map on a store error.
	manual := LoadClientNames(e.store)
	cn, err := e.store.ClientNodes(time.Now().Add(-24 * time.Hour).UnixMilli())
	e.mu.Lock()
	if err == nil {
		e.cnode = cn
	}
	e.manual = manual
	e.mu.Unlock()
	e.RefreshRewrites()
}

// Lookup resolves a client IP to an identity: an operator-assigned static name,
// else a Local DNS rewrite name, else a (cached) reverse-DNS hostname. Returns a
// zero Identity if nothing is found.
func (e *Enricher) Lookup(ctx context.Context, ip string) Identity {
	ip = clientIP(ip)
	if ip == "" {
		return Identity{}
	}
	// Operator-assigned static names win over everything else.
	e.mu.RLock()
	name := e.manual[ip]
	e.mu.RUnlock()
	if name != "" {
		return Identity{Name: name, Source: "manual"}
	}
	// Rewrites are local operator config: authoritative and free to consult,
	// unlike a PTR lookup that costs a network query per IP.
	if names := e.rewriteNames(ip); len(names) > 0 {
		id := Identity{Name: names[0], Source: "rewrite"}
		if len(names) > 1 {
			id.Aliases = append([]string(nil), names[1:]...)
		}
		return id
	}
	if name := e.reverseDNS(ctx, ip); name != "" {
		return Identity{Name: name, Source: "rdns"}
	}
	return Identity{}
}

func (e *Enricher) reverseDNS(ctx context.Context, ip string) string {
	now := time.Now()
	e.rdnsMu.Lock()
	if c, ok := e.rdns[ip]; ok && now.Before(c.exp) {
		e.rdnsMu.Unlock()
		return c.name
	}
	e.rdnsMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Internal/private clients won't resolve on public DNS — use the internal
	// resolver of the node that serves this client (nodes can be in different
	// sites), falling back to the master's resolver, then the system resolver.
	resolver := net.DefaultResolver
	if isInternalIP(ip) {
		if addr := e.resolverFor(ip); addr != "" {
			resolver = dnsResolver(addr)
		}
	}
	name := ""
	if names, err := resolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	ttl := time.Hour
	if name == "" {
		ttl = 10 * time.Minute // retry sooner when there's no PTR
	}
	e.rdnsMu.Lock()
	if len(e.rdns) > 20000 {
		e.rdns = map[string]rdnsEntry{}
	}
	e.rdns[ip] = rdnsEntry{name: name, exp: now.Add(ttl)}
	e.rdnsMu.Unlock()
	return name
}

// resolverFor returns the internal DNS resolver to use for a client IP: the
// resolver of the node that serves it, else the master's, else "".
func (e *Enricher) resolverFor(ip string) string {
	if e.resolvers == nil {
		return ""
	}
	e.mu.RLock()
	node := e.cnode[ip]
	e.mu.RUnlock()
	res := e.resolvers()
	if node != "" && res[node] != "" {
		return res[node]
	}
	return res["master"]
}

// SetClientName persists an operator-assigned static hostname for a client IP
// (an empty name clears it) and updates the in-memory map immediately so the
// change is reflected without waiting for the next refresh.
func (e *Enricher) SetClientName(ip, name string) error {
	if err := SaveClientName(e.store, ip, name); err != nil {
		return err
	}
	ip = clientIP(ip)
	name = strings.TrimSpace(name)
	e.mu.Lock()
	if name == "" {
		delete(e.manual, ip)
	} else {
		e.manual[ip] = name
	}
	e.mu.Unlock()
	return nil
}

// clientIP strips a :port if present (query-log clients may be "ip:port").
func clientIP(s string) string {
	s = strings.TrimSpace(s)
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

// isInternalIP reports whether ip is on a private/internal range — RFC1918,
// loopback, link-local, unique-local, or the 100.64/10 CGNAT block (carrier NAT
// and mesh VPNs).
func isInternalIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true // 100.64.0.0/10
	}
	return false
}

// dnsResolver builds a resolver that dials a specific DNS server (defaulting to
// port 53), used for internal reverse-DNS.
func dnsResolver(addr string) *net.Resolver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
		},
	}
}
