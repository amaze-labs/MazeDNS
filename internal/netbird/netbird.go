// Package netbird enriches a client IP with a human-friendly identity. When the
// NetBird integration is enabled it maps the IP to its NetBird peer (name +
// hostname) via the NetBird REST API; otherwise (and as a fallback) it does a
// reverse-DNS (PTR) lookup. This is what turns a bare "100.x.y.z" in the query
// log into "alice-laptop" in the UI.
package netbird

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// SettingsKey is the app_meta key under which the NetBird settings are persisted
// (configured on the Settings page, not via env vars).
const SettingsKey = "netbird_settings"

// Settings is the UI-editable NetBird configuration.
type Settings struct {
	Enabled bool   `json:"enabled"`
	APIURL  string `json:"api_url"` // e.g. https://api.netbird.io (or a self-hosted management URL)
	Token   string `json:"token"`   // NetBird PAT (Authorization: Token <token>)
}

func (s Settings) baseURL() string { return strings.TrimRight(strings.TrimSpace(s.APIURL), "/") }

// LoadSettings reads the persisted NetBird settings (def when unset / unparseable).
func LoadSettings(st *store.Store, def Settings) Settings {
	raw, err := st.GetMeta(SettingsKey)
	if err != nil || raw == "" {
		return def
	}
	var s Settings
	if json.Unmarshal([]byte(raw), &s) != nil {
		return def
	}
	return s
}

// SaveSettings persists the NetBird settings.
func SaveSettings(st *store.Store, s Settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.SetMeta(SettingsKey, string(b))
}

// Identity is the resolved name for a client IP.
type Identity struct {
	Name   string `json:"name"`   // display name (peer name or PTR hostname)
	Source string `json:"source"` // "netbird" | "rdns" | ""
}

// peer is the subset of a NetBird API peer object we use.
type peer struct {
	IP       string `json:"ip"`
	Name     string `json:"name"`
	DNSLabel string `json:"dns_label"`
	Hostname string `json:"hostname"`
}

// Enricher holds the live NetBird peer map (refreshed in the background) and the
// reverse-DNS cache, both keyed by client IP. For reverse-DNS it also tracks which
// node serves each client, so an internal client is resolved against that node's
// site resolver (nodes can be in different sites).
type Enricher struct {
	get       func() Settings
	resolvers func() map[string]string // node name -> internal DNS resolver
	store     *store.Store

	mu     sync.RWMutex
	peers  map[string]Identity // ip -> netbird identity
	cnode  map[string]string   // client ip -> node that serves it
	manual map[string]string   // client ip -> operator-assigned static hostname

	rdnsMu sync.Mutex
	rdns   map[string]rdnsEntry // ip -> cached PTR lookup
}

type rdnsEntry struct {
	name string
	exp  time.Time
}

// NewEnricher builds an enricher. get supplies the live NetBird settings;
// resolvers supplies the per-node internal DNS resolver map; st is used to learn
// which node serves each client (for picking that node's resolver).
func NewEnricher(get func() Settings, resolvers func() map[string]string, st *store.Store) *Enricher {
	return &Enricher{
		get: get, resolvers: resolvers, store: st,
		peers: map[string]Identity{}, cnode: map[string]string{}, manual: map[string]string{}, rdns: map[string]rdnsEntry{},
	}
}

// Run refreshes the NetBird peer map periodically until ctx is cancelled. It is a
// no-op (clearing the map) while the integration is disabled.
func (e *Enricher) Run(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	e.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.refresh(ctx)
		}
	}
}

func (e *Enricher) refresh(ctx context.Context) {
	// Refresh which node serves each client (used to pick that node's resolver for
	// internal reverse-DNS). Done regardless of NetBird being enabled.
	if e.store != nil {
		manual := LoadClientNames(e.store)
		if cn, err := e.store.ClientNodes(time.Now().Add(-24 * time.Hour).UnixMilli()); err == nil {
			e.mu.Lock()
			e.cnode = cn
			e.manual = manual
			e.mu.Unlock()
		} else {
			e.mu.Lock()
			e.manual = manual
			e.mu.Unlock()
		}
	}

	s := e.get()
	if !s.Enabled || s.baseURL() == "" || s.Token == "" {
		e.mu.Lock()
		e.peers = map[string]Identity{}
		e.mu.Unlock()
		return
	}
	peers, err := fetchPeers(ctx, s)
	if err != nil {
		return // keep the previous map on a transient error
	}
	m := make(map[string]Identity, len(peers))
	for _, p := range peers {
		if p.IP == "" {
			continue
		}
		name := firstNonEmpty(p.Name, p.Hostname, p.DNSLabel)
		m[p.IP] = Identity{Name: name, Source: "netbird"}
	}
	e.mu.Lock()
	e.peers = m
	e.mu.Unlock()
}

// Lookup resolves a client IP to an identity: a NetBird peer if known, otherwise
// a (cached) reverse-DNS hostname. Returns a zero Identity if nothing is found.
func (e *Enricher) Lookup(ctx context.Context, ip string) Identity {
	ip = clientIP(ip)
	if ip == "" {
		return Identity{}
	}
	// Operator-assigned static names win over everything else.
	e.mu.RLock()
	name := e.manual[ip]
	id, ok := e.peers[ip]
	e.mu.RUnlock()
	if name != "" {
		return Identity{Name: name, Source: "manual"}
	}
	if ok && id.Name != "" {
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

// PeerCount reports how many NetBird peers are currently mapped (for the UI / test).
func (e *Enricher) PeerCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.peers)
}

// FetchPeerCount validates settings by hitting the API once, returning the peer
// count (used by the Settings "Test connection" button).
func FetchPeerCount(ctx context.Context, s Settings) (int, error) {
	if s.baseURL() == "" || s.Token == "" {
		return 0, fmt.Errorf("API URL and token are required")
	}
	peers, err := fetchPeers(ctx, s)
	if err != nil {
		return 0, err
	}
	return len(peers), nil
}

func fetchPeers(ctx context.Context, s Settings) ([]peer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL()+"/api/peers", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+strings.TrimSpace(s.Token))
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netbird: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var peers []peer
	if err := json.Unmarshal(body, &peers); err != nil {
		return nil, fmt.Errorf("netbird: bad response: %w", err)
	}
	return peers, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
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
// loopback, link-local, unique-local, or the 100.64/10 CGNAT block NetBird uses.
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
