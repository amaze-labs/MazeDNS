// Package boot holds startup helpers shared by the control-plane and dns-agent
// entrypoints: logging, GC tuning, store opening, config→resolver conversions,
// and the filtering/rewrite policy builder.
package boot

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/logbuf"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// NewLogger returns a text logger at the given level (info by default). When
// ring is non-nil, every emitted line is also captured there so recent process
// logs can be served to (control plane) or shipped to (agent) the dashboard.
func NewLogger(level string, ring *logbuf.Buffer) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	var h slog.Handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	if ring != nil {
		h = logbuf.NewHandler(h, ring)
	}
	return slog.New(h)
}

// TuneGC applies a less aggressive default GC unless the operator set GOGC. The
// cache copies a message on every hit, so this trades a little memory (already
// bounded by the cache size) for fewer GC cycles and less tail-latency jitter.
func TuneGC() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(200)
	}
}

// FirstNonEmpty returns the first non-empty string.
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// OpenStore opens the datastore selected by the config: embedded SQLite by
// default, or an external PostgreSQL server when Database.Driver is postgres/pgx.
func OpenStore(cfg config.Config) (*store.Store, error) {
	switch cfg.Database.Driver {
	case "postgres", "pgx":
		return store.OpenWith("pgx", cfg.Database.DSN)
	default:
		return store.Open(cfg.Database.Path)
	}
}

// StoreBackend returns a short label for logging.
func StoreBackend(cfg config.Config) string {
	if cfg.Database.Driver == "postgres" || cfg.Database.Driver == "pgx" {
		return "postgres"
	}
	return "sqlite"
}

// RRType maps a rewrite record type string to its DNS type code.
func RRType(s string) (uint16, bool) {
	switch s {
	case "A":
		return dns.TypeA, true
	case "AAAA":
		return dns.TypeAAAA, true
	case "CNAME":
		return dns.TypeCNAME, true
	}
	return 0, false
}

// ToZoneSpecs converts config zones to resolver zone specs.
func ToZoneSpecs(zs []config.Zone) []resolver.ZoneSpec {
	out := make([]resolver.ZoneSpec, 0, len(zs))
	for _, z := range zs {
		recs := make([]resolver.ZoneRecordSpec, 0, len(z.Records))
		for _, r := range z.Records {
			recs = append(recs, resolver.ZoneRecordSpec{Name: r.Name, Type: r.Type, Value: r.Value, TTL: r.TTL})
		}
		out = append(out, resolver.ZoneSpec{Name: z.Name, Records: recs})
	}
	return out
}

func toForwardGroups(fs []config.Forwarder) []resolver.ForwardGroup {
	out := make([]resolver.ForwardGroup, 0, len(fs))
	for _, f := range fs {
		out = append(out, resolver.ForwardGroup{Suffix: f.Suffix, Upstreams: f.Upstreams})
	}
	return out
}

func rateLimitQPM(rl config.RateLimit) int {
	if !rl.Enabled {
		return 0
	}
	return rl.QPM
}

// SettingsFromConfig maps the file config to the resolver's operational settings.
func SettingsFromConfig(cfg config.Config) resolver.Settings {
	return resolver.Settings{
		Upstreams:     cfg.Upstreams,
		Forwarders:    toForwardGroups(cfg.Forwarders),
		BlockResponse: cfg.Filter.BlockResponse,
		RateLimitQPM:  rateLimitQPM(cfg.RateLimit),
		DNSSEC:        cfg.DNSSEC.Enabled,
		Cache: resolver.CacheSettings{
			Enabled:    cfg.Cache.Enabled,
			MaxEntries: cfg.Cache.MaxEntries,
			MinTTLSec:  int(cfg.Cache.MinTTL.Std().Seconds()),
			MaxTTLSec:  int(cfg.Cache.MaxTTL.Std().Seconds()),
		},
	}
}

// LoadOrSeedSettings returns the DB-stored operational settings, seeding them
// from the config file the first time (so the file is just initial defaults).
func LoadOrSeedSettings(st *store.Store, cfg config.Config) resolver.Settings {
	if raw, _ := st.GetSettings(); raw != "" {
		var s resolver.Settings
		if json.Unmarshal([]byte(raw), &s) == nil {
			return s
		}
	}
	s := SettingsFromConfig(cfg)
	if b, err := json.Marshal(s); err == nil {
		_ = st.SaveSettings(string(b))
	}
	return s
}

// MergeForwarders overlays centrally-pushed conditional forwarders onto a
// node's local settings. The central entry wins when both define the same
// normalized suffix; non-conflicting local entries survive. The merge happens
// at apply time only — central entries are never persisted into the node's
// saved settings, so deleting one centrally restores local behavior.
func MergeForwarders(s resolver.Settings, central []store.ForwardSpec) resolver.Settings {
	if len(central) == 0 {
		return s
	}
	merged := make([]resolver.ForwardGroup, 0, len(central)+len(s.Forwarders))
	taken := make(map[string]bool, len(central))
	for _, f := range central {
		key := filter.Normalize(f.Suffix)
		if key == "" || taken[key] {
			continue
		}
		taken[key] = true
		merged = append(merged, resolver.ForwardGroup{Suffix: key, Upstreams: f.Upstreams})
	}
	for _, g := range s.Forwarders {
		if !taken[filter.Normalize(g.Suffix)] {
			merged = append(merged, g)
		}
	}
	s.Forwarders = merged
	return s
}

// EffectiveSettings returns what the resolver should actually run: the node's
// local (seeded/DB) settings with the centrally-pushed forwarders merged in.
func EffectiveSettings(st *store.Store, cfg config.Config) resolver.Settings {
	s := LoadOrSeedSettings(st, cfg)
	fws, err := st.ClusterForwarders()
	if err != nil {
		slog.Warn("load cluster forwarders", "err", err)
		return s
	}
	return MergeForwarders(s, fws)
}

// ListCategory derives a blocklist's category label from its filename, e.g.
// "/etc/mazedns/stevenblack.hosts" -> "stevenblack". This keeps file-sourced
// blocks separate from the user's "custom" rules. Falls back to "blocklist".
func ListCategory(path string) string {
	base := strings.TrimLeft(filepath.Base(path), ".")
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToLower(strings.TrimSpace(base))
	if base == "" {
		return "blocklist"
	}
	return base
}

// BuildPolicy assembles the resolver's filtering/rewrite policy from file
// blocklists plus the DB's rules, enforced AI verdicts, and rewrites. Both the
// control plane (headless resolver) and agents build it identically; on an agent
// the classifications table is empty, so enforced AI blocks arrive as replicated
// deny rules instead.
func BuildPolicy(st *store.Store, cfg config.Config) (*resolver.Policy, error) {
	block := filter.New()
	if cfg.Filter.Enabled {
		for _, path := range cfg.Filter.BlocklistFiles {
			cat := ListCategory(path)
			if n, lerr := block.LoadHostsFile(path, cat); lerr != nil {
				slog.Warn("blocklist load failed", "file", path, "err", lerr)
			} else {
				slog.Info("blocklist loaded", "file", path, "category", cat, "domains", n)
			}
		}
	}
	allow := filter.New()
	rules, err := st.ActiveRules()
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.Action == "deny" {
			block.Add(rule.Domain, rule.Category)
		} else {
			allow.Add(rule.Domain, "")
		}
	}
	if aiBlocked, aerr := st.ActiveAIBlocked(); aerr == nil {
		for _, c := range aiBlocked {
			cat := c.Category
			if cat == "" {
				cat = "ai"
			}
			block.Add(c.Domain, cat)
		}
	} else {
		slog.Warn("load ai classifications", "err", aerr)
	}
	rewrites := map[string][]resolver.RewriteRR{}
	wildcards := map[string][]resolver.RewriteRR{}
	rws, werr := st.ListRewrites()
	if werr != nil {
		return nil, werr
	}
	for _, rw := range rws {
		if !rw.Enabled {
			continue
		}
		t, ok := RRType(rw.RRType)
		if !ok {
			continue
		}
		key := filter.Normalize(rw.Domain)
		rr := resolver.RewriteRR{Type: t, Value: rw.Value}
		if base, isWild := strings.CutPrefix(key, "*."); isWild {
			wildcards[base] = append(wildcards[base], rr)
		} else {
			rewrites[key] = append(rewrites[key], rr)
		}
	}
	// Freeze the engines: they are now fully built and about to be published
	// read-only, so the resolver can match against them lock-free on the hot path.
	block.Seal()
	allow.Seal()
	return &resolver.Policy{Block: block, Allow: allow, Rewrites: rewrites, Wildcards: wildcards}, nil
}
