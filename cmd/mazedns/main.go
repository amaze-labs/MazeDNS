// Command mazedns runs the MazeDNS filtering resolver and HTTP control plane.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/api"
	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/classifier"
	"github.com/IPMaze/MazeDNS/internal/cluster"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/lists"
	"github.com/IPMaze/MazeDNS/internal/metrics"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfgPath := flag.String("config", "configs/mazedns.yaml", "path to the YAML config file")
	modeFlag := flag.String("mode", "", "run mode: master (default, with web UI) or worker")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	slog.SetDefault(newLogger(cfg.Log.Level))

	mode := firstNonEmpty(*modeFlag, os.Getenv("MAZEDNS_MODE"), "master")
	if mode != "master" && mode != "worker" {
		slog.Error("invalid mode (want master|worker)", "mode", mode)
		os.Exit(1)
	}
	worker := mode == "worker"
	slog.Info("MazeDNS starting", "version", version, "mode", mode)

	// Datastore.
	st, err := store.Open(cfg.Database.Path)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	slog.Info("store ready", "path", cfg.Database.Path)

	// Auth (master only): bootstrap admin + optional OIDC.
	authMgr := auth.NewManager(st, nil, cfg.Auth.SessionTTL.Std())
	if !worker && cfg.Auth.Enabled {
		if err := bootstrapAdmin(st, cfg.Auth.Admin); err != nil {
			slog.Error("bootstrap admin", "err", err)
			os.Exit(1)
		}
		var oidcProvider *auth.OIDCProvider
		if cfg.Auth.OIDC.Enabled {
			p, oerr := auth.NewOIDC(context.Background(), cfg.Auth.OIDC)
			if oerr != nil {
				slog.Error("oidc init failed; continuing without SSO", "err", oerr)
			} else {
				oidcProvider = p
				// Log the exact redirect_uri we send the provider — it must match
				// the one registered there *character for character* (a common
				// cause of "mismatching redirect_uri").
				slog.Info("oidc enabled", "issuer", cfg.Auth.OIDC.Issuer, "redirect_uri", cfg.Auth.OIDC.RedirectURL)
				if cfg.Auth.OIDC.RedirectURL == "" {
					slog.Warn("oidc redirect_url is empty — set auth.oidc.redirect_url or MAZEDNS_OIDC_REDIRECT_URL")
				}
			}
		}
		authMgr = auth.NewManager(st, oidcProvider, cfg.Auth.SessionTTL.Std())
		slog.Info("auth enabled", "oidc", oidcProvider != nil)
	}

	mx := metrics.New()

	// Async query-log writer.
	qlog := store.NewQueryLogWriter(st, 4096)
	defer qlog.Close()

	// Optional LLM classifier worker (set below, master only); referenced here so
	// every query name can be fed to it for background classification.
	var clsWorker *classifier.Worker

	res := resolver.New(resolver.Options{
		Timeout:  5 * time.Second,
		Zones:    toZoneSpecs(cfg.Zones),
		QueryLog: cfg.Log.QueryLog,
		Metrics:  mx,
		OnQuery: func(ev resolver.QueryEvent) {
			qlog.Write(store.QueryLogEntry{
				TS:        ev.TS.UnixMilli(),
				Client:    ev.Client,
				Name:      ev.Name,
				QType:     ev.QType,
				Action:    ev.Action,
				Category:  ev.Category,
				Rcode:     ev.Rcode,
				ElapsedMS: float64(ev.Elapsed.Microseconds()) / 1000.0,
			})
			if clsWorker != nil {
				clsWorker.Enqueue(ev.Name)
			}
		},
	})
	// Operational settings: the DB is the source of truth, seeded from the config
	// file on first run, then managed live from the UI.
	res.ApplySettings(loadOrSeedSettings(st, cfg))
	// Restore any active block-pause across restarts.
	if ts, _ := st.GetBlockPausedUntil(); ts > 0 {
		res.SetBlockPausedUntil(ts)
	}

	// Build the filtering/rewrite policy from file blocklists + DB rules/rewrites.
	buildPolicy := func() (*resolver.Policy, error) {
		block := filter.New()
		if cfg.Filter.Enabled {
			for _, path := range cfg.Filter.BlocklistFiles {
				// Tag file-loaded domains with the list's own name (its basename)
				// rather than "custom", so they are distinguishable from the
				// user's manually-added "custom" rules in stats and the UI.
				cat := listCategory(path)
				if n, lerr := block.LoadHostsFile(path, cat); lerr != nil {
					slog.Warn("blocklist load failed", "file", path, "err", lerr)
				} else {
					slog.Info("blocklist loaded", "file", path, "category", cat, "domains", n)
				}
			}
		}
		allow := filter.New()
		rules, rerr := st.ActiveRules()
		if rerr != nil {
			return nil, rerr
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
		// Enforced AI verdicts (auto-blocked or user-approved) join the block set,
		// tagged "ai" so they're attributable in the dashboard.
		if aiBlocked, aerr := st.ActiveAIBlocked(); aerr == nil {
			for _, c := range aiBlocked {
				block.Add(c.Domain, "ai")
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
			t, ok := rrType(rw.RRType)
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
		return &resolver.Policy{Block: block, Allow: allow, Rewrites: rewrites, Wildcards: wildcards}, nil
	}

	reload := func() error {
		p, perr := buildPolicy()
		if perr != nil {
			return perr
		}
		res.SetPolicy(p)
		slog.Info("policy reloaded", "blocked", p.Block.Len(), "allowed", p.Allow.Len(), "rewrites", len(p.Rewrites))
		return nil
	}
	if err := reload(); err != nil {
		slog.Error("build policy", "err", err)
		os.Exit(1)
	}

	// Master: LLM domain classifier. The worker always runs (it no-ops while
	// disabled) so the feature can be turned on/repointed live from the Settings
	// UI without a restart. Config seeds the persisted settings on first run.
	if !worker {
		defaults := classifier.Settings{
			Enabled:               cfg.Classifier.Enabled,
			Endpoint:              cfg.Classifier.Endpoint,
			Model:                 cfg.Classifier.Model,
			APIKey:                cfg.Classifier.APIKey,
			Mode:                  cfg.Classifier.Mode,
			MinGapMS:              cfg.Classifier.MinGapMS,
			TimeoutSec:            cfg.Classifier.TimeoutSec,
			TrustedListURL:        cfg.Classifier.TrustedListURL,
			TrustedTopN:           cfg.Classifier.TrustedTopN,
			TrustedDisableDefault: cfg.Classifier.TrustedDisableDefault,
			ThreatListURL:         cfg.Classifier.ThreatListURL,
			ThreatDisableDefault:  cfg.Classifier.ThreatDisableDefault,
			WhoisEnabled:          cfg.Classifier.WhoisEnabled,
		}
		if cur, _ := st.GetMeta(classifier.SettingsKey); cur == "" {
			_ = classifier.SaveSettings(st, defaults)
		}
		getSettings := func() classifier.Settings { return classifier.LoadSettings(st, defaults) }
		clsWorker = classifier.NewWorker(st, getSettings, reload)
		go clsWorker.Run(context.Background())
		slog.Info("classifier ready", "enabled", getSettings().Enabled)
	}

	// Master: optionally pre-provision cluster nodes with fixed keys (handy for
	// dev/automated clustering). Format: "name1=key1,name2=key2".
	if !worker {
		bootstrapNodes(st, os.Getenv("MAZEDNS_CLUSTER_BOOTSTRAP_NODES"))
	}

	// Worker: replicate config from the master.
	var agentCancel context.CancelFunc
	if worker && cfg.Cluster.Enabled && cfg.Cluster.MasterURL != "" && cfg.Cluster.NodeKey != "" {
		var agentCtx context.Context
		agentCtx, agentCancel = context.WithCancel(context.Background())
		statsFn := func() store.NodeStats {
			t, b, ca, fwd, rw, e := res.StatsSnapshot()
			return store.NodeStats{
				Total: int64(t), Blocked: int64(b), Cached: int64(ca),
				Forwarded: int64(fwd), Rewritten: int64(rw), Errors: int64(e),
			}
		}
		ag := cluster.NewAgent(cfg.Cluster.MasterURL, cfg.Cluster.MasterIP, cfg.Cluster.NodeKey, cfg.Cluster.Interval.Std(), st, reload, statsFn, res.SetBlockPausedUntil)
		go ag.Run(agentCtx)
	}

	// Master: auto-refresh URL-backed rule lists on their schedule.
	refresher := lists.NewRefresher(st, reload)
	if !worker {
		go refresher.Run(context.Background())
	}

	// Bound query-log growth: the master keeps the full dashboard window (it also
	// ingests workers' shipped logs); a worker only needs a short buffer before
	// shipping. Pruning runs hourly, off the DNS path.
	retention := 90 * 24 * time.Hour
	if worker {
		retention = 48 * time.Hour
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			if n, err := st.PruneQueryLog(time.Now().Add(-retention).UnixMilli()); err == nil && n > 0 {
				slog.Info("query log pruned", "removed", n)
			}
		}
	}()

	// DNS server (UDP/TCP).
	dnsAddr := net.JoinHostPort(cfg.Listen.Address, strconv.Itoa(cfg.Listen.Port))
	dnsSrv := resolver.NewServer(dnsAddr, res)
	go func() {
		slog.Info("MazeDNS DNS starting", "addr", dnsAddr, "upstreams", cfg.Upstreams,
			"cache", cfg.Cache.Enabled, "filter", cfg.Filter.Enabled, "ratelimit", cfg.RateLimit.Enabled)
		if serveErr := dnsSrv.ListenAndServe(); serveErr != nil {
			slog.Error("dns server stopped", "err", serveErr)
			os.Exit(1)
		}
	}()

	// Encrypted DNS endpoints (DoT/DoH), driven by config in either mode.
	var dotSrv *dns.Server
	var dohSrv *http.Server
	if cfg.DoT.Enabled || cfg.DoH.Enabled {
		cert, selfSigned, cerr := resolver.TLSCert(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if cerr != nil {
			slog.Error("tls cert", "err", cerr)
			os.Exit(1)
		}
		if selfSigned {
			slog.Warn("using a self-signed TLS certificate for encrypted DNS")
		}
		if cfg.DoT.Enabled {
			addr := net.JoinHostPort(cfg.DoT.Address, strconv.Itoa(cfg.DoT.Port))
			dotSrv = resolver.NewDoTServer(addr, cert, res)
			go func() {
				slog.Info("MazeDNS DoT starting", "addr", addr)
				if e := dotSrv.ListenAndServe(); e != nil {
					slog.Error("dot server stopped", "err", e)
				}
			}()
		}
		if cfg.DoH.Enabled {
			addr := net.JoinHostPort(cfg.DoH.Address, strconv.Itoa(cfg.DoH.Port))
			dohSrv = resolver.NewDoHServer(addr, cfg.DoH.Path, cert, res)
			go func() {
				slog.Info("MazeDNS DoH starting", "addr", addr, "path", cfg.DoH.Path)
				if e := dohSrv.ListenAndServeTLS("", ""); e != nil && e != http.ErrServerClosed {
					slog.Error("doh server stopped", "err", e)
				}
			}()
		}
	}

	// HTTP server: master serves API + UI + metrics + the cluster control plane
	// (node enrollment is always available so operators can add workers from the
	// UI); worker serves only /healthz + /metrics.
	var apiSrv *api.Server
	if cfg.API.Enabled {
		apiAddr := net.JoinHostPort(cfg.API.Address, strconv.Itoa(cfg.API.Port))
		apiSrv = api.New(apiAddr, st, res, mx, reload, refresher, authMgr, cfg.Auth.Enabled && !worker, worker, !worker)
		if clsWorker != nil {
			apiSrv.SetClassifierStatus(clsWorker.TrustedCount, clsWorker.ThreatCount, clsWorker.TrustedSearch, clsWorker.Whois)
		}
		go func() {
			slog.Info("MazeDNS HTTP starting", "addr", apiAddr, "mode", mode)
			if serveErr := apiSrv.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
				slog.Error("http server stopped", "err", serveErr)
			}
		}()
	}

	// Periodic stats line.
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			t, b, ca, fwd, rw, e := res.StatsSnapshot()
			slog.Info("stats", "total", t, "blocked", b, "cached", ca, "forwarded", fwd, "rewritten", rw, "errors", e)
		}
	}()

	// Wait for a termination signal, then shut down gracefully.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	slog.Info("shutting down")
	if agentCancel != nil {
		agentCancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dnsSrv.Shutdown(ctx)
	if dotSrv != nil {
		_ = dotSrv.ShutdownContext(ctx)
	}
	if dohSrv != nil {
		_ = dohSrv.Shutdown(ctx)
	}
	if apiSrv != nil {
		_ = apiSrv.Shutdown(ctx)
	}
}

// listCategory derives a blocklist's category label from its filename, e.g.
// "/etc/mazedns/stevenblack.hosts" -> "stevenblack". This keeps file-sourced
// blocks separate from the user's "custom" rules. Falls back to "blocklist".
func listCategory(path string) string {
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

func toZoneSpecs(zs []config.Zone) []resolver.ZoneSpec {
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

// bootstrapNodes pre-provisions cluster nodes from a "name=key,name=key" spec
// so workers can be wired up without manual UI enrollment (e.g. in dev compose).
// Keys are stored hashed, exactly like UI-issued ones.
func bootstrapNodes(st *store.Store, spec string) {
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, key, ok := strings.Cut(pair, "=")
		name, key = strings.TrimSpace(name), strings.TrimSpace(key)
		if !ok || name == "" || key == "" {
			slog.Warn("ignoring malformed bootstrap node (want name=key)", "entry", pair)
			continue
		}
		sum := sha256.Sum256([]byte(key))
		prefix := key
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		if err := st.EnsureNode(name, hex.EncodeToString(sum[:]), prefix); err != nil {
			slog.Warn("bootstrap node failed", "name", name, "err", err)
			continue
		}
		slog.Info("cluster node provisioned", "name", name)
	}
}

func settingsFromConfig(cfg config.Config) resolver.Settings {
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

// loadOrSeedSettings returns the DB-stored operational settings, seeding them
// from the config file the first time (so the file is just initial defaults).
func loadOrSeedSettings(st *store.Store, cfg config.Config) resolver.Settings {
	if raw, _ := st.GetSettings(); raw != "" {
		var s resolver.Settings
		if json.Unmarshal([]byte(raw), &s) == nil {
			return s
		}
	}
	s := settingsFromConfig(cfg)
	if b, err := json.Marshal(s); err == nil {
		_ = st.SaveSettings(string(b))
	}
	return s
}

// bootstrapAdmin creates the first admin if no users exist. Username/password
// come from config or MAZEDNS_ADMIN_USERNAME / MAZEDNS_ADMIN_PASSWORD; a missing
// password is generated and logged once.
func bootstrapAdmin(st *store.Store, a config.AdminBootstrap) error {
	n, err := st.CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	username := firstNonEmpty(a.Username, os.Getenv("MAZEDNS_ADMIN_USERNAME"), "admin")
	password := firstNonEmpty(a.Password, os.Getenv("MAZEDNS_ADMIN_PASSWORD"))
	generated := false
	if password == "" {
		tok, terr := auth.NewToken()
		if terr != nil {
			return terr
		}
		password = tok[:16]
		generated = true
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := st.CreateLocalUser(username, hash, "admin"); err != nil {
		return err
	}
	if generated {
		slog.Warn("bootstrap admin created with a GENERATED password — log in and change it",
			"username", username, "password", password)
	} else {
		slog.Info("bootstrap admin created", "username", username)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func rrType(s string) (uint16, bool) {
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

func newLogger(level string) *slog.Logger {
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
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
