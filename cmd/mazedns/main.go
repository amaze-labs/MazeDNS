// Command mazedns runs the MazeDNS filtering resolver and HTTP control plane.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/api"
	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/cache"
	"github.com/IPMaze/MazeDNS/internal/cluster"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/filter"
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
				slog.Info("oidc enabled", "issuer", cfg.Auth.OIDC.Issuer)
			}
		}
		authMgr = auth.NewManager(st, oidcProvider, cfg.Auth.SessionTTL.Std())
		slog.Info("auth enabled", "oidc", oidcProvider != nil)
	}

	mx := metrics.New()

	// Async query-log writer.
	qlog := store.NewQueryLogWriter(st, 4096)
	defer qlog.Close()

	// Response cache.
	var c *cache.Cache
	if cfg.Cache.Enabled {
		c = cache.New(cfg.Cache.MaxEntries, cfg.Cache.MinTTL.Std(), cfg.Cache.MaxTTL.Std())
	}

	res := resolver.New(resolver.Options{
		Upstreams:     cfg.Upstreams,
		Forwarders:    toForwardGroups(cfg.Forwarders),
		Zones:         toZoneSpecs(cfg.Zones),
		RateLimitQPM:  rateLimitQPM(cfg.RateLimit),
		ForceDNSSEC:   cfg.DNSSEC.Enabled,
		Cache:         c,
		BlockResponse: cfg.Filter.BlockResponse,
		QueryLog:      cfg.Log.QueryLog,
		Metrics:       mx,
		OnQuery: func(ev resolver.QueryEvent) {
			qlog.Write(store.QueryLogEntry{
				TS:        ev.TS.UnixMilli(),
				Client:    ev.Client,
				Name:      ev.Name,
				QType:     ev.QType,
				Action:    ev.Action,
				Rcode:     ev.Rcode,
				ElapsedMS: ev.Elapsed.Milliseconds(),
			})
		},
	})

	// Build the filtering/rewrite policy from file blocklists + DB rules/rewrites.
	buildPolicy := func() (*resolver.Policy, error) {
		block := filter.New()
		if cfg.Filter.Enabled {
			for _, path := range cfg.Filter.BlocklistFiles {
				if n, lerr := block.LoadHostsFile(path); lerr != nil {
					slog.Warn("blocklist load failed", "file", path, "err", lerr)
				} else {
					slog.Info("blocklist loaded", "file", path, "domains", n)
				}
			}
		}
		allow := filter.New()
		rules, rerr := st.ListRules()
		if rerr != nil {
			return nil, rerr
		}
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			if rule.Action == "deny" {
				block.Add(rule.Domain)
			} else {
				allow.Add(rule.Domain)
			}
		}
		rewrites := map[string][]resolver.RewriteRR{}
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
			rewrites[key] = append(rewrites[key], resolver.RewriteRR{Type: t, Value: rw.Value})
		}
		return &resolver.Policy{Block: block, Allow: allow, Rewrites: rewrites}, nil
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

	// Worker: replicate config from the master.
	var agentCancel context.CancelFunc
	if worker && cfg.Cluster.Enabled && cfg.Cluster.MasterURL != "" {
		nodeName := cfg.Cluster.NodeName
		if nodeName == "" {
			nodeName, _ = os.Hostname()
		}
		var agentCtx context.Context
		agentCtx, agentCancel = context.WithCancel(context.Background())
		ag := cluster.NewAgent(cfg.Cluster.MasterURL, cfg.Cluster.Token, nodeName, cfg.Cluster.Interval.Std(), st, reload)
		go ag.Run(agentCtx)
	}

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

	// HTTP server: master serves API + UI + metrics (+ cluster snapshot when a
	// cluster token is set); worker serves only /healthz + /metrics.
	clusterToken := ""
	if cfg.Cluster.Enabled {
		clusterToken = cfg.Cluster.Token
	}
	var apiSrv *api.Server
	if cfg.API.Enabled {
		apiAddr := net.JoinHostPort(cfg.API.Address, strconv.Itoa(cfg.API.Port))
		apiSrv = api.New(apiAddr, st, res, mx, reload, authMgr, cfg.Auth.Enabled && !worker, worker, clusterToken)
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
