// Command control-plane runs the MazeDNS control plane: the HTTP API, web UI,
// auth, domain classifier, list refresher, cluster coordination, and dashboard
// aggregation. It never serves DNS — every query is answered by the dns-agent
// fleet — so control-plane load (dashboards, stats, classification) cannot affect
// resolver latency.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/IPMaze/MazeDNS/internal/api"
	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/boot"
	"github.com/IPMaze/MazeDNS/internal/classifier"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/lists"
	"github.com/IPMaze/MazeDNS/internal/metrics"
	"github.com/IPMaze/MazeDNS/internal/netbird"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
	"github.com/IPMaze/MazeDNS/internal/victorialogs"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfgPath := flag.String("config", "configs/mazedns.yaml", "path to the YAML config file")
	flag.Parse()

	boot.TuneGC()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	slog.SetDefault(boot.NewLogger(cfg.Log.Level))
	slog.Info("MazeDNS control plane starting", "version", version)

	st, err := boot.OpenStore(cfg)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	slog.Info("store ready", "backend", boot.StoreBackend(cfg), "path", cfg.Database.Path)

	// Record the control plane's own reachable address (cluster.advertise_addr /
	// MAZEDNS_ADVERTISE_ADDR). It is handed to each agent at enrollment and pinned
	// locally, so a node keeps reaching the control plane by its fixed IP even if
	// DNS/hostname resolution later breaks.
	if cfg.Cluster.AdvertiseAddr != "" {
		_ = st.SetMasterAdvertiseAddr(cfg.Cluster.AdvertiseAddr)
		slog.Info("control-plane advertise address set", "addr", cfg.Cluster.AdvertiseAddr)
	}

	// Auth: bootstrap admin + optional OIDC.
	authMgr := auth.NewManager(st, nil, cfg.Auth.SessionTTL.Std())
	if cfg.Auth.Enabled {
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

	// The control plane keeps a headless resolver purely so the API can apply
	// operational settings, the block-pause deadline, and report per-process stats.
	// No DNS/DoT/DoH listener is ever started, so it stays off the query path.
	res := resolver.New(resolver.Options{
		Timeout: 5 * time.Second,
		Zones:   boot.ToZoneSpecs(cfg.Zones),
		Metrics: mx,
	})
	res.ApplySettings(boot.LoadOrSeedSettings(st, cfg))
	if ts, _ := st.GetBlockPausedUntil(); ts > 0 {
		res.SetBlockPausedUntil(ts)
	}

	reload := func() error {
		p, perr := boot.BuildPolicy(st, cfg)
		if perr != nil {
			return perr
		}
		res.SetPolicy(p)
		return nil
	}
	if err := reload(); err != nil {
		slog.Error("build policy", "err", err)
		os.Exit(1)
	}

	// Domain classifier. On the control plane its live feed of newly-seen domains
	// comes from agents' shipped query logs (wired into the API below), not from a
	// local resolver.
	clsWorker := newClassifier(st, cfg, reload)
	go clsWorker.Run(context.Background())
	slog.Info("classifier ready")

	// Optionally pre-provision cluster nodes with fixed keys (dev/automation).
	bootstrapNodes(st, os.Getenv("MAZEDNS_CLUSTER_BOOTSTRAP_NODES"))

	// NetBird/reverse-DNS client enricher (turns client IPs into peer/hostnames).
	enricher := netbird.NewEnricher(
		func() netbird.Settings { return netbird.LoadSettings(st, netbird.Settings{}) },
		func() map[string]string { return netbird.LoadResolvers(st) },
		st,
	)
	go enricher.Run(context.Background())

	// Auto-refresh URL-backed rule lists on their schedule.
	refresher := lists.NewRefresher(st, reload)
	go refresher.Run(context.Background())

	// Retention + rollups: the control plane holds the cluster-wide query log
	// (ingested from every agent), so it owns pruning and the dashboard rollups.
	retention := 30 * 24 * time.Hour
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			if n, err := st.PruneQueryLog(time.Now().Add(-retention).UnixMilli()); err == nil && n > 0 {
				slog.Info("query log pruned", "removed", n)
			}
			_ = st.PruneRollups(time.Now().Add(-retention).UnixMilli())
		}
	}()
	go func() {
		for {
			more, err := st.RollupAdvance(50000)
			if err != nil {
				slog.Warn("rollup advance failed", "err", err)
			}
			wait := 5 * time.Second
			if more {
				wait = 50 * time.Millisecond
			}
			time.Sleep(wait)
		}
	}()

	// VictoriaMetrics + VictoriaLogs export (control plane holds the cluster-wide view).
	startMetricsExport(st, cfg, mx)
	startLogsExport(st, cfg)

	// HTTP: API + UI + metrics + cluster control plane. Auth applies; cluster
	// endpoints (including token self-enrollment) are always available.
	apiAddr := net.JoinHostPort(cfg.API.Address, strconv.Itoa(cfg.API.Port))
	apiSrv := api.New(apiAddr, st, res, mx, reload, refresher, authMgr, cfg.Auth.Enabled, false, true)
	apiSrv.SetClusterEnrollment(cfg.Cluster.JoinToken, cfg.Cluster.RequireApproval)
	apiSrv.SetClassifierStatus(clsWorker)
	apiSrv.SetClassifierEnqueue(clsWorker.Enqueue)
	apiSrv.SetEnricher(enricher)
	if cfg.Cluster.JoinToken != "" {
		slog.Info("cluster self-enrollment enabled", "require_approval", cfg.Cluster.RequireApproval)
	}
	go func() {
		slog.Info("MazeDNS control-plane HTTP starting", "addr", apiAddr)
		if serveErr := apiSrv.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			slog.Error("http server stopped", "err", serveErr)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(ctx)
}

// newClassifier builds the classifier worker, seeding its persisted settings from
// the config file on first run.
func newClassifier(st *store.Store, cfg config.Config, reload func() error) *classifier.Worker {
	defaults := classifier.Settings{
		Enabled:               cfg.Classifier.Enabled,
		AIEnabled:             !cfg.Classifier.AIDisabled,
		Provider:              cfg.Classifier.Provider,
		Endpoint:              cfg.Classifier.Endpoint,
		Model:                 cfg.Classifier.Model,
		APIKey:                cfg.Classifier.APIKey,
		Mode:                  cfg.Classifier.Mode,
		MinGapMS:              cfg.Classifier.MinGapMS,
		TimeoutSec:            cfg.Classifier.TimeoutSec,
		TrustedListURL:        cfg.Classifier.TrustedListURL,
		TrustedTopN:           cfg.Classifier.TrustedTopN,
		TrustedDisableDefault: cfg.Classifier.TrustedDisableDefault,
		ThreatFeeds:           cfg.Classifier.ThreatFeeds,
		ThreatListURL:         cfg.Classifier.ThreatListURL,
		ThreatDisableDefault:  cfg.Classifier.ThreatDisableDefault,
		WhoisEnabled:          cfg.Classifier.WhoisEnabled,
		VTEnabled:             cfg.Classifier.VTEnabled,
		VTAPIKey:              cfg.Classifier.VTAPIKey,
		AbuseIPDBEnabled:      cfg.Classifier.AbuseIPDBEnabled,
		AbuseIPDBAPIKey:       cfg.Classifier.AbuseIPDBAPIKey,
	}
	if defaults.ThreatFeeds == nil {
		defaults.ThreatFeeds = classifier.DefaultThreatFeeds
	}
	if cur, _ := st.GetMeta(classifier.SettingsKey); cur == "" {
		_ = classifier.SaveSettings(st, defaults)
	}
	getSettings := func() classifier.Settings { return classifier.LoadSettings(st, defaults) }
	return classifier.NewWorker(st, getSettings, reload)
}

// startMetricsExport runs the VictoriaMetrics pusher (settings are UI-editable and
// re-read each cycle).
func startMetricsExport(st *store.Store, cfg config.Config, mx *metrics.Metrics) {
	vm := cfg.Metrics.VictoriaMetrics
	_ = st.EnsureVMExport(store.VMExport{
		Enabled: vm.Enabled, URL: vm.URL, IntervalSec: int(vm.Interval.Std().Seconds()),
		Job: vm.Job, Instance: vm.Instance, Username: vm.Username, Password: vm.Password,
	})
	hostname, _ := os.Hostname()
	get := func() metrics.VMConfig {
		v := st.LoadVMExport(store.VMExport{})
		return metrics.VMConfig{
			Enabled: v.Enabled, URL: v.URL, Interval: time.Duration(v.IntervalSec) * time.Second,
			Job: v.Job, Instance: v.Instance, Username: v.Username, Password: v.Password,
		}
	}
	go metrics.NewVMPusher(get, hostname, mx.Gatherer()).Run(context.Background())
}

// startLogsExport ships the cluster-wide query log to VictoriaLogs for retention
// beyond the local window.
func startLogsExport(st *store.Store, cfg config.Config) {
	vl := cfg.Metrics.VictoriaLogs
	_ = st.EnsureVLExport(store.VLExport{
		Enabled: vl.Enabled, URL: vl.URL, IntervalSec: int(vl.Interval.Std().Seconds()),
		Username: vl.Username, Password: vl.Password,
	})
	getVL := func() victorialogs.Config {
		v := st.LoadVLExport(store.VLExport{})
		return victorialogs.Config{
			Enabled: v.Enabled, URL: v.URL, Interval: time.Duration(v.IntervalSec) * time.Second,
			Username: v.Username, Password: v.Password,
		}
	}
	go victorialogs.NewExporter(getVL, st).Run(context.Background())
}

// bootstrapAdmin creates the first admin if no users exist. Username/password come
// from config or MAZEDNS_ADMIN_USERNAME / MAZEDNS_ADMIN_PASSWORD; a missing
// password is generated and logged once.
func bootstrapAdmin(st *store.Store, a config.AdminBootstrap) error {
	n, err := st.CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	username := boot.FirstNonEmpty(a.Username, os.Getenv("MAZEDNS_ADMIN_USERNAME"), "admin")
	password := boot.FirstNonEmpty(a.Password, os.Getenv("MAZEDNS_ADMIN_PASSWORD"))
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

// bootstrapNodes pre-provisions cluster nodes from a "name=key,name=key" spec so
// agents can be wired up without token enrollment (e.g. in dev compose). Keys are
// stored hashed, exactly like issued ones.
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
