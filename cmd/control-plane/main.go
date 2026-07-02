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

	"github.com/google/uuid"

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
	// Break-glass admin recovery: `control-plane reset-admin` operates directly on
	// the DB (not read on every boot), replacing the old MAZEDNS_ADMIN_PASSWORD path.
	if len(os.Args) > 1 && os.Args[1] == "reset-admin" {
		resetAdminCmd(os.Args[2:])
		return
	}

	cfgPath := flag.String("config", "configs/mazedns.yaml", "path to the YAML config file")
	flag.Parse()

	boot.TuneGC()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	slog.SetDefault(boot.NewLogger(cfg.Log.Level))
	for _, d := range cfg.Deprecations {
		slog.Warn(d)
	}
	slog.Info("MazeDNS control plane starting", "version", version)

	st, err := boot.OpenStore(cfg)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	slog.Info("store ready", "backend", boot.StoreBackend(cfg), "path", cfg.Database.Path)

	// Runtime settings are DB-backed and UI-editable. On first boot only, seed them
	// from env/YAML so an existing deployment upgrades transparently; afterwards the
	// database is the single source of truth and env/YAML runtime values are ignored.
	seeded, _ := st.EnsureCPSettings(seedCPSettings(cfg))
	if seeded {
		slog.Info("seeded control-plane runtime settings from config; the database is now the source of truth (env/YAML runtime values are ignored)")
	} else {
		slog.Info("control-plane runtime settings loaded from the database (env/YAML runtime values are ignored)")
	}
	cpset := st.LoadCPSettings(store.CPSettings{SessionTTLSec: 24 * 3600})

	// Auth: DB-backed session TTL + optional OIDC (built from DB settings).
	authMgr := auth.NewManager(st, nil, time.Duration(cpset.SessionTTLSec)*time.Second)
	if cfg.Auth.Enabled {
		if cpset.OIDC.Enabled {
			if p, oerr := buildOIDC(context.Background(), cpset.OIDC); oerr != nil {
				slog.Error("oidc init failed; continuing without SSO", "err", oerr)
			} else {
				authMgr.SetOIDC(p)
				slog.Info("oidc enabled", "issuer", cpset.OIDC.Issuer, "redirect_uri", cpset.OIDC.RedirectURL)
			}
		}
		slog.Info("auth enabled", "oidc", authMgr.OIDCEnabled())
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

	warnRemovedBootstrapNodes(os.Getenv("MAZEDNS_CLUSTER_BOOTSTRAP_NODES"))

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
	// Per-node key rotation policy (DB-backed): default to 30d if unset.
	keyMaxAge := time.Duration(cpset.KeyMaxAgeSec) * time.Second
	if keyMaxAge == 0 {
		keyMaxAge = 30 * 24 * time.Hour
	}
	// Live-apply all DB-backed CP settings at boot (cluster policy, session TTL,
	// login rate limits) so runtime services match the store without a restart.
	apiSrv.ApplyCPSettings(cpset)
	apiSrv.SetClassifierStatus(clsWorker)
	apiSrv.SetClassifierEnqueue(clsWorker.Enqueue)
	apiSrv.SetEnricher(enricher)
	// SSO settings change live: rebuild and swap the OIDC provider without a restart.
	apiSrv.SetRebuildOIDC(func(o store.OIDCSettings) error {
		if !o.Enabled {
			authMgr.SetOIDC(nil)
			slog.Info("oidc disabled via settings")
			return nil
		}
		p, err := buildOIDC(context.Background(), o)
		if err != nil {
			return err
		}
		authMgr.SetOIDC(p)
		slog.Info("oidc reconfigured via settings", "issuer", o.Issuer)
		return nil
	})
	// Enrollment secrets are UI-managed keys in the DB. A configured join_token is
	// deprecated: import it once as a never-expiring enrollment key so existing
	// agents keep working, then warn the operator to manage keys in the UI.
	importDeprecatedJoinToken(st, cfg.Cluster.JoinToken)

	// First-boot setup wizard: on a fresh, admin-less control plane, guard the API
	// behind the setup wizard (trust-on-first-use — whoever reaches the fresh CP
	// first completes setup; see setup.go). Existing deployments (an admin already
	// exists) skip setup entirely.
	if cfg.Auth.Enabled && !st.SetupCompleted() {
		if n, _ := st.CountUsers(); n == 0 {
			apiSrv.EnableSetupMode()
			slog.Warn("first-boot setup mode active — open the web UI to create the first admin",
				"api", apiAddr,
				"note", "do NOT expose the control plane publicly until setup completes")
		}
	}
	slog.Info("cluster self-enrollment ready (manage enrollment keys in the UI)",
		"require_approval", cpset.RequireApproval, "key_max_age", keyMaxAge)
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

// seedCPSettings maps the file/env config to the DB-backed control-plane runtime
// settings, used ONLY to seed the database on first boot.
func seedCPSettings(cfg config.Config) store.CPSettings {
	o := cfg.Auth.OIDC
	return store.CPSettings{
		SessionTTLSec: int(cfg.Auth.SessionTTL.Std().Seconds()),
		OIDC: store.OIDCSettings{
			Enabled:              o.Enabled,
			Issuer:               o.Issuer,
			ClientID:             o.ClientID,
			ClientSecret:         o.ClientSecret,
			RedirectURL:          o.RedirectURL,
			Scopes:               o.Scopes,
			GroupsClaim:          o.GroupsClaim,
			AdminGroup:           o.AdminGroup,
			AdminEmail:           o.AdminEmail,
			DisablePasswordLogin: o.DisablePasswordLogin,
			AutoLogin:            o.AutoLogin,
		},
		RequireApproval: cfg.Cluster.RequireApproval,
		KeyMaxAgeSec:    int64(cfg.Cluster.KeyMaxAge.Std().Seconds()),
		KeyGraceSec:     int64(cfg.Cluster.KeyGrace.Std().Seconds()),
		AdvertiseAddr:   cfg.Cluster.AdvertiseAddr,
		QueryLog:        cfg.Log.QueryLog,
	}
}

// buildOIDC constructs an OIDC provider from the DB-backed SSO settings.
func buildOIDC(ctx context.Context, o store.OIDCSettings) (*auth.OIDCProvider, error) {
	return auth.NewOIDC(ctx, config.OIDC{
		Enabled:              o.Enabled,
		Issuer:               o.Issuer,
		ClientID:             o.ClientID,
		ClientSecret:         o.ClientSecret,
		RedirectURL:          o.RedirectURL,
		Scopes:               o.Scopes,
		GroupsClaim:          o.GroupsClaim,
		AdminGroup:           o.AdminGroup,
		AdminEmail:           o.AdminEmail,
		DisablePasswordLogin: o.DisablePasswordLogin,
		AutoLogin:            o.AutoLogin,
	})
}

// resetAdminCmd is the break-glass admin recovery subcommand:
//
//	control-plane reset-admin [--config path] [--username name] [--password pw]
//
// It creates the admin if none exists, or resets an existing user to admin with a
// new password. A missing password is generated and printed once.
func resetAdminCmd(args []string) {
	fs := flag.NewFlagSet("reset-admin", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/mazedns.yaml", "path to the YAML config file")
	username := fs.String("username", "admin", "admin username to create or reset")
	password := fs.String("password", "", "new password (generated if empty)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	slog.SetDefault(boot.NewLogger(cfg.Log.Level))
	st, err := boot.OpenStore(cfg)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	pw := strings.TrimSpace(*password)
	generated := false
	if pw == "" {
		tok, terr := auth.NewToken()
		if terr != nil {
			slog.Error("token", "err", terr)
			os.Exit(1)
		}
		pw = tok[:16]
		generated = true
	}
	// Enforce the same password policy as the UI for an operator-supplied password
	// (generated ones are strong by construction).
	if !generated {
		if msg := auth.PasswordStrengthError(pw); msg != "" {
			slog.Error("weak password", "err", msg)
			os.Exit(1)
		}
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		slog.Error("hash", "err", err)
		os.Exit(1)
	}
	existing, _ := st.GetUserByUsername(*username)
	if existing != nil {
		if err := st.UpdateUserPassword(existing.ID, hash); err != nil {
			slog.Error("reset password", "err", err)
			os.Exit(1)
		}
		if existing.Role != "admin" {
			_ = st.UpdateUserRole(existing.ID, "admin")
		}
		slog.Info("admin password reset", "username", *username)
	} else {
		if _, err := st.CreateLocalUser(*username, hash, "admin"); err != nil {
			slog.Error("create admin", "err", err)
			os.Exit(1)
		}
		// Mark setup complete so the wizard doesn't reopen after a manual admin create.
		_ = st.SetMeta("setup_completed", "1")
		slog.Info("admin created", "username", *username)
	}
	if generated {
		slog.Warn("generated password (shown once) — log in and change it", "username", *username, "password", pw)
	}
}

// warnRemovedBootstrapNodes logs a one-line notice when the removed
// MAZEDNS_CLUSTER_BOOTSTRAP_NODES env var is still set, and otherwise does nothing.
// Node pre-provisioning was removed because it put node secrets in the environment,
// bypassed UI-managed enrollment keys and the approval flow, and created nodes
// outside the server-assigned-UUID identity model. It never provisions anything;
// automation should create an enrollment key (UI or admin API) and pass it to
// agents as MAZEDNS_JOIN_TOKEN. Returns whether the notice fired (for tests).
func warnRemovedBootstrapNodes(spec string) bool {
	if strings.TrimSpace(spec) == "" {
		return false
	}
	slog.Warn("MAZEDNS_CLUSTER_BOOTSTRAP_NODES was removed and is ignored — create an enrollment key in the UI (or via the admin API) and pass it to agents as MAZEDNS_JOIN_TOKEN")
	return true
}

// importDeprecatedJoinToken migrates a configured cluster.join_token to a DB
// enrollment key. It is idempotent (keyed by hash) so restarts don't duplicate it,
// and it lets already-deployed agents keep enrolling with their existing
// MAZEDNS_JOIN_TOKEN value while the operator moves to UI-managed keys.
func importDeprecatedJoinToken(st *store.Store, token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	sum := sha256.Sum256([]byte(token))
	prefix := token
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	if err := st.EnsureEnrollKey(uuid.NewString(), "imported-join-token (deprecated config)", hex.EncodeToString(sum[:]), prefix); err != nil {
		slog.Warn("could not import deprecated join_token as an enrollment key", "err", err)
		return
	}
	slog.Warn("cluster.join_token / MAZEDNS_JOIN_TOKEN is deprecated: imported as a never-expiring enrollment key " +
		"(manage and revoke it under Cluster → Enrollment keys in the UI)")
}
