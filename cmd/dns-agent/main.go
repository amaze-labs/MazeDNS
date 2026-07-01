// Command dns-agent runs a MazeDNS resolver node (the data plane): it serves DNS
// (UDP/TCP, optionally DoT/DoH), replicates its filtering config from the control
// plane, ships its query log and stats back, and exposes only /healthz + /metrics
// over HTTP. It carries no dashboard, auth, or classifier, so nothing competes
// with the resolver hot path.
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

	"github.com/IPMaze/MazeDNS/internal/boot"
	"github.com/IPMaze/MazeDNS/internal/cluster"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/metrics"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// nodeKeyMeta is the app_meta key under which the agent persists the per-node API
// key issued by the control plane at enrollment.
const nodeKeyMeta = "node_key"

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
	slog.Info("MazeDNS dns-agent starting", "version", version)

	st, err := boot.OpenStore(cfg)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	mx := metrics.New()

	qlog := store.NewQueryLogWriter(st, 4096)
	defer qlog.Close()

	res := resolver.New(resolver.Options{
		Timeout:  5 * time.Second,
		Zones:    boot.ToZoneSpecs(cfg.Zones),
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
		},
	})
	res.ApplySettings(boot.LoadOrSeedSettings(st, cfg))
	go res.MaintainUpstreams(context.Background())
	if ts, _ := st.GetBlockPausedUntil(); ts > 0 {
		res.SetBlockPausedUntil(ts)
	}

	reload := func() error {
		p, perr := boot.BuildPolicy(st, cfg)
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

	// Replicate config from the control plane. The node key is obtained from (in
	// order) the locally-persisted key, self-enrollment with the join token, or an
	// explicitly-supplied key.
	agentCtx, agentCancel := context.WithCancel(context.Background())
	startAgent(agentCtx, st, cfg, res, reload)

	// Bound local query-log growth: the agent only needs a short buffer before
	// shipping to the control plane.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			if n, err := st.PruneQueryLog(time.Now().Add(-48 * time.Hour).UnixMilli()); err == nil && n > 0 {
				slog.Info("query log pruned", "removed", n)
			}
		}
	}()

	// Each node pushes its own metrics to VictoriaMetrics, labelled by instance.
	startMetricsExport(st, cfg, mx)

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

	// Encrypted DNS endpoints (DoT/DoH).
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

	// Minimal HTTP surface: liveness + Prometheus metrics only (no API/UI). Bind
	// 0.0.0.0 by default — unlike the control plane, whose loopback default keeps
	// its sensitive API/UI private, the agent exposes only /healthz + /metrics,
	// which a remote Prometheus and a container port mapping must be able to reach.
	httpAddr := cfg.API.Address
	if httpAddr == "127.0.0.1" {
		httpAddr = "0.0.0.0"
	}
	httpSrv := healthServer(net.JoinHostPort(httpAddr, strconv.Itoa(cfg.API.Port)), mx)
	go func() {
		slog.Info("MazeDNS agent HTTP starting (healthz + metrics)", "addr", httpSrv.Addr)
		if e := httpSrv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			slog.Error("http server stopped", "err", e)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	slog.Info("shutting down")
	agentCancel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dnsSrv.Shutdown(ctx)
	if dotSrv != nil {
		_ = dotSrv.ShutdownContext(ctx)
	}
	if dohSrv != nil {
		_ = dohSrv.Shutdown(ctx)
	}
	_ = httpSrv.Shutdown(ctx)
}

// startAgent resolves this node's API key and launches the replication agent. It
// no-ops (serving standalone DNS) when no control plane is configured.
func startAgent(ctx context.Context, st *store.Store, cfg config.Config, res *resolver.Resolver, reload func() error) {
	cpURL := cfg.Cluster.ControlPlaneURL()
	if !cfg.Cluster.Enabled || cpURL == "" {
		slog.Info("standalone mode: no control plane configured (set MAZEDNS_CP_URL)")
		return
	}
	name := cfg.Cluster.NodeName
	if name == "" {
		name, _ = os.Hostname()
	}
	client := cluster.NewEnrollClient(cfg.Cluster.MasterIP)

	// reenroll self-registers with the join token and persists the fresh key.
	reenroll := func(ctx context.Context) (string, error) {
		r, err := cluster.Enroll(ctx, client, cpURL, name, cfg.Cluster.JoinToken)
		if err != nil {
			return "", err
		}
		_ = st.SetMeta(nodeKeyMeta, r.Key)
		if !r.Approved {
			slog.Warn("enrolled but pending approval — approve this node in the control-plane UI", "name", name)
		}
		return r.Key, nil
	}

	nodeKey := resolveNodeKey(ctx, st, cfg, name, cpURL, reenroll)
	if nodeKey == "" {
		slog.Error("no node key: set MAZEDNS_JOIN_TOKEN (auto-enroll) or MAZEDNS_NODE_KEY; running standalone")
		return
	}

	statsFn := func() store.NodeStats {
		t, b, ca, fwd, rw, e := res.StatsSnapshot()
		return store.NodeStats{
			Total: int64(t), Blocked: int64(b), Cached: int64(ca),
			Forwarded: int64(fwd), Rewritten: int64(rw), Errors: int64(e),
		}
	}
	ag := cluster.NewAgent(cpURL, cfg.Cluster.MasterIP, nodeKey, cfg.Cluster.AdvertiseAddr,
		cfg.Cluster.Interval.Std(), st, reload, statsFn, res.SetBlockPausedUntil, res.SetMaintenance)
	if cfg.Cluster.JoinToken != "" {
		ag.SetReenroll(reenroll)
	}
	go ag.Run(ctx)
}

// resolveNodeKey returns the API key the agent authenticates with: a previously
// persisted key, then a freshly self-enrolled one (when a join token is set), then
// an explicitly-supplied MAZEDNS_NODE_KEY.
func resolveNodeKey(ctx context.Context, st *store.Store, cfg config.Config, name, cpURL string, reenroll func(context.Context) (string, error)) string {
	if k, _ := st.GetMeta(nodeKeyMeta); k != "" {
		slog.Info("using persisted node key", "name", name)
		return k
	}
	if cfg.Cluster.JoinToken != "" {
		slog.Info("self-enrolling with the control plane", "cp", cpURL, "name", name)
		if k, err := reenroll(ctx); err == nil {
			return k
		} else {
			slog.Warn("self-enrollment failed; will retry on the next sync cycle", "err", err)
		}
	}
	if cfg.Cluster.NodeKey != "" {
		// Persist so restarts don't depend on the env staying set.
		_ = st.SetMeta(nodeKeyMeta, cfg.Cluster.NodeKey)
		return cfg.Cluster.NodeKey
	}
	return ""
}

// healthServer builds the agent's minimal HTTP server: liveness + metrics only.
func healthServer(addr string, mx *metrics.Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("GET /metrics", mx.Handler())
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

// startMetricsExport runs the VictoriaMetrics pusher for this node.
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
