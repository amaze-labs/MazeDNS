// Command dns-agent runs a MazeDNS resolver node (the data plane): it serves DNS
// (UDP/TCP, optionally DoT/DoH), replicates its filtering config from the control
// plane, ships its query log and stats back, and exposes only /healthz + /metrics
// over HTTP. It carries no dashboard, auth, or classifier, so nothing competes
// with the resolver hot path.
package main

import (
	"context"
	"errors"
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

// nodeIDMeta is the app_meta key under which the agent persists its immutable node
// id (a server-generated UUID). It is returned at enrollment and, for agents
// upgraded from a pre-UUID build, learned from the next config snapshot. The agent
// presents it on re-enrollment so a hostname change or key rejection re-attaches to
// the SAME node. It is never user-configurable — see docs/configuration.md.
const nodeIDMeta = "node_id"

// cpIPMeta is the app_meta key under which the agent persists the control plane's
// advertised address, learned at enrollment. Once known it pins the CP's fixed IP
// so the node keeps reaching the control plane even if DNS/hostname later breaks.
const cpIPMeta = "cp_ip"

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
	for _, d := range cfg.Deprecations {
		slog.Warn(d)
	}
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
	mx.RegisterQueryLogDropped(func() float64 { return float64(qlog.Dropped()) })

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
	// follows cfg.API.Address, whose default is loopback (secure by default): the
	// endpoint is unauthenticated, so exposing it on the network is an explicit
	// operator choice via MAZEDNS_API_ADDRESS (set to 0.0.0.0 in the compose files,
	// or to the overlay IP on a bare host).
	httpSrv := healthServer(net.JoinHostPort(cfg.API.Address, strconv.Itoa(cfg.API.Port)), mx)
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
	if cpURL == "" {
		slog.Info("standalone mode: no control plane configured (set MAZEDNS_CP_URL)")
		return
	}
	name := cfg.Cluster.NodeName
	if name == "" {
		name, _ = os.Hostname()
	}
	// Pin the control-plane IP from (in order) the explicit config, then the address
	// learned at a previous enrollment. Empty = reach the CP via its URL/DNS.
	pinnedIP := cfg.Cluster.MasterIP
	if pinnedIP == "" {
		pinnedIP, _ = st.GetMeta(cpIPMeta)
	}
	client := cluster.NewEnrollClient(pinnedIP)

	// reenroll self-registers with the join token and persists the fresh key. When
	// the control plane advertises its own address and no explicit master_ip was
	// configured, it is persisted so the node keeps a fixed CP IP across restarts.
	reenroll := func(ctx context.Context) (string, error) {
		// Present our current identity so the control plane re-attaches to the SAME
		// node: it rotates the existing node's key only when the presented key proves
		// ownership of the persisted id. Both are empty on the very first enrollment.
		curID, _ := st.GetMeta(nodeIDMeta)
		curKey, _ := st.GetMeta(nodeKeyMeta)
		var r cluster.EnrollResult
		var err error
		// A "name in use by a live node" answer means our name currently belongs to
		// a node the control plane still sees polling — typically OUR predecessor
		// container during an image update. Wait it out: once the control plane
		// marks it offline (~2 min), the same enrollment RECLAIMS that node's
		// identity, so no "<name>-2" duplicate is created. Only when the holder is
		// genuinely alive after the full wait do we accept a de-duplicated name.
		for attempt := 0; ; attempt++ {
			r, err = cluster.Enroll(ctx, client, cpURL, name, cfg.Cluster.JoinToken, curID, curKey, false)
			if !errors.Is(err, cluster.ErrNameInUse) {
				break
			}
			if attempt >= 8 { // ~4 min, comfortably past the CP's 2-min reclaim window
				slog.Warn("node name still held by a live node — enrolling with a de-duplicated name", "name", name)
				r, err = cluster.Enroll(ctx, client, cpURL, name, cfg.Cluster.JoinToken, curID, curKey, true)
				break
			}
			slog.Info("node name held by a live node — waiting to reclaim its identity (image update?)",
				"name", name, "retry_in", "30s")
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(30 * time.Second):
			}
		}
		if err != nil {
			return "", err
		}
		_ = st.SetMeta(nodeKeyMeta, r.Key)
		if r.ID != "" {
			_ = st.SetMeta(nodeIDMeta, r.ID)
		}
		if r.CPAddress != "" && cfg.Cluster.MasterIP == "" {
			_ = st.SetMeta(cpIPMeta, r.CPAddress)
			slog.Info("learned control-plane address at enrollment", "cp_address", r.CPAddress)
		}
		if !r.Approved {
			slog.Warn("enrolled but pending approval — approve this node in the control-plane UI", "name", name)
		}
		return r.Key, nil
	}

	// launch starts the replication agent once a node key is in hand.
	launch := func(nodeKey string) {
		// Enrollment may have just learned+persisted the CP's fixed address; use it
		// to pin the replication agent's transport for all later polls.
		ip := pinnedIP
		if cfg.Cluster.MasterIP == "" {
			if learned, _ := st.GetMeta(cpIPMeta); learned != "" {
				ip = learned
			}
		}
		statsFn := func() store.NodeStats {
			t, b, ca, fwd, rw, e := res.StatsSnapshot()
			return store.NodeStats{
				Total: int64(t), Blocked: int64(b), Cached: int64(ca),
				Forwarded: int64(fwd), Rewritten: int64(rw), Errors: int64(e),
			}
		}
		ag := cluster.NewAgent(cpURL, ip, nodeKey, cfg.Cluster.AdvertiseAddr,
			cfg.Cluster.Interval.Std(), st, reload, statsFn, res.SetBlockPausedUntil, res.SetMaintenance)
		if cfg.Cluster.JoinToken != "" {
			ag.SetReenroll(reenroll)
		}
		// Learn+persist our node id from the config snapshot when we don't have one
		// yet (upgraded from a pre-UUID build with only a key). Transparent — no
		// operator action; it lets a later re-enroll prove ownership of this node.
		curID, _ := st.GetMeta(nodeIDMeta)
		ag.SetNodeID(curID, func(id string) { _ = st.SetMeta(nodeIDMeta, id) })
		// Persist a control-plane-rotated node key so it survives restarts (the CP
		// keeps the old key valid for a grace window, so this is safe even if we
		// crash here).
		ag.SetSaveNodeKey(func(k string) { _ = st.SetMeta(nodeKeyMeta, k) })
		go ag.Run(ctx)
	}

	// Key resolution: a locally-resolvable key (persisted, or explicit with no
	// join token) launches immediately; otherwise self-enroll with the join token
	// IN THE BACKGROUND — DNS serving must never wait on (or be killed by)
	// enrollment, which may legitimately take minutes while a predecessor node is
	// being reclaimed. Enrollment retries until it succeeds (the old one-shot
	// attempt left the agent standalone until restart).
	if k := localNodeKey(st, cfg.Cluster.JoinToken, cfg.Cluster.NodeKey); k != "" {
		slog.Info("using local node key", "name", name)
		launch(k)
		return
	}
	if cfg.Cluster.JoinToken == "" {
		slog.Error("no node key: set MAZEDNS_JOIN_TOKEN (auto-enroll) or MAZEDNS_NODE_KEY; running standalone")
		return
	}
	go func() {
		slog.Info("self-enrolling with the control plane", "cp", cpURL, "name", name)
		persist := func(k string) { _ = st.SetMeta(nodeKeyMeta, k) }
		if k := enrollLoop(ctx, reenroll, cfg.Cluster.NodeKey, persist, pinnedIP); k != "" {
			launch(k)
		}
	}()
}

// localNodeKey returns the key resolvable without the network: a persisted key
// first, then — only when no join token is configured — the explicit node_key
// (persisted so restarts don't depend on the env staying set). Empty means the
// agent must self-enroll or run standalone.
func localNodeKey(st *store.Store, joinToken, nodeKey string) string {
	if k, _ := st.GetMeta(nodeKeyMeta); k != "" {
		return k
	}
	if joinToken == "" && nodeKey != "" {
		_ = st.SetMeta(nodeKeyMeta, nodeKey)
		return nodeKey
	}
	return ""
}

// enrollLoop retries self-enrollment until it succeeds, returning the node key.
// A revoked node is terminal (returns ""). When an explicit fallback key is
// configured alongside the join token, the first failure falls back to it (and
// persists it) — a working credential beats looping on a broken enrollment path.
func enrollLoop(ctx context.Context, reenroll func(context.Context) (string, error), fallback string, persist func(string), pinnedIP string) string {
	for ctx.Err() == nil {
		k, err := reenroll(ctx)
		if err == nil {
			return k
		}
		if errors.Is(err, cluster.ErrNodeRevoked) {
			slog.Error("this node was revoked on the control plane — not retrying (un-revoke it in the UI, or wipe /data to join as a new node)")
			return ""
		}
		slog.Warn("self-enrollment failed; retrying", "err", err, "retry_in", "30s")
		hintUnresolvableCP(err, pinnedIP)
		if fallback != "" {
			persist(fallback)
			return fallback
		}
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
	}
	return ""
}

// hintUnresolvableCP logs an actionable hint when the control plane couldn't be
// reached because its hostname didn't resolve and no IP pin is configured — the
// classic bootstrap trap where the agent is the only DNS on its network, so it
// can't resolve its own control plane's FQDN. Pinning MAZEDNS_CP_IP skips DNS.
func hintUnresolvableCP(err error, pinnedIP string) {
	if pinnedIP != "" {
		return // already pinning an IP; DNS isn't the problem
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		slog.Warn("control-plane hostname did not resolve — if this agent is the only DNS on its network, "+
			"pin the control plane's IP with MAZEDNS_CP_IP (TLS still verifies the URL host)", "host", dnsErr.Name)
	}
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
