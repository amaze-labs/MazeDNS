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
	"github.com/IPMaze/MazeDNS/internal/cache"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/metrics"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

func main() {
	cfgPath := flag.String("config", "configs/mazedns.yaml", "path to the YAML config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	slog.SetDefault(newLogger(cfg.Log.Level))

	// Datastore.
	st, err := store.Open(cfg.Database.Path)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	slog.Info("store ready", "path", cfg.Database.Path)

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

	// DNS server.
	dnsAddr := net.JoinHostPort(cfg.Listen.Address, strconv.Itoa(cfg.Listen.Port))
	dnsSrv := resolver.NewServer(dnsAddr, res)
	go func() {
		slog.Info("MazeDNS DNS starting", "addr", dnsAddr, "upstreams", cfg.Upstreams,
			"cache", cfg.Cache.Enabled, "filter", cfg.Filter.Enabled)
		if serveErr := dnsSrv.ListenAndServe(); serveErr != nil {
			slog.Error("dns server stopped", "err", serveErr)
			os.Exit(1)
		}
	}()

	// HTTP API + metrics.
	var apiSrv *api.Server
	if cfg.API.Enabled {
		apiAddr := net.JoinHostPort(cfg.API.Address, strconv.Itoa(cfg.API.Port))
		apiSrv = api.New(apiAddr, st, res, mx, reload)
		go func() {
			slog.Info("MazeDNS API starting", "addr", apiAddr)
			if serveErr := apiSrv.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
				slog.Error("api server stopped", "err", serveErr)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dnsSrv.Shutdown(ctx)
	if apiSrv != nil {
		_ = apiSrv.Shutdown(ctx)
	}
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
