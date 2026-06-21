// Command mazedns runs the MazeDNS filtering resolver.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/IPMaze/MazeDNS/internal/cache"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/resolver"
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

	// Blocklist filter.
	var fe *filter.Engine
	if cfg.Filter.Enabled {
		fe = filter.New()
		for _, path := range cfg.Filter.BlocklistFiles {
			n, lerr := fe.LoadHostsFile(path)
			if lerr != nil {
				slog.Warn("blocklist load failed", "file", path, "err", lerr)
				continue
			}
			slog.Info("blocklist loaded", "file", path, "domains", n)
		}
		slog.Info("filter ready", "total_domains", fe.Len())
	}

	// Response cache.
	var c *cache.Cache
	if cfg.Cache.Enabled {
		c = cache.New(cfg.Cache.MaxEntries, cfg.Cache.MinTTL.Std(), cfg.Cache.MaxTTL.Std())
	}

	res := resolver.New(resolver.Options{
		Upstreams:     cfg.Upstreams,
		Cache:         c,
		Filter:        fe,
		BlockResponse: cfg.Filter.BlockResponse,
		QueryLog:      cfg.Log.QueryLog,
	})

	addr := net.JoinHostPort(cfg.Listen.Address, strconv.Itoa(cfg.Listen.Port))
	srv := resolver.NewServer(addr, res)

	go func() {
		slog.Info("MazeDNS starting",
			"addr", addr, "upstreams", cfg.Upstreams,
			"cache", cfg.Cache.Enabled, "filter", cfg.Filter.Enabled)
		if serveErr := srv.ListenAndServe(); serveErr != nil {
			slog.Error("server stopped", "err", serveErr)
			os.Exit(1)
		}
	}()

	// Periodic stats line.
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			t, b, ca, fwd, e := res.StatsSnapshot()
			slog.Info("stats", "total", t, "blocked", b, "cached", ca, "forwarded", fwd, "errors", e)
		}
	}()

	// Wait for a termination signal, then shut down gracefully.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
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
