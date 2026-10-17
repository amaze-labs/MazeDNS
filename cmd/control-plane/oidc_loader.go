package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// oidcLoader builds and installs the OIDC provider. Discovery needs the issuer to
// be reachable, which at boot it often is not yet (the IdP container is still
// starting, or DNS isn't up). Instead of leaving SSO off until the next restart,
// a failed boot attempt keeps retrying in the background with backoff. A settings
// change (Apply) supersedes any pending retry, so a stale config never overwrites
// a newer one.
type oidcLoader struct {
	build      func(context.Context, store.OIDCSettings) (*auth.OIDCProvider, error)
	install    func(*auth.OIDCProvider)
	timeout    time.Duration // per discovery attempt
	backoff    time.Duration // first retry delay, doubled up to maxBackoff
	maxBackoff time.Duration

	mu     sync.Mutex
	gen    uint64             // bumped by every Start/Apply; only the latest may install
	cancel context.CancelFunc // stops the pending boot retry, if any
}

func newOIDCLoader(install func(*auth.OIDCProvider)) *oidcLoader {
	return &oidcLoader{
		build:      buildOIDC,
		install:    install,
		timeout:    15 * time.Second,
		backoff:    5 * time.Second,
		maxBackoff: 5 * time.Minute,
	}
}

// Start tries discovery once and reports whether SSO is up. On failure it keeps
// retrying in the background until it succeeds, ctx ends, or Apply supersedes it.
func (l *oidcLoader) Start(ctx context.Context, o store.OIDCSettings) bool {
	gen, ctx := l.begin(ctx)
	p, err := l.attempt(ctx, o)
	if err == nil {
		return l.installIf(gen, p)
	}
	slog.Error("oidc init failed; SSO is off until the issuer is reachable, retrying in the background",
		"issuer", o.Issuer, "err", err)
	go l.retry(ctx, gen, o)
	return false
}

// Apply swaps the provider for changed settings (disabled = SSO off), cancelling
// any pending boot retry. On error the current provider is left as it is.
func (l *oidcLoader) Apply(o store.OIDCSettings) error {
	gen, ctx := l.begin(context.Background())
	if !o.Enabled {
		l.installIf(gen, nil)
		return nil
	}
	p, err := l.attempt(ctx, o)
	if err != nil {
		return err
	}
	l.installIf(gen, p)
	return nil
}

// begin starts a new generation, cancelling the previous one's retry.
func (l *oidcLoader) begin(parent context.Context) (uint64, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cancel != nil {
		l.cancel()
	}
	l.gen++
	l.cancel = cancel
	return l.gen, ctx
}

func (l *oidcLoader) attempt(ctx context.Context, o store.OIDCSettings) (*auth.OIDCProvider, error) {
	ctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	return l.build(ctx, o)
}

// installIf installs p only if gen is still the latest generation.
func (l *oidcLoader) installIf(gen uint64, p *auth.OIDCProvider) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if gen != l.gen {
		return false
	}
	l.install(p)
	return true
}

func (l *oidcLoader) retry(ctx context.Context, gen uint64, o store.OIDCSettings) {
	delay := l.backoff
	for attempt := 2; ; attempt++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		p, err := l.attempt(ctx, o)
		if err == nil {
			if l.installIf(gen, p) {
				slog.Info("oidc enabled", "issuer", o.Issuer, "redirect_uri", o.RedirectURL, "attempt", attempt)
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		delay = min(delay*2, l.maxBackoff)
		slog.Warn("oidc init retry failed", "issuer", o.Issuer, "attempt", attempt, "next_in", delay, "err", err)
	}
}
