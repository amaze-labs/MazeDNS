package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// fakeLoader returns a loader whose discovery fails the first `fails` calls for
// issuer "boot", and records what was installed.
func fakeLoader(fails int32) (*oidcLoader, *atomic.Int32, func() *auth.OIDCProvider, map[string]*auth.OIDCProvider) {
	providers := map[string]*auth.OIDCProvider{"boot": {}, "new": {}}
	var calls atomic.Int32
	var mu sync.Mutex
	var installed *auth.OIDCProvider
	l := &oidcLoader{
		build: func(_ context.Context, o store.OIDCSettings) (*auth.OIDCProvider, error) {
			if o.Issuer == "boot" && calls.Add(1) <= fails {
				return nil, errors.New("issuer unreachable")
			}
			return providers[o.Issuer], nil
		},
		install: func(p *auth.OIDCProvider) {
			mu.Lock()
			installed = p
			mu.Unlock()
		},
		timeout:    time.Second,
		backoff:    time.Millisecond,
		maxBackoff: 5 * time.Millisecond,
	}
	get := func() *auth.OIDCProvider {
		mu.Lock()
		defer mu.Unlock()
		return installed
	}
	return l, &calls, get, providers
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestOIDCLoaderStartSucceedsImmediately(t *testing.T) {
	l, _, installed, prov := fakeLoader(0)
	if !l.Start(context.Background(), store.OIDCSettings{Enabled: true, Issuer: "boot"}) {
		t.Fatal("Start = false, want true")
	}
	if installed() != prov["boot"] {
		t.Fatal("provider not installed")
	}
}

// The bug: an IdP that is down at boot left SSO off until restart.
func TestOIDCLoaderRetriesUntilIssuerIsUp(t *testing.T) {
	l, calls, installed, prov := fakeLoader(3)
	if l.Start(context.Background(), store.OIDCSettings{Enabled: true, Issuer: "boot"}) {
		t.Fatal("Start = true, want false while issuer is down")
	}
	waitFor(t, func() bool { return installed() == prov["boot"] })
	if n := calls.Load(); n != 4 {
		t.Fatalf("discovery calls = %d, want 4", n)
	}
}

func TestOIDCLoaderApplySupersedesRetry(t *testing.T) {
	l, calls, installed, prov := fakeLoader(1 << 30)
	l.Start(context.Background(), store.OIDCSettings{Enabled: true, Issuer: "boot"})
	waitFor(t, func() bool { return calls.Load() >= 2 }) // retry loop running

	if err := l.Apply(store.OIDCSettings{Enabled: true, Issuer: "new"}); err != nil {
		t.Fatal(err)
	}
	if installed() != prov["new"] {
		t.Fatal("new provider not installed")
	}
	// The boot retry is cancelled: no further attempts, and it can't overwrite.
	// An attempt already in flight when Apply cancelled may still finish.
	time.Sleep(10 * time.Millisecond)
	n := calls.Load()
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != n {
		t.Fatal("boot retry still running after Apply")
	}
	if installed() != prov["new"] {
		t.Fatal("stale boot provider overwrote the new one")
	}
}

func TestOIDCLoaderApplyDisable(t *testing.T) {
	l, _, installed, _ := fakeLoader(0)
	l.Start(context.Background(), store.OIDCSettings{Enabled: true, Issuer: "boot"})
	if err := l.Apply(store.OIDCSettings{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if installed() != nil {
		t.Fatal("SSO still installed after disable")
	}
}

func TestOIDCLoaderStopsOnContextCancel(t *testing.T) {
	l, calls, installed, _ := fakeLoader(1 << 30)
	ctx, cancel := context.WithCancel(context.Background())
	l.Start(ctx, store.OIDCSettings{Enabled: true, Issuer: "boot"})
	waitFor(t, func() bool { return calls.Load() >= 2 })
	cancel()
	time.Sleep(10 * time.Millisecond)
	n := calls.Load()
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != n {
		t.Fatal("retry still running after cancel")
	}
	if installed() != nil {
		t.Fatal("provider installed despite failures")
	}
}
