package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// newSetupServer builds an auth-enabled server in first-boot setup mode.
func newSetupServer(t *testing.T, token string) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st, auth: auth.NewManager(st, nil, time.Hour), authEnabled: true}
	s.setupDone.Store(true) // matches New()'s default
	s.EnableSetupMode(token)
	return s, st
}

func postJSON(h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rr
}

// While setup is pending the gate blocks normal API routes but allows the wizard,
// health, and public auth info.
func TestSetupGateBlocksUntilComplete(t *testing.T) {
	s, _ := newSetupServer(t, "tok")
	gate := s.setupGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// A protected API route is blocked with setup_required.
	rr := httptest.NewRecorder()
	gate.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "setup_required") {
		t.Fatalf("protected route during setup: %d %s", rr.Code, rr.Body.String())
	}
	// Setup + health + auth info + static pass through.
	for _, p := range []string{"/api/setup/status", "/healthz", "/api/auth/info", "/index.html"} {
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("path %q should pass the gate during setup, got %d", p, rr.Code)
		}
	}
}

func TestSetupCompleteFlow(t *testing.T) {
	s, st := newSetupServer(t, "s3tup-tok")

	// Wrong token rejected.
	if rr := postJSON(s.setupComplete, "/api/setup/complete", `{"token":"nope","username":"admin","password":"correcthorse7"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rr.Code)
	}
	// Weak password rejected.
	if rr := postJSON(s.setupComplete, "/api/setup/complete", `{"token":"s3tup-tok","username":"admin","password":"short"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("weak password: %d", rr.Code)
	}
	if c, _ := st.CountUsers(); c != 0 {
		t.Fatalf("no admin should exist after failed attempts, got %d", c)
	}

	// Valid completion creates the admin, sets a session cookie, and closes setup.
	rr := postJSON(s.setupComplete, "/api/setup/complete", `{"token":"s3tup-tok","username":"root","password":"correcthorse7"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid setup: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Set-Cookie"), auth.CookieName) {
		t.Fatal("setup should start a session (Set-Cookie)")
	}
	if c, _ := st.CountUsers(); c != 1 {
		t.Fatalf("one admin expected, got %d", c)
	}
	if s.setupActive() {
		t.Fatal("setup should be closed after completion")
	}
	// Setup endpoints are permanently closed (410).
	if rr := postJSON(s.setupComplete, "/api/setup/complete", `{"token":"s3tup-tok","username":"x","password":"correcthorse7"}`); rr.Code != http.StatusGone {
		t.Fatalf("post-completion setup should be 410, got %d", rr.Code)
	}
}

// Concurrent setup attempts (all with the valid token) create exactly one admin.
func TestSetupCompleteConcurrent(t *testing.T) {
	s, st := newSetupServer(t, "tok")
	const n = 15
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok200 := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := postJSON(s.setupComplete, "/api/setup/complete", `{"token":"tok","username":"admin","password":"correcthorse7"}`)
			if rr.Code == http.StatusOK {
				mu.Lock()
				ok200++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok200 != 1 {
		t.Fatalf("exactly one setup should succeed, got %d", ok200)
	}
	if c, _ := st.CountUsers(); c != 1 {
		t.Fatalf("one admin expected, got %d", c)
	}
}
