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
func newSetupServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st, auth: auth.NewManager(st, nil, time.Hour), authEnabled: true}
	s.setupDone.Store(true) // matches New()'s default
	s.EnableSetupMode()
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
	s, _ := newSetupServer(t)
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

// Local-accounts path: no token required, weak passwords rejected, completion
// creates the admin + session and permanently closes setup (410).
func TestSetupCompleteFlow(t *testing.T) {
	s, st := newSetupServer(t)

	// Weak password rejected.
	if rr := postJSON(s.setupComplete, "/api/setup/complete", `{"username":"admin","password":"short"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("weak password: %d", rr.Code)
	}
	if c, _ := st.CountUsers(); c != 0 {
		t.Fatalf("no admin should exist after failed attempts, got %d", c)
	}

	// Valid completion (no token) creates the admin, sets a session cookie, and closes setup.
	rr := postJSON(s.setupComplete, "/api/setup/complete", `{"username":"root","password":"correcthorse7"}`)
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
	if rr := postJSON(s.setupComplete, "/api/setup/complete", `{"username":"x","password":"correcthorse7"}`); rr.Code != http.StatusGone {
		t.Fatalf("post-completion setup should be 410, got %d", rr.Code)
	}
}

// SSO path: a failing OIDC discovery blocks completion (nothing persisted); a
// passing one persists the OIDC config atomically with the break-glass admin.
func TestSetupCompleteSSO(t *testing.T) {
	s, st := newSetupServer(t)

	// IdP validation failure blocks completion with a clear error.
	var validateErr error = errStub("discovery failed: 404 Not Found")
	s.rebuildOIDC = func(store.OIDCSettings) error { return validateErr }
	body := `{"method":"sso","break_glass":true,"username":"root","password":"correcthorse7",
		"oidc":{"issuer":"https://idp.example","client_id":"cid","redirect_url":"https://cp/cb","admin_email":"op@example.com"}}`
	rr := postJSON(s.setupComplete, "/api/setup/complete", body)
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "discovery failed") {
		t.Fatalf("bad issuer should block completion: %d %s", rr.Code, rr.Body.String())
	}
	if s.setupActive() == false {
		t.Fatal("setup must stay open after a failed SSO validation")
	}
	if c, _ := st.CountUsers(); c != 0 {
		t.Fatalf("no admin should be created on failed SSO validation, got %d", c)
	}

	// Now discovery passes: completion persists OIDC + break-glass admin atomically.
	validateErr = nil
	rr = postJSON(s.setupComplete, "/api/setup/complete", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid SSO setup: %d %s", rr.Code, rr.Body.String())
	}
	cp := st.LoadCPSettings(store.CPSettings{})
	if !cp.OIDC.Enabled || cp.OIDC.Issuer != "https://idp.example" || cp.OIDC.AdminEmail != "op@example.com" {
		t.Fatalf("OIDC config not persisted: %+v", cp.OIDC)
	}
	if cp.OIDC.DisablePasswordLogin {
		t.Fatal("break-glass keeps password login enabled")
	}
	if c, _ := st.CountUsers(); c != 1 {
		t.Fatalf("break-glass admin should exist, got %d", c)
	}
	if s.setupActive() {
		t.Fatal("setup should be closed after SSO completion")
	}
}

// SSO-only (break-glass declined) persists SSO-only config and creates no local
// user; the response reports the wizard is not locally authenticated.
func TestSetupCompleteSSOOnly(t *testing.T) {
	s, st := newSetupServer(t)
	s.rebuildOIDC = func(store.OIDCSettings) error { return nil }
	body := `{"method":"sso","break_glass":false,
		"oidc":{"issuer":"https://idp.example","client_id":"cid","redirect_url":"https://cp/cb","admin_email":"op@example.com"}}`
	rr := postJSON(s.setupComplete, "/api/setup/complete", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("SSO-only setup: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"authenticated":true`) {
		t.Fatal("SSO-only setup has no local session")
	}
	if c, _ := st.CountUsers(); c != 0 {
		t.Fatalf("SSO-only should create no local user, got %d", c)
	}
	cp := st.LoadCPSettings(store.CPSettings{})
	if !cp.OIDC.DisablePasswordLogin {
		t.Fatal("SSO-only should disable password login")
	}
}

// Concurrent setup attempts create exactly one admin / one completion.
func TestSetupCompleteConcurrent(t *testing.T) {
	s, st := newSetupServer(t)
	const n = 15
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok200 := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := postJSON(s.setupComplete, "/api/setup/complete", `{"username":"admin","password":"correcthorse7"}`)
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

// A break-glass local admin created in SSO mode can still log in with a password
// when the IdP is unreachable (no live OIDC provider): the operator is not locked
// out by a misconfigured or down IdP.
func TestBreakGlassLoginWhenIdPDown(t *testing.T) {
	s, _ := newSetupServer(t)
	// Discovery "passed" at setup time, but no live provider is wired afterwards
	// (simulating the IdP going down / OIDC failing to initialize).
	s.rebuildOIDC = func(store.OIDCSettings) error { return nil }
	body := `{"method":"sso","break_glass":true,"username":"root","password":"correcthorse7",
		"oidc":{"issuer":"https://idp.example","client_id":"cid","redirect_url":"https://cp/cb","admin_email":"op@example.com"}}`
	if rr := postJSON(s.setupComplete, "/api/setup/complete", body); rr.Code != http.StatusOK {
		t.Fatalf("SSO+break-glass setup: %d %s", rr.Code, rr.Body.String())
	}
	// OIDC is not actually enabled on the auth manager (IdP down), so password
	// login must remain available for the break-glass account.
	rr := postJSON(s.login, "/api/auth/login", `{"username":"root","password":"correcthorse7"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("break-glass local login should work when IdP is down: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Set-Cookie"), auth.CookieName) {
		t.Fatal("break-glass login should start a session")
	}
}

// errStub is a trivial error for stubbing the OIDC validation callback.
type errStub string

func (e errStub) Error() string { return string(e) }
