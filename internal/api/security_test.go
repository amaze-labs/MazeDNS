package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// newAuthServer builds an auth-enabled server with setup already complete and the
// login limiter initialized, plus one local admin (admin / "correcthorse7").
func newAuthServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st, auth: auth.NewManager(st, nil, time.Hour), authEnabled: true, loginRate: newKeyedLimiter()}
	s.setupDone.Store(true)
	s.applyCPSettings(cpSettingsDefaults())
	hash, _ := auth.HashPassword("correcthorse7")
	if _, err := st.CreateLocalUser("admin", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	return s, st
}

func loginReq(body, xfp string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	if xfp != "" {
		r.Header.Set("X-Forwarded-Proto", xfp)
	}
	return r
}

// Finding #2: login is rate-limited per the GUI-configured window; excess returns
// 429 with Retry-After.
func TestLoginRateLimited(t *testing.T) {
	s, _ := newAuthServer(t)
	s.applyCPSettings(store.CPSettings{SessionTTLSec: 3600, LoginRateAttempts: 2, LoginRateWindowSec: 60})

	body := `{"username":"admin","password":"wrong-password-1"}`
	codes := []int{}
	for i := 0; i < 4; i++ {
		rr := httptest.NewRecorder()
		s.login(rr, loginReq(body, ""))
		codes = append(codes, rr.Code)
		if rr.Code == http.StatusTooManyRequests && rr.Header().Get("Retry-After") == "" {
			t.Fatal("429 response must carry Retry-After")
		}
	}
	// First two are 401 (bad creds), then the limiter trips to 429.
	if codes[0] != http.StatusUnauthorized || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("expected 401,401,429,...; got %v", codes)
	}
}

// Finding #2: with the limit disabled (0), attempts are never throttled.
func TestLoginRateDisabled(t *testing.T) {
	s, _ := newAuthServer(t)
	s.applyCPSettings(store.CPSettings{SessionTTLSec: 3600, LoginRateAttempts: 0, LoginRateWindowSec: 60})
	for i := 0; i < 20; i++ {
		rr := httptest.NewRecorder()
		s.login(rr, loginReq(`{"username":"admin","password":"wrong"}`, ""))
		if rr.Code == http.StatusTooManyRequests {
			t.Fatal("limit=0 should disable throttling")
		}
	}
}

// Finding #4: the session cookie is Secure only when the request is HTTPS
// (X-Forwarded-Proto=https), so dev over plain http still works.
func TestLoginCookieSecureBehindProxy(t *testing.T) {
	s, _ := newAuthServer(t)
	good := `{"username":"admin","password":"correcthorse7"}`

	rrHTTP := httptest.NewRecorder()
	s.login(rrHTTP, loginReq(good, ""))
	if rrHTTP.Code != http.StatusOK {
		t.Fatalf("plain-http login should succeed: %d %s", rrHTTP.Code, rrHTTP.Body.String())
	}
	if strings.Contains(rrHTTP.Header().Get("Set-Cookie"), "Secure") {
		t.Fatal("cookie must NOT be Secure over plain http (dev)")
	}

	rrHTTPS := httptest.NewRecorder()
	s.login(rrHTTPS, loginReq(good, "https"))
	if !strings.Contains(rrHTTPS.Header().Get("Set-Cookie"), "Secure") {
		t.Fatal("cookie must be Secure when X-Forwarded-Proto=https")
	}
}

// Finding #6: /metrics is open when no scrape token is set, requires a valid Bearer
// token when set, and is blocked while setup is pending.
func TestMetricsScrapeToken(t *testing.T) {
	s, st := newAuthServer(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	// Unset -> open.
	rr := httptest.NewRecorder()
	s.metricsAuth(ok).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("open /metrics expected 200, got %d", rr.Code)
	}

	// Set a token.
	c := st.LoadCPSettings(cpSettingsDefaults())
	c.MetricsScrapeTokenHash = hashKey("scrape-secret")
	c.MetricsScrapeTokenPrefix = "scrape-s"
	if err := st.SaveCPSettings(c); err != nil {
		t.Fatal(err)
	}

	// No/incorrect token -> 401.
	rr = httptest.NewRecorder()
	s.metricsAuth(ok).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("token set, no auth -> expected 401, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	bad := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	bad.Header.Set("Authorization", "Bearer wrong")
	s.metricsAuth(ok).ServeHTTP(rr, bad)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token -> expected 401, got %d", rr.Code)
	}

	// Correct token -> 200.
	rr = httptest.NewRecorder()
	good := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	good.Header.Set("Authorization", "Bearer scrape-secret")
	s.metricsAuth(ok).ServeHTTP(rr, good)
	if rr.Code != http.StatusOK {
		t.Fatalf("correct token -> expected 200, got %d", rr.Code)
	}

	// During setup, the gate blocks /metrics entirely.
	s.setupDone.Store(false)
	rr = httptest.NewRecorder()
	s.setupGate(ok).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "setup_required") {
		t.Fatalf("/metrics during setup should be 403 setup_required, got %d %s", rr.Code, rr.Body.String())
	}
	// /healthz stays public during setup.
	rr = httptest.NewRecorder()
	s.setupGate(ok).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/healthz should stay public during setup, got %d", rr.Code)
	}
}

// Finding #7: every password-setting handler enforces the shared strength policy.
func TestPasswordPolicyEnforced(t *testing.T) {
	s, _ := newAuthServer(t)
	// createUser rejects a weak password, accepts a strong one.
	rr := httptest.NewRecorder()
	s.createUser(rr, httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(
		`{"username":"weakling","password":"short","role":"readonly"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("weak password should be rejected: %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	s.createUser(rr, httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(
		`{"username":"strongun","password":"correcthorse7","role":"readonly"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("strong password should be accepted: %d %s", rr.Code, rr.Body.String())
	}
}

// Finding #8: advertised address must be an IP or host:port with an IP host.
func TestValidAdvertiseAddr(t *testing.T) {
	valid := []string{"10.0.0.5", "10.0.0.5:53", "2001:db8::1", "[2001:db8::1]:53"}
	invalid := []string{"", "evil.example.com", "evil.example.com:53", "10.0.0.5:notaport", "not an addr", "10.0.0.5 extra"}
	for _, v := range valid {
		if !validAdvertiseAddr(v) {
			t.Errorf("expected %q to be valid", v)
		}
	}
	for _, v := range invalid {
		if validAdvertiseAddr(v) {
			t.Errorf("expected %q to be rejected", v)
		}
	}
}
