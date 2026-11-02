package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// mfaClient drives the MFA flow against handlers directly, carrying the
// session cookie between calls like a browser.
type mfaClient struct {
	t      *testing.T
	s      *Server
	cookie *http.Cookie
}

func (c *mfaClient) do(h http.HandlerFunc, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	c.t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	rr := httptest.NewRecorder()
	h(rr, r)
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == auth.CookieName && ck.Value != "" {
			c.cookie = ck
		}
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func (c *mfaClient) login(user, pw string) (*httptest.ResponseRecorder, map[string]any) {
	c.cookie = nil
	return c.do(c.s.login, "/api/auth/login", `{"username":"`+user+`","password":"`+pw+`"}`)
}

func jsonBody(kv map[string]string) string {
	b, _ := json.Marshal(kv)
	return string(b)
}

// enroll turns MFA on for the signed-in user and returns the secret and the
// recovery codes.
func (c *mfaClient) enroll() (string, []string) {
	c.t.Helper()
	rr, out := c.do(c.s.mfaSetup, "/api/auth/mfa/setup", `{}`)
	if rr.Code != http.StatusOK {
		c.t.Fatalf("setup: %d %s", rr.Code, rr.Body)
	}
	secret := out["secret"].(string)
	if !strings.HasPrefix(out["uri"].(string), "otpauth://totp/MazeDNS:admin?") {
		c.t.Errorf("uri %v", out["uri"])
	}
	// The code of the previous step: the next sign-in uses the current one, and
	// each step can only be used once.
	code, _ := auth.TOTPCode(secret, time.Now().Add(-30*time.Second))
	rr, out = c.do(c.s.mfaEnable, "/api/auth/mfa/enable", jsonBody(map[string]string{"code": code}))
	if rr.Code != http.StatusOK {
		c.t.Fatalf("enable: %d %s", rr.Code, rr.Body)
	}
	var codes []string
	for _, v := range out["recovery_codes"].([]any) {
		codes = append(codes, v.(string))
	}
	if len(codes) != auth.RecoveryCodeCount {
		c.t.Fatalf("got %d recovery codes", len(codes))
	}
	return secret, codes
}

func TestMFAEnrollAndSignIn(t *testing.T) {
	s, st := newAuthServer(t)
	c := &mfaClient{t: t, s: s}
	if rr, _ := c.login("admin", "correcthorse7"); rr.Code != http.StatusOK || c.cookie == nil {
		t.Fatalf("plain login: %d", rr.Code)
	}
	secret, recovery := c.enroll()

	// The password alone no longer signs in.
	rr, out := c.login("admin", "correcthorse7")
	if rr.Code != http.StatusOK || out["mfa"] != "verify" || c.cookie != nil {
		t.Fatalf("login with MFA on: %d %v cookie=%v", rr.Code, out, c.cookie)
	}
	challenge := out["challenge"].(string)

	// A wrong code keeps the challenge and says how many tries are left.
	rr, _ = c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": challenge, "code": "000000"}))
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "4 left") || c.cookie != nil {
		t.Fatalf("wrong code: %d %s", rr.Code, rr.Body)
	}
	code, _ := auth.TOTPCode(secret, time.Now())
	rr, _ = c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": challenge, "code": code}))
	if rr.Code != http.StatusOK || c.cookie == nil {
		t.Fatalf("right code: %d %s", rr.Code, rr.Body)
	}

	// The challenge is single-use, and the same code can't sign in twice.
	rr, _ = c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": challenge, "code": code}))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("challenge reused: %d", rr.Code)
	}
	_, out = c.login("admin", "correcthorse7")
	rr, _ = c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": out["challenge"].(string), "code": code}))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code accepted: %d", rr.Code)
	}

	// A recovery code works once, typed loosely, and is audited.
	_, out = c.login("admin", "correcthorse7")
	loose := " " + strings.ToUpper(strings.Replace(recovery[3], "-", "", 1))
	rr, _ = c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": out["challenge"].(string), "code": loose}))
	if rr.Code != http.StatusOK {
		t.Fatalf("recovery code: %d %s", rr.Code, rr.Body)
	}
	_, out = c.login("admin", "correcthorse7")
	rr, _ = c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": out["challenge"].(string), "code": recovery[3]}))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("recovery code reused: %d", rr.Code)
	}
	if !auditHas(t, st, "auth.mfa.recovery_code") || !auditHas(t, st, "auth.mfa.enabled") {
		t.Error("missing audit entries")
	}
}

func TestMFAChallengeAttemptLimit(t *testing.T) {
	s, _ := newAuthServer(t)
	c := &mfaClient{t: t, s: s}
	c.login("admin", "correcthorse7")
	secret, _ := c.enroll()
	_, out := c.login("admin", "correcthorse7")
	challenge := out["challenge"].(string)
	for i := 0; i < mfaMaxAttempts; i++ {
		c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": challenge, "code": "000000"}))
	}
	code, _ := auth.TOTPCode(secret, time.Now())
	rr, _ := c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": challenge, "code": code}))
	if rr.Code != http.StatusUnauthorized || c.cookie != nil {
		t.Fatalf("a right code after %d wrong ones signed in: %d", mfaMaxAttempts, rr.Code)
	}
}

func TestMFARequiredPolicy(t *testing.T) {
	s, st := newAuthServer(t)
	cfg := cpSettingsDefaults()
	cfg.RequireMFA = true
	if err := st.SaveCPSettings(cfg); err != nil {
		t.Fatal(err)
	}
	c := &mfaClient{t: t, s: s}

	// Not enrolled: the password leads to setup, not to a session.
	rr, out := c.login("admin", "correcthorse7")
	if rr.Code != http.StatusOK || out["mfa"] != "setup" || c.cookie != nil {
		t.Fatalf("login under policy: %d %v", rr.Code, out)
	}
	challenge := out["challenge"].(string)
	rr, out = c.do(s.mfaSetup, "/api/auth/mfa/setup", jsonBody(map[string]string{"challenge": challenge}))
	if rr.Code != http.StatusOK {
		t.Fatalf("setup via challenge: %d %s", rr.Code, rr.Body)
	}
	// A setup challenge can't be used to skip the code check at /verify.
	if rr, _ := c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": challenge, "code": "123456"})); rr.Code != http.StatusUnauthorized {
		t.Fatalf("setup challenge accepted at verify: %d", rr.Code)
	}
	code, _ := auth.TOTPCode(out["secret"].(string), time.Now())
	rr, out = c.do(s.mfaEnable, "/api/auth/mfa/enable", jsonBody(map[string]string{"challenge": challenge, "code": code}))
	if rr.Code != http.StatusOK || out["user"] == nil || c.cookie == nil || len(out["recovery_codes"].([]any)) != auth.RecoveryCodeCount {
		t.Fatalf("enable via challenge: %d %v", rr.Code, out)
	}

	// With the policy on, the user can't turn it off themselves.
	// Refused before the code is even checked.
	rr, _ = c.do(s.mfaDisable, "/api/auth/mfa/disable", jsonBody(map[string]string{"password": "correcthorse7", "code": "123456"}))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("disable under policy: %d", rr.Code)
	}
}

func TestMFADisableAndAdminReset(t *testing.T) {
	s, st := newAuthServer(t)
	hash, _ := auth.HashPassword("anotherhorse8")
	bobID, _ := st.CreateLocalUser("bob", hash, "readonly")

	// bob enrolls, then turns it off: password and a current code needed.
	bob := &mfaClient{t: t, s: s}
	bob.login("bob", "anotherhorse8")
	rr, out := bob.do(s.mfaSetup, "/api/auth/mfa/setup", `{}`)
	secret := out["secret"].(string)
	code, _ := auth.TOTPCode(secret, time.Now().Add(-30*time.Second))
	bob.do(s.mfaEnable, "/api/auth/mfa/enable", jsonBody(map[string]string{"code": code}))
	code, _ = auth.TOTPCode(secret, time.Now())
	if rr, _ = bob.do(s.mfaDisable, "/api/auth/mfa/disable", jsonBody(map[string]string{"password": "wrong", "code": code})); rr.Code != http.StatusUnauthorized {
		t.Fatalf("disable with a wrong password: %d", rr.Code)
	}
	if rr, _ = bob.do(s.mfaDisable, "/api/auth/mfa/disable", jsonBody(map[string]string{"password": "anotherhorse8", "code": code})); rr.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body)
	}
	if s.mfaEnabled(bobID) {
		t.Fatal("still enabled after disable")
	}

	// bob enrolls again and loses the phone: the admin resets it, which also
	// ends bob's sessions.
	rr, out = bob.do(s.mfaSetup, "/api/auth/mfa/setup", `{}`)
	code, _ = auth.TOTPCode(out["secret"].(string), time.Now())
	bob.do(s.mfaEnable, "/api/auth/mfa/enable", jsonBody(map[string]string{"code": code}))
	admin := &mfaClient{t: t, s: s}
	admin.login("admin", "correcthorse7")
	r := httptest.NewRequest(http.MethodDelete, "/api/users/x/mfa", nil)
	r.SetPathValue("id", jsonNum(bobID))
	r.AddCookie(admin.cookie)
	rr = httptest.NewRecorder()
	s.requireSession(roleAdmin, s.resetUserMFA)(rr, r)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("admin reset: %d %s", rr.Code, rr.Body)
	}
	if s.mfaEnabled(bobID) {
		t.Fatal("still enabled after admin reset")
	}
	r = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.AddCookie(bob.cookie)
	if _, ok := s.auth.UserFromRequest(r); ok {
		t.Error("bob's session survived the reset")
	}
	if !auditHas(t, st, "user.mfa_reset") {
		t.Error("reset not audited")
	}
}

func TestMFAListAndMe(t *testing.T) {
	s, _ := newAuthServer(t)
	c := &mfaClient{t: t, s: s}
	c.login("admin", "correcthorse7")
	c.enroll()

	rr := httptest.NewRecorder()
	s.listUsers(rr, httptest.NewRequest(http.MethodGet, "/api/users", nil))
	var users []store.User
	_ = json.Unmarshal(rr.Body.Bytes(), &users)
	if len(users) != 1 || !users[0].MFAEnabled {
		t.Errorf("list: %+v", users)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.AddCookie(c.cookie)
	rr = httptest.NewRecorder()
	s.me(rr, r)
	if !strings.Contains(rr.Body.String(), `"mfa_enabled":true`) {
		t.Errorf("me: %s", rr.Body)
	}
}

func jsonNum(n int64) string { b, _ := json.Marshal(n); return string(b) }

func auditHas(t *testing.T, st *store.Store, action string) bool {
	t.Helper()
	entries, err := st.ListAudit()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

// Fresh challenges (each with its own tries) don't reset the per-account limit
// on code guesses, even with the login rate limit turned off.
func TestMFAGuessLimitAcrossChallenges(t *testing.T) {
	s, _ := newAuthServer(t)
	s.applyCPSettings(store.CPSettings{SessionTTLSec: 3600, LoginRateAttempts: 0, LoginRateWindowSec: 60})
	c := &mfaClient{t: t, s: s}
	c.login("admin", "correcthorse7")
	secret, _ := c.enroll()

	guesses := 1 // confirming the setup used one
	for guesses < mfaCodeLimit {
		_, out := c.login("admin", "correcthorse7")
		challenge := out["challenge"].(string)
		for i := 0; i < 3 && guesses < mfaCodeLimit; i++ {
			rr, _ := c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": challenge, "code": "000000"}))
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("guess %d: %d", guesses+1, rr.Code)
			}
			guesses++
		}
	}
	// The limit is spent: a new challenge with the right code is still refused.
	_, out := c.login("admin", "correcthorse7")
	code, _ := auth.TOTPCode(secret, time.Now())
	rr, _ := c.do(s.mfaVerify, "/api/auth/mfa/verify", jsonBody(map[string]string{"challenge": out["challenge"].(string), "code": code}))
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" || c.cookie != nil {
		t.Fatalf("after %d guesses: %d %s", mfaCodeLimit, rr.Code, rr.Body)
	}
}
