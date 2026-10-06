package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/metrics"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// tokenEnv is a full control-plane router (auth on, cluster on) with one admin
// console session, for exercising the real route table.
type tokenEnv struct {
	t      *testing.T
	h      http.Handler
	st     *store.Store
	cookie *http.Cookie
}

func newTokenEnv(t *testing.T) *tokenEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mgr := auth.NewManager(st, nil, time.Hour)
	srv := New("127.0.0.1:0", st, resolver.New(resolver.Options{}), metrics.New(),
		func() error { return nil }, nil, mgr, true, false, true)
	srv.applyCPSettings(cpSettingsDefaults())
	hash, _ := auth.HashPassword("correcthorse7")
	id, err := st.CreateLocalUser("admin", hash, roleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	sess, _, err := mgr.StartSession(id, "admin", roleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return &tokenEnv{t: t, h: srv.http.Handler, st: st, cookie: &http.Cookie{Name: auth.CookieName, Value: sess}}
}

// do sends a request; cookie and authz ("" = none) set the credentials.
func (e *tokenEnv) do(method, path, body string, cookie bool, authz string) *httptest.ResponseRecorder {
	e.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie {
		r.AddCookie(e.cookie)
	}
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, r)
	return rr
}

// mint creates a token through the console API and returns its id and value.
func (e *tokenEnv) mint(name, role string, expiresAt int64) (string, string) {
	e.t.Helper()
	rr := e.do(http.MethodPost, "/api/tokens",
		fmt.Sprintf(`{"name":%q,"role":%q,"expires_at":%d}`, name, role, expiresAt), true, "")
	if rr.Code != http.StatusCreated {
		e.t.Fatalf("create token: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if !strings.HasPrefix(out.Token, auth.APITokenPrefix) || len(out.Token) < 40 {
		e.t.Fatalf("token value %q", out.Token)
	}
	return out.ID, out.Token
}

func bearer(tok string) string { return "Bearer " + tok }

func TestAPITokenRoles(t *testing.T) {
	e := newTokenEnv(t)
	_, ro := e.mint("dashboard", roleReadonly, 0)
	_, adm := e.mint("ipam-sync", roleAdmin, 0)

	// readonly: can read, cannot write.
	if rr := e.do(http.MethodGet, "/api/rewrites", "", false, bearer(ro)); rr.Code != http.StatusOK {
		t.Fatalf("readonly GET rewrites: %d %s", rr.Code, rr.Body.String())
	}
	if rr := e.do(http.MethodPost, "/api/rewrites", `{"domain":"nas.lan","rrtype":"A","value":"10.0.0.5"}`, false, bearer(ro)); rr.Code != http.StatusForbidden {
		t.Fatalf("readonly POST rewrites: %d, want 403", rr.Code)
	}

	// admin: full rewrite CRUD.
	rr := e.do(http.MethodPost, "/api/rewrites", `{"domain":"nas.lan","rrtype":"A","value":"10.0.0.5"}`, false, bearer(adm))
	if rr.Code != http.StatusCreated {
		t.Fatalf("admin POST rewrites: %d %s", rr.Code, rr.Body.String())
	}
	rws, _ := e.st.ListRewrites()
	if len(rws) != 1 {
		t.Fatalf("rewrites = %+v", rws)
	}
	path := fmt.Sprintf("/api/rewrites/%d", rws[0].ID)
	if rr := e.do(http.MethodPut, path, `{"domain":"nas.lan","rrtype":"A","value":"10.0.0.6","enabled":true}`, false, bearer(adm)); rr.Code/100 != 2 {
		t.Fatalf("admin PUT rewrite: %d %s", rr.Code, rr.Body.String())
	}
	if rr := e.do(http.MethodDelete, path, "", false, bearer(adm)); rr.Code/100 != 2 {
		t.Fatalf("admin DELETE rewrite: %d %s", rr.Code, rr.Body.String())
	}

	// /api/auth/me identifies the token.
	rr = e.do(http.MethodGet, "/api/auth/me", "", false, bearer(adm))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"username":"token:ipam-sync"`) ||
		!strings.Contains(rr.Body.String(), `"kind":"token"`) {
		t.Fatalf("me: %d %s", rr.Code, rr.Body.String())
	}
}

// Console-only routes refuse every token, whatever its role, while the same
// routes still work for an admin console session.
func TestAPITokenSessionOnlyRoutes(t *testing.T) {
	e := newTokenEnv(t)
	_, adm := e.mint("ipam-sync", roleAdmin, 0)

	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/users", ""},
		{http.MethodPost, "/api/users", `{"username":"x","password":"correcthorse7","role":"admin"}`},
		{http.MethodGet, "/api/tokens", ""},
		{http.MethodPost, "/api/tokens", `{"name":"escalate","role":"admin"}`},
		{http.MethodDelete, "/api/tokens/whatever", ""},
		{http.MethodPost, "/api/auth/password", `{}`},
		{http.MethodGet, "/api/settings/cp", ""},
		{http.MethodPut, "/api/settings/cp", `{}`},
		{http.MethodPost, "/api/settings/metrics-token", ""},
		{http.MethodGet, "/api/config/export", ""},
		{http.MethodPost, "/api/config/import", `{}`},
		{http.MethodPut, "/api/classifier/settings", `{}`},
		// Would send the stored LLM API key to an endpoint named in the request.
		{http.MethodPost, "/api/classifier/test", `{"provider":"openai","endpoint":"http://127.0.0.1:1","model":"m"}`},
		{http.MethodPut, "/api/netbird", `{}`},
		{http.MethodGet, "/api/cluster/enroll-keys", ""},
		{http.MethodPost, "/api/cluster/enroll-keys", `{"name":"k"}`},
		{http.MethodPost, "/api/cluster/nodes", `{"name":"n"}`},
	}
	for _, rt := range routes {
		if rr := e.do(rt.method, rt.path, rt.body, false, bearer(adm)); rr.Code != http.StatusForbidden {
			t.Errorf("token %s %s: %d, want 403", rt.method, rt.path, rr.Code)
		}
	}
	for _, path := range []string{"/api/users", "/api/tokens", "/api/settings/cp", "/api/cluster/enroll-keys"} {
		if rr := e.do(http.MethodGet, path, "", true, ""); rr.Code != http.StatusOK {
			t.Errorf("session GET %s: %d, want 200", path, rr.Code)
		}
	}
	if toks, _ := e.st.ListAPITokens(); len(toks) != 1 {
		t.Fatalf("a token minted another token: %+v", toks)
	}
}

// A Bearer header is judged alone; other schemes fall through to the cookie.
func TestAPITokenHeaderPrecedence(t *testing.T) {
	e := newTokenEnv(t)
	_, ro := e.mint("dashboard", roleReadonly, 0)
	write := `{"domain":"nas.lan","rrtype":"A","value":"10.0.0.5"}`

	// Readonly token + admin cookie: the token decides, so the write is refused.
	if rr := e.do(http.MethodPost, "/api/rewrites", write, true, bearer(ro)); rr.Code != http.StatusForbidden {
		t.Fatalf("token+cookie write: %d, want 403", rr.Code)
	}
	// Unknown bearer + valid cookie: 401, no fallback to the cookie.
	for _, bad := range []string{"mzd_doesnotexist", "not-a-mzd-token", ""} {
		if rr := e.do(http.MethodGet, "/api/rewrites", "", true, "Bearer "+bad); rr.Code != http.StatusUnauthorized {
			t.Fatalf("bad bearer %q + cookie: %d, want 401", bad, rr.Code)
		}
	}
	// A Basic header (e.g. from a proxy in front of the console) is not ours.
	if rr := e.do(http.MethodGet, "/api/rewrites", "", true, "Basic dXNlcjpwYXNz"); rr.Code != http.StatusOK {
		t.Fatalf("basic + cookie: %d, want 200", rr.Code)
	}
	// The scheme is case-insensitive.
	if rr := e.do(http.MethodGet, "/api/rewrites", "", false, "bearer "+ro); rr.Code != http.StatusOK {
		t.Fatalf("lowercase bearer: %d, want 200", rr.Code)
	}
	// A token never gets a session cookie.
	if rr := e.do(http.MethodGet, "/api/rewrites", "", false, bearer(ro)); len(rr.Result().Cookies()) != 0 {
		t.Fatalf("token request set cookies: %v", rr.Result().Cookies())
	}
}

func TestAPITokenRevokedAndExpired(t *testing.T) {
	e := newTokenEnv(t)
	id, tok := e.mint("ipam-sync", roleAdmin, time.Now().Add(time.Hour).Unix())
	if rr := e.do(http.MethodGet, "/api/rewrites", "", false, bearer(tok)); rr.Code != http.StatusOK {
		t.Fatalf("before revoke: %d", rr.Code)
	}
	if rr := e.do(http.MethodDelete, "/api/tokens/"+id, "", true, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	if rr := e.do(http.MethodGet, "/api/rewrites", "", false, bearer(tok)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("after revoke: %d, want 401", rr.Code)
	}
	if rr := e.do(http.MethodDelete, "/api/tokens/"+id, "", true, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("revoke twice: %d, want 404", rr.Code)
	}

	// An expired token (the API refuses a past expiry, so insert it directly).
	expired, _ := auth.NewAPIToken()
	if err := e.st.CreateAPIToken(store.APIToken{ID: "old", Name: "old", Role: roleAdmin,
		ExpiresAt: time.Now().Add(-time.Second).Unix()}, auth.HashAPIToken(expired)); err != nil {
		t.Fatal(err)
	}
	if rr := e.do(http.MethodGet, "/api/rewrites", "", false, bearer(expired)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("expired: %d, want 401", rr.Code)
	}
}

func TestAPITokenCreateValidationAndListing(t *testing.T) {
	e := newTokenEnv(t)
	for _, body := range []string{
		`{"name":"","role":"admin"}`,
		`{"name":"x","role":"superuser"}`,
		`{"name":"x","role":"admin","expires_at":1}`,
		`{"name":"` + strings.Repeat("n", maxAPITokenName+1) + `","role":"admin"}`,
	} {
		if rr := e.do(http.MethodPost, "/api/tokens", body, true, ""); rr.Code != http.StatusBadRequest {
			t.Errorf("create %s: %d, want 400", body, rr.Code)
		}
	}

	_, tok := e.mint("ipam-sync", roleAdmin, 0)
	_ = e.do(http.MethodGet, "/api/rewrites", "", false, bearer(tok)) // records last use

	rr := e.do(http.MethodGet, "/api/tokens", "", true, "")
	if strings.Contains(rr.Body.String(), tok) || strings.Contains(rr.Body.String(), auth.HashAPIToken(tok)) {
		t.Fatal("listing leaks the token or its hash")
	}
	var toks []store.APIToken
	_ = json.Unmarshal(rr.Body.Bytes(), &toks)
	if len(toks) != 1 || toks[0].Name != "ipam-sync" || toks[0].CreatedBy != "admin" ||
		toks[0].LastUsedAt == 0 || !strings.HasPrefix(tok, toks[0].TokenPrefix) {
		t.Fatalf("listing = %+v", toks)
	}

	// Creation and revocation are audited under the console user.
	entries, _ := e.st.ListAudit()
	if len(entries) == 0 || entries[len(entries)-1].Action != "apitoken.create" || entries[len(entries)-1].User != "admin" {
		t.Fatalf("audit = %+v", entries)
	}
}

// A token never outranks its creator: it acts as readonly once the creator is
// demoted, and stops working once the creator's account is deleted.
func TestAPITokenFollowsCreator(t *testing.T) {
	e := newTokenEnv(t)
	hash, _ := auth.HashPassword("correcthorse7")
	opsID, err := e.st.CreateLocalUser("ops", hash, roleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := auth.NewAPIToken()
	if err := e.st.CreateAPIToken(store.APIToken{ID: "ops-tok", Name: "ipam-sync", Role: roleAdmin,
		CreatedBy: "ops", CreatedByID: opsID, CreatedAt: time.Now().Unix()}, auth.HashAPIToken(tok)); err != nil {
		t.Fatal(err)
	}
	write := `{"domain":"nas.lan","rrtype":"A","value":"10.0.0.5"}`
	if rr := e.do(http.MethodPost, "/api/rewrites", write, false, bearer(tok)); rr.Code != http.StatusCreated {
		t.Fatalf("creator is admin: %d %s", rr.Code, rr.Body.String())
	}

	if err := e.st.UpdateUserRole(opsID, roleReadonly); err != nil {
		t.Fatal(err)
	}
	if rr := e.do(http.MethodGet, "/api/rewrites", "", false, bearer(tok)); rr.Code != http.StatusOK {
		t.Fatalf("creator demoted, GET: %d, want 200", rr.Code)
	}
	if rr := e.do(http.MethodPost, "/api/rewrites", `{"domain":"x.lan","rrtype":"A","value":"10.0.0.6"}`, false, bearer(tok)); rr.Code != http.StatusForbidden {
		t.Fatalf("creator demoted, POST: %d, want 403", rr.Code)
	}

	if err := e.st.DeleteUser(opsID); err != nil {
		t.Fatal(err)
	}
	if rr := e.do(http.MethodGet, "/api/rewrites", "", false, bearer(tok)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("creator deleted: %d, want 401", rr.Code)
	}

	// A new account with the same username (e.g. an SSO email re-provisioned)
	// is a different person: it must not revive the old creator's token.
	if _, err := e.st.CreateLocalUser("ops", hash, roleAdmin); err != nil {
		t.Fatal(err)
	}
	if rr := e.do(http.MethodGet, "/api/rewrites", "", false, bearer(tok)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("same-name account recreated: %d, want 401", rr.Code)
	}
}
