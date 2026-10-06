package auth

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestBearerToken(t *testing.T) {
	for h, want := range map[string]string{
		"Bearer mzd_abc":     "mzd_abc",
		"bearer  mzd_abc ":   "mzd_abc",
		"BEARER mzd_abc":     "mzd_abc",
		"Basic dXNlcjpwYXNz": "",
		"Bearer":             "",
		"":                   "",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		got, ok := bearerToken(r)
		if got != want || ok != (want != "" || strings.HasPrefix(strings.ToLower(h), "bearer ")) {
			t.Errorf("bearerToken(%q) = %q,%v; want %q", h, got, ok, want)
		}
	}
}

// SSO-only mode refuses password login but has no say over API tokens.
func TestAPITokenWorksWithSSOOnly(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := NewManager(st, &OIDCProvider{disablePasswordLogin: true}, time.Hour)
	if !m.OIDC().DisablePasswordLogin() {
		t.Fatal("precondition: SSO-only")
	}

	adminID, err := st.CreateLocalUser("admin", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := NewAPIToken()
	if err := st.CreateAPIToken(store.APIToken{ID: "t1", Name: "ipam-sync", Role: "admin", CreatedBy: "admin", CreatedByID: adminID}, HashAPIToken(tok)); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/rewrites", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	u, ok := m.UserFromRequest(r)
	if !ok || u.Kind != KindToken || u.Role != "admin" || u.Username != "token:ipam-sync" || u.TokenID != "t1" {
		t.Fatalf("principal = %+v, %v", u, ok)
	}
}
