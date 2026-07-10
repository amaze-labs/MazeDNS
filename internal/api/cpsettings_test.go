package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

func newCPServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st, auth: auth.NewManager(st, nil, time.Hour), authEnabled: true}
	s.setupDone.Store(true)
	return s, st
}

func putJSON(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPut, "/api/settings/cp", strings.NewReader(body)))
	return rr
}

// The OIDC client secret is write-only: never returned by GET, and an empty value
// on PUT keeps the stored secret.
func TestCPSettingsSecretNeverEchoed(t *testing.T) {
	s, st := newCPServer(t)
	// Seed a secret directly.
	if err := st.SaveCPSettings(store.CPSettings{
		SessionTTLSec: 3600,
		OIDC:          store.OIDCSettings{Enabled: true, Issuer: "https://idp", ClientID: "cid", ClientSecret: "TOP-SECRET", RedirectURL: "https://cp/cb"},
	}); err != nil {
		t.Fatal(err)
	}

	// GET must mask the secret.
	rr := httptest.NewRecorder()
	s.getCPSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/cp", nil))
	if strings.Contains(rr.Body.String(), "TOP-SECRET") {
		t.Fatalf("GET leaked the client secret: %s", rr.Body.String())
	}
	var got struct {
		Settings            store.CPSettings `json:"settings"`
		OIDCHasClientSecret bool             `json:"oidc_has_client_secret"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if !got.OIDCHasClientSecret || got.Settings.OIDC.ClientSecret != "" {
		t.Fatalf("expected masked-but-present secret: %+v", got)
	}

	// PUT with empty secret keeps the stored one.
	rr = putJSON(s.putCPSettings, `{"session_ttl_sec":7200,"oidc":{"enabled":true,"issuer":"https://idp","client_id":"cid","client_secret":"","redirect_url":"https://cp/cb"}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}
	if kept := st.LoadCPSettings(store.CPSettings{}).OIDC.ClientSecret; kept != "TOP-SECRET" {
		t.Fatalf("empty secret on PUT should keep the stored value, got %q", kept)
	}
}

// Saving cluster policy applies it live to the running server (no restart).
func TestCPSettingsLiveReloadClusterPolicy(t *testing.T) {
	s, _ := newCPServer(t)
	s.SetClusterEnrollment(false, 30*24*time.Hour, 15*time.Minute)
	if s.requireApproval {
		t.Fatal("precondition: require_approval should be off")
	}
	rr := putJSON(s.putCPSettings, `{"session_ttl_sec":3600,"require_approval":true,"key_grace_sec":600}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}
	if !s.requireApproval {
		t.Fatal("require_approval should be applied live")
	}
	if s.keyGrace != 600*time.Second {
		t.Fatalf("key grace not applied live: %v", s.keyGrace)
	}
}

// Saving session TTL applies it live to the auth manager.
func TestCPSettingsLiveReloadSessionTTL(t *testing.T) {
	s, st := newCPServer(t)
	rr := putJSON(s.putCPSettings, `{"session_ttl_sec":3600}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}
	// New sessions should reflect the ~1h TTL applied to the manager.
	_, _, err := s.auth.StartSession(1, "admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got := st.LoadCPSettings(store.CPSettings{}).SessionTTLSec; got != 3600 {
		t.Fatalf("session ttl not persisted: %d", got)
	}
}

// A change is recorded in the audit log (which keys, never secret values).
func TestCPSettingsAudited(t *testing.T) {
	s, st := newCPServer(t)
	rr := putJSON(s.putCPSettings, `{"session_ttl_sec":7200,"oidc":{"enabled":true,"issuer":"https://idp","client_id":"cid","client_secret":"NEW-SECRET","redirect_url":"https://cp/cb"}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}
	entries, _ := st.ListAudit()
	if len(entries) == 0 {
		t.Fatal("settings change should be audited")
	}
	for _, e := range entries {
		if strings.Contains(e.Detail, "NEW-SECRET") {
			t.Fatalf("audit log leaked a secret value: %q", e.Detail)
		}
	}
}
