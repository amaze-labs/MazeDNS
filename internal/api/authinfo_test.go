package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func authInfoJSON(t *testing.T, s *Server) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	s.authInfo(rr, httptest.NewRequest(http.MethodGet, "/api/auth/info", nil))
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Issue #94: SSO switched on but not loaded shows on the public sign-in info as
// unavailable, without leaking the reason (that stays in admin settings).
func TestAuthInfoReportsSSOUnavailable(t *testing.T) {
	s, _ := newSetupServer(t)
	if v := authInfoJSON(t, s); v["oidc_unavailable"] != false || v["oidc_enabled"] != false {
		t.Fatalf("SSO off: %v", v)
	}

	s.auth.SetOIDCConfigured(true)
	s.auth.SetOIDCError(errors.New("dial tcp sso.internal.example: no such host"), true)
	v := authInfoJSON(t, s)
	if v["oidc_unavailable"] != true || v["oidc_enabled"] != false {
		t.Fatalf("SSO down: %v", v)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "sso.internal.example") {
		t.Fatal("public auth info leaks the SSO error")
	}
	if st := s.oidcStatus(); st.Error == "" || !st.Retrying {
		t.Fatalf("admin status: %+v", st)
	}
}
