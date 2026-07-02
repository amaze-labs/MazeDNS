package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// SetRebuildOIDC wires the callback that swaps the running OIDC provider when SSO
// settings change (owned by main, which builds the provider from config).
func (s *Server) SetRebuildOIDC(fn func(store.OIDCSettings) error) { s.rebuildOIDC = fn }

// cpSettingsDefaults returns the baseline used when nothing is stored yet.
func cpSettingsDefaults() store.CPSettings {
	return store.CPSettings{SessionTTLSec: 24 * 3600}
}

// getCPSettings returns the control-plane runtime settings with all secrets
// masked. Secrets are reported as has_* booleans so the UI can show "set/unset"
// without ever receiving the value.
func (s *Server) getCPSettings(w http.ResponseWriter, _ *http.Request) {
	c := s.store.LoadCPSettings(cpSettingsDefaults())
	hasSecret := c.OIDC.ClientSecret != ""
	c.OIDC.ClientSecret = "" // never leak
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":               c,
		"oidc_has_client_secret": hasSecret,
	})
}

// putCPSettings validates, persists, and live-applies the control-plane runtime
// settings. Empty secret fields mean "leave unchanged" so masked values round-trip.
// Every change is audit-logged (which keys, never secret values) and applied
// without a restart.
func (s *Server) putCPSettings(w http.ResponseWriter, r *http.Request) {
	var in store.CPSettings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cur := s.store.LoadCPSettings(cpSettingsDefaults())

	// Secrets: empty on write keeps the stored value.
	in.OIDC.Issuer = strings.TrimSpace(in.OIDC.Issuer)
	in.OIDC.ClientID = strings.TrimSpace(in.OIDC.ClientID)
	in.OIDC.RedirectURL = strings.TrimSpace(in.OIDC.RedirectURL)
	in.AdvertiseAddr = strings.TrimSpace(in.AdvertiseAddr)
	if in.OIDC.ClientSecret == "" {
		in.OIDC.ClientSecret = cur.OIDC.ClientSecret
	}
	if in.SessionTTLSec <= 0 {
		in.SessionTTLSec = cur.SessionTTLSec
	}
	if in.SessionTTLSec <= 0 {
		in.SessionTTLSec = 24 * 3600
	}
	if in.KeyMaxAgeSec < 0 {
		in.KeyMaxAgeSec = 0
	}
	if in.KeyGraceSec < 0 {
		in.KeyGraceSec = 0
	}
	// OIDC validation only when enabled.
	if in.OIDC.Enabled {
		if in.OIDC.Issuer == "" || in.OIDC.ClientID == "" || in.OIDC.RedirectURL == "" {
			writeError(w, http.StatusBadRequest, "SSO requires issuer, client ID, and redirect URL")
			return
		}
	}

	if err := s.store.SaveCPSettings(in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// --- live apply, no restart ---
	s.applyCPSettings(in)

	// Rebuild OIDC provider if SSO config changed materially.
	if s.rebuildOIDC != nil && oidcChanged(cur.OIDC, in.OIDC) {
		if err := s.rebuildOIDC(in.OIDC); err != nil {
			// Persisted but provider failed: report so the admin can fix it. SSO stays
			// on the previous provider (or off), never locking anyone out.
			writeError(w, http.StatusBadGateway, "settings saved, but SSO provider init failed: "+err.Error())
			return
		}
	}

	user := auditUser(s, r)
	_ = s.store.AppendAudit(store.AuditEntry{
		User: user, Action: "settings.cp", Detail: cpSettingsDiff(cur, in),
	})

	c := in
	c.OIDC.ClientSecret = ""
	writeJSON(w, http.StatusOK, map[string]any{"settings": c, "oidc_has_client_secret": in.OIDC.ClientSecret != ""})
}

// applyCPSettings pushes runtime settings into the live services (auth session
// TTL + cluster enrollment policy). advertise_addr is mirrored to app_meta inside
// SaveCPSettings, which the enrollment path reads directly.
func (s *Server) applyCPSettings(c store.CPSettings) {
	if s.auth != nil {
		s.auth.SetSessionTTL(time.Duration(c.SessionTTLSec) * time.Second)
	}
	keyMaxAge := time.Duration(c.KeyMaxAgeSec) * time.Second
	if keyMaxAge == 0 {
		keyMaxAge = 30 * 24 * time.Hour // server default when unset
	}
	s.SetClusterEnrollment(c.RequireApproval, keyMaxAge, time.Duration(c.KeyGraceSec)*time.Second)
}

// getSettingsAudit returns the settings-change audit log (newest first).
func (s *Server) getSettingsAudit(w http.ResponseWriter, _ *http.Request) {
	entries, err := s.store.ListAudit()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Reverse to newest-first for display.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	writeJSON(w, http.StatusOK, entries)
}

// auditUser returns the acting username for the audit log, if known.
func auditUser(s *Server, r *http.Request) string {
	if u, ok := s.currentUser(r); ok {
		return u
	}
	return "system"
}

// oidcChanged reports whether the OIDC provider must be rebuilt.
func oidcChanged(a, b store.OIDCSettings) bool {
	return a.Enabled != b.Enabled || a.Issuer != b.Issuer || a.ClientID != b.ClientID ||
		a.ClientSecret != b.ClientSecret || a.RedirectURL != b.RedirectURL ||
		strings.Join(a.Scopes, ",") != strings.Join(b.Scopes, ",") ||
		a.GroupsClaim != b.GroupsClaim || a.AdminGroup != b.AdminGroup
}

// cpSettingsDiff summarizes which setting groups changed (never secret values).
func cpSettingsDiff(a, b store.CPSettings) string {
	var ch []string
	if a.SessionTTLSec != b.SessionTTLSec {
		ch = append(ch, fmt.Sprintf("session_ttl=%ds", b.SessionTTLSec))
	}
	if oidcChanged(a.OIDC, b.OIDC) {
		ch = append(ch, fmt.Sprintf("sso(enabled=%t)", b.OIDC.Enabled))
	}
	if a.RequireApproval != b.RequireApproval {
		ch = append(ch, fmt.Sprintf("require_approval=%t", b.RequireApproval))
	}
	if a.KeyMaxAgeSec != b.KeyMaxAgeSec {
		ch = append(ch, fmt.Sprintf("key_max_age=%ds", b.KeyMaxAgeSec))
	}
	if a.KeyGraceSec != b.KeyGraceSec {
		ch = append(ch, fmt.Sprintf("key_grace=%ds", b.KeyGraceSec))
	}
	if a.AdvertiseAddr != b.AdvertiseAddr {
		ch = append(ch, "advertise_addr")
	}
	if a.QueryLog != b.QueryLog {
		ch = append(ch, fmt.Sprintf("query_log=%t", b.QueryLog))
	}
	if len(ch) == 0 {
		return "no changes"
	}
	return strings.Join(ch, ", ")
}
