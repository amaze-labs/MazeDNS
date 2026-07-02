package api

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// clientIP extracts the request's source IP for logging (best effort).
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// Setup mode solves the unauthenticated-first-boot problem: on a fresh control
// plane (auth enabled, no users) the API refuses everything except the setup
// wizard until setup completes. It uses trust-on-first-use (Grafana-style):
// whoever reaches the fresh control plane first completes setup — the operator is
// expected NOT to expose the CP publicly until that happens. The setup endpoints:
//
//   - work only while setup is incomplete,
//   - are rate-limited and logged,
//   - flip the completed flag ATOMICALLY with admin creation and SSO config, and
//   - are permanently closed (410 Gone) afterwards.

// EnableSetupMode puts the server into first-boot setup mode. Called only when
// auth is enabled and no admin exists yet.
func (s *Server) EnableSetupMode() {
	s.setupDone.Store(false)
}

// setupActive reports whether first-boot setup is still pending.
func (s *Server) setupActive() bool { return !s.setupDone.Load() }

// setupGate wraps the mux so that, while setup is pending, only the wizard,
// static assets, and health/metrics are reachable; every other API route returns
// 403 {"setup_required":true} so the SPA redirects to the wizard.
func (s *Server) setupGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.setupActive() {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		switch {
		case p == "/healthz" || p == "/metrics",
			strings.HasPrefix(p, "/api/setup"),
			p == "/api/auth/info",          // public; carries setup_required so the SPA knows
			!strings.HasPrefix(p, "/api/"): // static assets + SPA shell
			next.ServeHTTP(w, r)
		default:
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":          "setup required",
				"setup_required": true,
			})
		}
	})
}

// setupStatus reports whether the wizard should run. Public and always available.
func (s *Server) setupStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"setup_required": s.setupActive()})
}

// setupLimiter is a tiny fixed-window rate limiter for setup attempts.
type setupLimiter struct {
	mu       sync.Mutex
	windowAt time.Time
	count    int
}

func (l *setupLimiter) allow(limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.windowAt) > window {
		l.windowAt = now
		l.count = 0
	}
	l.count++
	return l.count <= limit
}

// setupComplete finishes first-boot setup, atomically closing it. The operator
// chooses how the control plane authenticates:
//
//   - method "local": create a local admin (username+password).
//   - method "sso":   configure an OIDC provider. A local break-glass admin is
//     created alongside it by default (break_glass), so a misconfigured or
//     unreachable IdP can never lock the operator out; opting out leaves the CLI
//     `control-plane reset-admin` path as recovery. The OIDC issuer's discovery
//     document is fetched and verified BEFORE completion — a bad issuer blocks
//     setup with an inline error, so completion never persists a broken provider.
//
// The completed flag flips together with the admin mapping and the SSO config in a
// single transaction (store.CompleteSetup). When a local admin exists (local mode,
// or SSO+break-glass) a session is started so the wizard proceeds authenticated
// into the optional steps.
func (s *Server) setupComplete(w http.ResponseWriter, r *http.Request) {
	if !s.setupActive() {
		writeError(w, http.StatusGone, "setup already completed")
		return
	}
	if !s.setupRate.allow(10, time.Minute) {
		slog.Warn("setup: rate limit exceeded", "remote", clientIP(r))
		writeError(w, http.StatusTooManyRequests, "too many setup attempts; try again shortly")
		return
	}
	var in struct {
		Method     string             `json:"method"` // "local" | "sso"
		Username   string             `json:"username"`
		Password   string             `json:"password"`
		OIDC       store.OIDCSettings `json:"oidc"`
		BreakGlass bool               `json:"break_glass"` // SSO mode: also create a local admin
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	params := store.SetupParams{}
	sso := strings.EqualFold(strings.TrimSpace(in.Method), "sso")
	// A local admin is created in local mode always, and in SSO mode when the
	// break-glass account is kept (the default).
	needLocalAdmin := !sso || in.BreakGlass
	username := strings.TrimSpace(in.Username)

	if needLocalAdmin {
		if username == "" {
			writeError(w, http.StatusBadRequest, "username required")
			return
		}
		if msg := passwordStrengthError(in.Password); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		hash, err := auth.HashPassword(in.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "hash failed")
			return
		}
		params.AdminUsername = username
		params.AdminPasswordHash = hash
	}

	if sso {
		o := in.OIDC
		o.Enabled = true
		o.Issuer = strings.TrimSpace(o.Issuer)
		o.ClientID = strings.TrimSpace(o.ClientID)
		o.RedirectURL = strings.TrimSpace(o.RedirectURL)
		o.AdminEmail = strings.TrimSpace(o.AdminEmail)
		if o.Issuer == "" || o.ClientID == "" || o.RedirectURL == "" {
			writeError(w, http.StatusBadRequest, "SSO requires issuer, client ID, and redirect URL")
			return
		}
		if o.AdminEmail == "" {
			writeError(w, http.StatusBadRequest, "SSO requires the admin email (who becomes admin on first login)")
			return
		}
		// A break-glass account only helps if local login stays reachable, so keep
		// password login on whenever it exists; otherwise go SSO-only.
		o.DisablePasswordLogin = !in.BreakGlass
		// Validate discovery BEFORE completing: build the provider (fetches
		// /.well-known/openid-configuration). This also swaps the live provider, so
		// on success SSO is immediately usable; on failure nothing is persisted.
		if s.rebuildOIDC != nil {
			if err := s.rebuildOIDC(o); err != nil {
				slog.Warn("setup: OIDC validation failed", "issuer", o.Issuer, "err", err, "remote", clientIP(r))
				writeError(w, http.StatusBadGateway, "SSO provider validation failed: "+err.Error())
				return
			}
		}
		params.OIDC = &o
	}

	completed, err := s.store.CompleteSetup(params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !completed {
		// A concurrent request already completed setup.
		s.setupDone.Store(true)
		writeError(w, http.StatusGone, "setup already completed")
		return
	}
	s.setupDone.Store(true)

	detail := "local admin " + username
	if sso {
		if in.BreakGlass {
			detail = "SSO (" + params.OIDC.Issuer + ") + break-glass admin " + username
		} else {
			detail = "SSO only (" + params.OIDC.Issuer + ")"
		}
	}
	slog.Info("setup completed", "mode", authMode(sso), "detail", detail, "remote", clientIP(r))
	_ = s.store.AppendAudit(store.AuditEntry{User: username, Action: "setup.complete", Detail: detail})

	// Start a session when a local admin exists so the wizard continues
	// authenticated. SSO-only setups have no local session; the wizard directs the
	// operator to sign in with SSO instead.
	authenticated := false
	if params.AdminUsername != "" {
		if u, _ := s.store.GetUserByUsername(username); u != nil {
			if token, _, serr := s.auth.StartSession(u.ID, u.Username, u.Role); serr == nil {
				s.auth.SetCookie(w, token)
				authenticated = true
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":      username,
		"role":          "admin",
		"authenticated": authenticated,
	})
}

// authMode labels the chosen auth method for logs.
func authMode(sso bool) string {
	if sso {
		return "sso"
	}
	return "local"
}

// passwordStrengthError returns a validation message, or "" if the password is
// acceptable (>= 10 chars with some variety).
func passwordStrengthError(pw string) string {
	if len(pw) < 10 {
		return "password must be at least 10 characters"
	}
	var hasLetter, hasOther bool
	for _, r := range pw {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		default:
			hasOther = true
		}
	}
	if !hasLetter || !hasOther {
		return "password must mix letters with digits or symbols"
	}
	return ""
}
