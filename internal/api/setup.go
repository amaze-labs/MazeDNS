package api

import (
	"crypto/subtle"
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

// constantTimeEqual compares two strings without leaking length-independent timing.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// clientIP extracts the request's source IP for logging (best effort).
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// Setup mode solves the unauthenticated-first-boot problem: on a fresh control
// plane (auth enabled, no users) the API refuses everything except the setup
// wizard until an admin is created. The wizard is guarded by a one-time token
// printed to the container log (Portainer-style) — the only robust defense when
// the CP port is reachable before any admin exists. The setup endpoints:
//
//   - work only while setup is incomplete,
//   - require the setup token (constant-time compared), rate-limited and logged,
//   - flip the completed flag ATOMICALLY with admin creation, and
//   - are permanently closed (410 Gone) afterwards.

// EnableSetupMode puts the server into first-boot setup mode with the given
// one-time token. Called only when auth is enabled and no admin exists yet.
func (s *Server) EnableSetupMode(token string) {
	s.setupToken = token
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

// setupComplete creates the first admin, atomically closing setup. Requires the
// one-time setup token. On success it starts a session so the wizard can continue
// authenticated into the optional steps.
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
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !constantTimeEqual(strings.TrimSpace(in.Token), s.setupToken) {
		slog.Warn("setup: invalid token", "remote", clientIP(r))
		writeError(w, http.StatusUnauthorized, "invalid setup token")
		return
	}
	username := strings.TrimSpace(in.Username)
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
	created, err := s.store.CreateFirstAdmin(username, hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !created {
		// A concurrent request already created the first admin.
		s.setupDone.Store(true)
		writeError(w, http.StatusGone, "setup already completed")
		return
	}
	s.setupDone.Store(true)
	s.setupToken = "" // burn the token
	slog.Info("setup completed: first admin created", "username", username, "remote", clientIP(r))
	_ = s.store.AppendAudit(store.AuditEntry{User: username, Action: "setup.complete", Detail: "created first admin " + username})

	// Start a session so the wizard proceeds authenticated into the optional steps.
	u, _ := s.store.GetUserByUsername(username)
	if u != nil {
		if token, _, serr := s.auth.StartSession(u.ID, u.Username, u.Role); serr == nil {
			s.auth.SetCookie(w, token)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": username, "role": "admin"})
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
