package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// CookieName is the session cookie name.
const CookieName = "mazedns_session"

// ErrInvalidCredentials is returned for a failed local login.
var ErrInvalidCredentials = errors.New("invalid credentials")

// SessionUser is the authenticated principal for a request.
type SessionUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Manager handles local login, server-side sessions, and optional OIDC.
type Manager struct {
	store *store.Store
	oidc  *OIDCProvider // nil if OIDC is not configured
	ttl   time.Duration
}

// NewManager builds a Manager. oidc may be nil.
func NewManager(st *store.Store, oidc *OIDCProvider, ttl time.Duration) *Manager {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Manager{store: st, oidc: oidc, ttl: ttl}
}

// OIDCEnabled reports whether OIDC login is available.
func (m *Manager) OIDCEnabled() bool { return m.oidc != nil }

// OIDC returns the OIDC provider (may be nil).
func (m *Manager) OIDC() *OIDCProvider { return m.oidc }

// Login verifies a local user and starts a session, returning the token + user.
func (m *Manager) Login(username, password string) (string, *SessionUser, error) {
	u, err := m.store.GetUserByUsername(username)
	if err != nil || u == nil || u.PasswordHash == "" {
		return "", nil, ErrInvalidCredentials
	}
	ok, err := VerifyPassword(u.PasswordHash, password)
	if err != nil || !ok {
		return "", nil, ErrInvalidCredentials
	}
	return m.StartSession(u.ID, u.Username, u.Role)
}

// StartSession creates a session for a user (used by local and OIDC login).
func (m *Manager) StartSession(id int64, username, role string) (string, *SessionUser, error) {
	token, err := NewToken()
	if err != nil {
		return "", nil, err
	}
	exp := time.Now().Add(m.ttl).Unix()
	if err := m.store.CreateSession(token, id, username, role, exp); err != nil {
		return "", nil, err
	}
	return token, &SessionUser{ID: id, Username: username, Role: role}, nil
}

// UserFromRequest returns the authenticated user for r, if the session is valid.
func (m *Manager) UserFromRequest(r *http.Request) (*SessionUser, bool) {
	ck, err := r.Cookie(CookieName)
	if err != nil {
		return nil, false
	}
	sess, err := m.store.GetSession(ck.Value)
	if err != nil || sess == nil {
		return nil, false
	}
	return &SessionUser{ID: sess.UserID, Username: sess.Username, Role: sess.Role}, true
}

// Logout deletes the session referenced by the request's cookie.
func (m *Manager) Logout(r *http.Request) {
	if ck, err := r.Cookie(CookieName); err == nil {
		_ = m.store.DeleteSession(ck.Value)
	}
}

// SetCookie writes the session cookie.
func (m *Manager) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.ttl.Seconds()),
	})
}

// ClearCookie removes the session cookie.
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
