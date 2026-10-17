package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// APITokenPrefix starts every API token, so a leaked token is greppable and
// never mistaken for a session token.
const APITokenPrefix = "mzd_"

// Principal kinds (SessionUser.Kind).
const (
	KindSession = "session"
	KindToken   = "token"
)

// apiTokenTouchEvery bounds how often a token's last_used_at is written, so a
// busy integration doesn't cost a database write per request.
const apiTokenTouchEvery = time.Minute

// NewAPIToken returns a fresh API token: APITokenPrefix + 32 random bytes,
// base64url.
func NewAPIToken() (string, error) {
	t, err := NewToken()
	if err != nil {
		return "", err
	}
	return APITokenPrefix + t, nil
}

// APITokenDisplayPrefix is the part of a token shown in the console to tell
// tokens apart (the prefix plus 4 characters).
func APITokenDisplayPrefix(token string) string {
	if n := len(APITokenPrefix) + 4; len(token) > n {
		return token[:n]
	}
	return token
}

// bearerToken returns the API token of an "Authorization: Bearer mzd_..."
// header. Any other credential (Basic, or a Bearer JWT forwarded by an
// authenticating proxy such as oauth2-proxy in front of the console) is not ours
// and is ignored, so it never locks a cookie session out.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	if !strings.HasPrefix(tok, APITokenPrefix) {
		return "", false
	}
	return tok, true
}

// userFromAPIToken resolves a bearer token to its principal. Revocation and
// expiry take effect on the next request: every request looks the token up.
//
// A token never outranks the account that created it, checked on every request
// against that account's current role in MazeDNS: it stops working once the
// account is deleted, and an admin token acts as readonly once the account is no
// longer an admin. An SSO account's role is only refreshed when its owner signs
// in, so a change at the provider reaches their tokens at that point; to cut an
// SSO user off at once, delete their account here (which revokes their tokens).
func (m *Manager) userFromAPIToken(token string) (*SessionUser, bool) {
	now := time.Now()
	t, err := m.store.GetAPIToken(token, now.Unix())
	if err != nil || t == nil {
		return nil, false
	}
	creator, err := m.store.GetUserByID(t.CreatedByID)
	if err != nil || creator == nil {
		return nil, false
	}
	role := t.Role
	if creator.Role != "admin" {
		role = creator.Role
	}
	m.touchAPIToken(t, now)
	return &SessionUser{Username: "token:" + t.Name, Role: role, Kind: KindToken, TokenID: t.ID}, true
}

// touchAPIToken records the token's use, at most once per apiTokenTouchEvery.
func (m *Manager) touchAPIToken(t *store.APIToken, now time.Time) {
	last := t.LastUsedAt
	if v, ok := m.tokenTouched.Load(t.ID); ok && v.(int64) > last {
		last = v.(int64)
	}
	if now.Unix()-last < int64(apiTokenTouchEvery.Seconds()) {
		return
	}
	m.tokenTouched.Store(t.ID, now.Unix())
	_ = m.store.TouchAPIToken(t.ID, now.Unix())
}
