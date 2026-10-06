package auth

import (
	"crypto/sha256"
	"encoding/hex"
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

// HashAPIToken is the at-rest form of an API token.
func HashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// APITokenDisplayPrefix is the part of a token shown in the console to tell
// tokens apart (the prefix plus 4 characters).
func APITokenDisplayPrefix(token string) string {
	if n := len(APITokenPrefix) + 4; len(token) > n {
		return token[:n]
	}
	return token
}

// bearerToken returns the credential of an "Authorization: Bearer ..." header.
// Other schemes (e.g. Basic, added by a reverse proxy in front of the console)
// are not ours and are ignored, so they never lock a cookie session out.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	return strings.TrimSpace(h[7:]), true
}

// userFromAPIToken resolves a bearer token to its principal. Revocation and
// expiry take effect on the next request: every request looks the token up.
//
// A token never outranks the admin who created it, checked on every request: it
// stops working once its creator's account is deleted, and an admin token acts
// as readonly once its creator is no longer an admin (including an SSO user
// whose role changed at the provider). So removing someone's access also removes
// the access of any token they may have kept a copy of.
func (m *Manager) userFromAPIToken(token string) (*SessionUser, bool) {
	if !strings.HasPrefix(token, APITokenPrefix) {
		return nil, false
	}
	now := time.Now()
	t, err := m.store.GetAPITokenByHash(HashAPIToken(token), now.Unix())
	if err != nil || t == nil {
		return nil, false
	}
	creator, err := m.store.GetUserByUsername(t.CreatedBy)
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
