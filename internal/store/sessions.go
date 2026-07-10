package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// Session is an authenticated session (server-side, revocable).
type Session struct {
	Token     string
	UserID    int64
	Username  string
	Role      string
	ExpiresAt int64
}

// hashSessionToken is the at-rest form of a bearer session token. Tokens are
// stored hashed (like node/enrollment keys) so a database read can't be used to
// impersonate a live session; the raw token lives only in the user's cookie.
func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateSession stores a new session, keyed by the token's hash.
func (s *Store) CreateSession(token string, userID int64, username, role string, expiresAt int64) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions(token, user_id, username, role, expires_at) VALUES(?,?,?,?,?)`,
		hashSessionToken(token), userID, username, role, expiresAt)
	return err
}

// GetSession returns a non-expired session for the raw token, or (nil, nil) if
// missing or expired. The lookup hashes the token first, so sessions predating the
// hashing upgrade (raw tokens in the DB) no longer match and are effectively
// invalidated — those users simply re-login.
func (s *Store) GetSession(token string) (*Session, error) {
	h := hashSessionToken(token)
	se := &Session{}
	err := s.read.QueryRow(
		`SELECT token, user_id, username, role, expires_at FROM sessions WHERE token=?`, h).
		Scan(&se.Token, &se.UserID, &se.Username, &se.Role, &se.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() > se.ExpiresAt {
		_ = s.deleteSessionHash(h)
		return nil, nil
	}
	return se, nil
}

// DeleteSession removes the session for the raw token.
func (s *Store) DeleteSession(token string) error {
	return s.deleteSessionHash(hashSessionToken(token))
}

// deleteSessionHash removes a session by its stored hash.
func (s *Store) deleteSessionHash(hash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, hash)
	return err
}

// DeleteSessionsForUser revokes all of a user's sessions (e.g. on delete, role
// change, or admin password reset).
func (s *Store) DeleteSessionsForUser(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

// DeleteExpiredSessions purges expired sessions.
func (s *Store) DeleteExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
	return err
}
