package store

import (
	"database/sql"
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

// CreateSession stores a new session.
func (s *Store) CreateSession(token string, userID int64, username, role string, expiresAt int64) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions(token, user_id, username, role, expires_at) VALUES(?,?,?,?,?)`,
		token, userID, username, role, expiresAt)
	return err
}

// GetSession returns a non-expired session, or (nil, nil) if missing or expired.
func (s *Store) GetSession(token string) (*Session, error) {
	se := &Session{}
	err := s.read.QueryRow(
		`SELECT token, user_id, username, role, expires_at FROM sessions WHERE token=?`, token).
		Scan(&se.Token, &se.UserID, &se.Username, &se.Role, &se.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() > se.ExpiresAt {
		_ = s.DeleteSession(token)
		return nil, nil
	}
	return se, nil
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
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
