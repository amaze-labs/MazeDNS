package store

import (
	"database/sql"
	"errors"
	"time"
)

// User is an account (local password or OIDC-provisioned).
type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Role         string `json:"role"`   // "admin" | "readonly"
	Source       string `json:"source"` // "local" | "oidc"
	Subject      string `json:"-"`
	PasswordHash string `json:"-"`
	UpdatedAt    int64  `json:"updated_at"`
}

// CountUsers returns the number of users.
func (s *Store) CountUsers() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateLocalUser inserts a local (password) user and returns its id.
func (s *Store) CreateLocalUser(username, passwordHash, role string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO users(username, role, source, subject, password_hash, updated_at)
		 VALUES(?,?, 'local', '', ?, ?)`,
		username, role, passwordHash, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetUserByUsername returns the user, or (nil, nil) if not found.
func (s *Store) GetUserByUsername(username string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(
		`SELECT id, username, role, source, subject, password_hash, updated_at FROM users WHERE username=?`,
		username).
		Scan(&u.ID, &u.Username, &u.Role, &u.Source, &u.Subject, &u.PasswordHash, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// UpsertOIDCUser creates or updates an OIDC user (keyed by username) and returns it.
func (s *Store) UpsertOIDCUser(subject, username, role string) (*User, error) {
	now := time.Now().Unix()
	if _, err := s.db.Exec(
		`INSERT INTO users(username, role, source, subject, password_hash, updated_at)
		 VALUES(?,?, 'oidc', ?, '', ?)
		 ON CONFLICT(username) DO UPDATE SET
		   role=excluded.role, source='oidc', subject=excluded.subject, updated_at=excluded.updated_at`,
		username, role, subject, now); err != nil {
		return nil, err
	}
	return s.GetUserByUsername(username)
}
