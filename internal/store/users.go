package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// User is an account (local password or OIDC-provisioned).
type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Role         string `json:"role"`   // "admin" | "readonly"
	Source       string `json:"source"` // "local" | "oidc"
	AvatarURL    string `json:"avatar_url"`
	Subject      string `json:"-"`
	PasswordHash string `json:"-"`
	UpdatedAt    int64  `json:"updated_at"`
}

// CountUsers returns the number of users.
func (s *Store) CountUsers() (int64, error) {
	var n int64
	err := s.read.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateLocalUser inserts a local (password) user and returns its id.
func (s *Store) CreateLocalUser(username, passwordHash, role string) (int64, error) {
	return s.insertID(
		`INSERT INTO users(username, role, source, subject, password_hash, updated_at)
		 VALUES(?,?, 'local', '', ?, ?)`,
		username, role, passwordHash, time.Now().Unix())
}

// ListUsers returns all users ordered by username.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.read.Query(
		`SELECT id, username, role, source, updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Source, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountAdmins returns the number of admin users (used to protect the last admin).
func (s *Store) CountAdmins() (int64, error) {
	var n int64
	err := s.read.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&n)
	return n, err
}

// GetUserByID returns the user, or (nil, nil) if not found.
func (s *Store) GetUserByID(id int64) (*User, error) {
	u := &User{}
	err := s.read.QueryRow(
		`SELECT id, username, role, source, avatar_url, subject, password_hash, updated_at FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.Role, &u.Source, &u.AvatarURL, &u.Subject, &u.PasswordHash, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// UpdateUserRole changes a user's role.
func (s *Store) UpdateUserRole(id int64, role string) error {
	_, err := s.db.Exec(`UPDATE users SET role=?, updated_at=? WHERE id=?`, role, time.Now().Unix(), id)
	return err
}

// UpdateUserPassword sets a user's password hash.
func (s *Store) UpdateUserPassword(id int64, passwordHash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash=?, updated_at=? WHERE id=?`, passwordHash, time.Now().Unix(), id)
	return err
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

// GetUserByUsername returns the user, or (nil, nil) if not found.
func (s *Store) GetUserByUsername(username string) (*User, error) {
	u := &User{}
	err := s.read.QueryRow(
		`SELECT id, username, role, source, avatar_url, subject, password_hash, updated_at FROM users WHERE username=?`,
		username).
		Scan(&u.ID, &u.Username, &u.Role, &u.Source, &u.AvatarURL, &u.Subject, &u.PasswordHash, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetOIDCUserBySubject returns the OIDC account with the given stable subject, or
// (nil, nil) if none. Subject — not the mutable, IdP-controllable username — is the
// identity key for SSO accounts.
func (s *Store) GetOIDCUserBySubject(subject string) (*User, error) {
	u := &User{}
	err := s.read.QueryRow(
		`SELECT id, username, role, source, avatar_url, subject, password_hash, updated_at
		 FROM users WHERE source='oidc' AND subject=?`, subject).
		Scan(&u.ID, &u.Username, &u.Role, &u.Source, &u.AvatarURL, &u.Subject, &u.PasswordHash, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// freeUsername returns base, or base with a numeric suffix, so it does not collide
// with any existing account (mirrors uniqueNodeName). Used to give a first-time
// SSO user a distinct display name rather than merging into a same-named account.
func (s *Store) freeUsername(base string) (string, error) {
	candidate := base
	for i := 2; ; i++ {
		u, err := s.GetUserByUsername(candidate)
		if err != nil {
			return "", err
		}
		if u == nil {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s-%d", base, i)
	}
}

// UpsertOIDCUser provisions or refreshes an OIDC account, keyed on the stable
// subject (NOT the username). This prevents SSO account takeover: an IdP user
// whose derived username matches an existing account can no longer merge into —
// and log in as — that account (including a local break-glass admin).
//
//   - existing subject  -> update role/avatar on that row only (username stays put)
//   - new subject       -> insert a NEW account; if the derived username collides
//     with a DIFFERENT existing account, store a de-duplicated (suffixed) username
//
// It never updates a local account (matches only source='oidc' rows on update), so
// a local user's source or password_hash can never be changed by an SSO login.
func (s *Store) UpsertOIDCUser(subject, username, role, avatarURL string) (*User, error) {
	now := time.Now().Unix()
	if existing, err := s.GetOIDCUserBySubject(subject); err != nil {
		return nil, err
	} else if existing != nil {
		// Known SSO identity: refresh role + avatar. Keep the stored (possibly
		// de-duplicated) username stable so a preferred_username change at the IdP
		// doesn't churn the display name or risk a fresh collision.
		if _, err := s.db.Exec(
			`UPDATE users SET role=?, avatar_url=?, updated_at=? WHERE id=? AND source='oidc'`,
			role, avatarURL, now, existing.ID); err != nil {
			return nil, err
		}
		return s.GetUserByID(existing.ID)
	}
	// First login for this subject: pick a display username that does not collide
	// with any existing account, then create a separate row.
	display, err := s.freeUsername(username)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(
		`INSERT INTO users(username, role, source, avatar_url, subject, password_hash, updated_at)
		 VALUES(?,?, 'oidc', ?, ?, '', ?)`,
		display, role, avatarURL, subject, now); err != nil {
		return nil, err
	}
	return s.GetUserByUsername(display)
}
