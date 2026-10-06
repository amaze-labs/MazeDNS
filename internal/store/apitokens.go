package store

import (
	"database/sql"
	"errors"
)

// APIToken is a bearer credential for integrations calling the admin API. Only
// the hash of the token is stored (plus a short display prefix); the token is
// shown once, at creation.
type APIToken struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TokenPrefix string `json:"token_prefix"`
	Role        string `json:"role"`
	CreatedBy   string `json:"created_by"`
	// CreatedByID is the creator's users.id. A token is only valid while that
	// account exists; matching on the id (never reused) rather than the
	// username keeps a later account with the same name from reviving it.
	CreatedByID int64 `json:"-"`
	CreatedAt   int64  `json:"created_at"`
	LastUsedAt  int64  `json:"last_used_at"` // 0 = never
	ExpiresAt   int64  `json:"expires_at"`   // 0 = never
}

// ErrAPITokenNotFound is returned when deleting an unknown token.
var ErrAPITokenNotFound = errors.New("api token not found")

// CreateAPIToken stores a new token (already hashed by the caller).
func (s *Store) CreateAPIToken(t APIToken, tokenHash string) error {
	if tokenHash == "" {
		return errors.New("token hash is required")
	}
	_, err := s.db.Exec(
		`INSERT INTO api_tokens(id, name, token_hash, token_prefix, role, created_by, created_by_id, created_at, last_used_at, expires_at)
		 VALUES(?,?,?,?,?,?,?,?,0,?)`,
		t.ID, t.Name, tokenHash, t.TokenPrefix, t.Role, t.CreatedBy, t.CreatedByID, t.CreatedAt, t.ExpiresAt)
	return err
}

// ListAPITokens returns every token, newest first. The hash is never returned.
func (s *Store) ListAPITokens() ([]APIToken, error) {
	rows, err := s.read.Query(
		`SELECT id, name, token_prefix, role, created_by, created_at, last_used_at, expires_at
		 FROM api_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.Role, &t.CreatedBy,
			&t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetAPITokenByHash returns the token with the given hash if it exists and has
// not expired at now (unix secs), or (nil, nil).
func (s *Store) GetAPITokenByHash(tokenHash string, now int64) (*APIToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	var t APIToken
	err := s.read.QueryRow(
		`SELECT id, name, token_prefix, role, created_by, created_by_id, created_at, last_used_at, expires_at
		 FROM api_tokens WHERE token_hash=?`, tokenHash).
		Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.Role, &t.CreatedBy, &t.CreatedByID, &t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if t.ExpiresAt != 0 && t.ExpiresAt <= now {
		return nil, nil
	}
	return &t, nil
}

// TouchAPIToken records that a token was used at ts (unix secs).
func (s *Store) TouchAPIToken(id string, ts int64) error {
	_, err := s.db.Exec(`UPDATE api_tokens SET last_used_at=? WHERE id=?`, ts, id)
	return err
}

// DeleteAPIToken revokes a token and returns its name. It stops working on the
// next request, since every request looks the token up.
func (s *Store) DeleteAPIToken(id string) (string, error) {
	var name string
	err := s.db.QueryRow(`SELECT name FROM api_tokens WHERE id=?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAPITokenNotFound
	}
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`DELETE FROM api_tokens WHERE id=?`, id)
	return name, err
}
