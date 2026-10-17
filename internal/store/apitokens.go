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
	CreatedAt   int64 `json:"created_at"`
	LastUsedAt  int64 `json:"last_used_at"` // 0 = never
	ExpiresAt   int64 `json:"expires_at"`   // 0 = never
	// EffectiveRole is what the token can do right now (ListAPITokens only): its
	// role capped by its creator's current role, or "" once the creator's account
	// is gone and the token no longer works.
	EffectiveRole string `json:"effective_role"`
}

// ErrAPITokenNotFound is returned when deleting an unknown token.
var ErrAPITokenNotFound = errors.New("api token not found")

// CreateAPIToken stores a new token, keyed by the token's hash.
func (s *Store) CreateAPIToken(t APIToken, token string) error {
	if token == "" {
		return errors.New("token is required")
	}
	_, err := s.db.Exec(
		`INSERT INTO api_tokens(id, name, token_hash, token_prefix, role, created_by, created_by_id, created_at, last_used_at, expires_at)
		 VALUES(?,?,?,?,?,?,?,?,0,?)`,
		t.ID, t.Name, hashSecret(token), t.TokenPrefix, t.Role, t.CreatedBy, t.CreatedByID, t.CreatedAt, t.ExpiresAt)
	return err
}

// ListAPITokens returns every token, newest first, with its effective role. The
// hash is never returned.
func (s *Store) ListAPITokens() ([]APIToken, error) {
	rows, err := s.read.Query(
		`SELECT t.id, t.name, t.token_prefix, t.role, t.created_by, t.created_at, t.last_used_at, t.expires_at,
		        CASE WHEN u.id IS NULL THEN '' WHEN u.role <> 'admin' THEN u.role ELSE t.role END
		 FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by_id
		 ORDER BY t.created_at DESC, t.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.Role, &t.CreatedBy,
			&t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt, &t.EffectiveRole); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetAPIToken returns the token for the raw value if it exists and has not
// expired at now (unix secs), or (nil, nil).
func (s *Store) GetAPIToken(token string, now int64) (*APIToken, error) {
	if token == "" {
		return nil, nil
	}
	var t APIToken
	err := s.read.QueryRow(
		`SELECT id, name, token_prefix, role, created_by, created_by_id, created_at, last_used_at, expires_at
		 FROM api_tokens WHERE token_hash=?`, hashSecret(token)).
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

// DeleteAPITokensForUser revokes every token a user created (on account
// deletion), returning how many were removed.
func (s *Store) DeleteAPITokensForUser(userID int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM api_tokens WHERE created_by_id=?`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
