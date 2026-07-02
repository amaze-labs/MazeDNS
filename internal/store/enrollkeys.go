package store

import (
	"database/sql"
	"errors"
	"time"
)

// EnrollKey is a UI-managed cluster enrollment secret. Only the hash of the secret
// is stored (plus a short display prefix), exactly like a node key. An enrollment
// key bootstraps a node's identity at /api/cluster/enroll and authenticates nowhere
// else; ongoing auth uses the per-node key.
type EnrollKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	KeyPrefix string `json:"key_prefix"`
	CreatedAt int64  `json:"created_at"`
	CreatedBy string `json:"created_by"`
	ExpiresAt int64  `json:"expires_at"` // 0 = never
	MaxUses   int64  `json:"max_uses"`   // 0 = unlimited
	UseCount  int64  `json:"use_count"`
	Revoked   bool   `json:"revoked"`
	// Status is derived (not stored): active | expired | exhausted | revoked.
	Status string `json:"status"`
}

// enrollKeyStatus derives a display status from an enrollment key's state.
func enrollKeyStatus(revoked bool, expiresAt, maxUses, useCount, now int64) string {
	switch {
	case revoked:
		return "revoked"
	case expiresAt != 0 && expiresAt <= now:
		return "expired"
	case maxUses != 0 && useCount >= maxUses:
		return "exhausted"
	default:
		return "active"
	}
}

// CreateEnrollKey inserts a new enrollment key (secret already hashed by the
// caller). expiresAt is a unix timestamp (0 = never); maxUses is 0 for unlimited.
func (s *Store) CreateEnrollKey(id, name, keyHash, keyPrefix, createdBy string, expiresAt, maxUses int64) error {
	if keyHash == "" {
		return errors.New("key hash is required")
	}
	_, err := s.db.Exec(
		`INSERT INTO enroll_keys(id, name, key_hash, key_prefix, created_at, created_by, expires_at, max_uses, use_count, revoked)
		 VALUES(?,?,?,?,?,?,?,?,0,0)`,
		id, name, keyHash, keyPrefix, time.Now().Unix(), createdBy, expiresAt, maxUses)
	return err
}

// EnsureEnrollKey idempotently inserts an enrollment key by hash (no-op if one
// with the same hash already exists). Used to import a deprecated config
// join_token as a DB key on first boot.
func (s *Store) EnsureEnrollKey(id, name, keyHash, keyPrefix string) error {
	if keyHash == "" {
		return errors.New("key hash is required")
	}
	_, err := s.db.Exec(
		`INSERT INTO enroll_keys(id, name, key_hash, key_prefix, created_at, created_by, expires_at, max_uses, use_count, revoked)
		 VALUES(?,?,?,?,?,'config',0,0,0,0)
		 ON CONFLICT(key_hash) DO NOTHING`,
		id, name, keyHash, keyPrefix, time.Now().Unix())
	return err
}

// ListEnrollKeys returns all enrollment keys (newest first) with a derived status.
// The secret hash is never returned.
func (s *Store) ListEnrollKeys() ([]EnrollKey, error) {
	rows, err := s.read.Query(
		`SELECT id, name, key_prefix, created_at, created_by, expires_at, max_uses, use_count, revoked
		 FROM enroll_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().Unix()
	out := []EnrollKey{}
	for rows.Next() {
		var k EnrollKey
		var revoked int
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.CreatedAt, &k.CreatedBy,
			&k.ExpiresAt, &k.MaxUses, &k.UseCount, &revoked); err != nil {
			return nil, err
		}
		k.Revoked = revoked != 0
		k.Status = enrollKeyStatus(k.Revoked, k.ExpiresAt, k.MaxUses, k.UseCount, now)
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeEnrollKey marks an enrollment key revoked; it can no longer enroll or
// re-enroll any node.
func (s *Store) RevokeEnrollKey(id string) error {
	res, err := s.db.Exec(`UPDATE enroll_keys SET revoked=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("enrollment key not found")
	}
	return nil
}

// ConsumeEnrollKey atomically validates and consumes one use of the enrollment key
// with the given hash. It returns true only when the key exists, is not revoked,
// is not expired, and has a use left — incrementing use_count in the same
// statement so concurrent enrollments can never exceed max_uses. Used for NEW node
// enrollments.
func (s *Store) ConsumeEnrollKey(keyHash string, now int64) (bool, error) {
	if keyHash == "" {
		return false, nil
	}
	res, err := s.db.Exec(
		`UPDATE enroll_keys SET use_count = use_count + 1
		 WHERE key_hash=? AND revoked=0
		   AND (expires_at=0 OR expires_at>?)
		   AND (max_uses=0 OR use_count<max_uses)`,
		keyHash, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// EnrollKeyValid reports whether an enrollment key with the given hash is currently
// usable (exists, not revoked, not expired, not exhausted) WITHOUT consuming a use.
// Used for re-enrollment of an already-authorized node: an expired/exhausted/revoked
// key must not affect an existing node, but a valid one shouldn't burn a use on
// recovery. Returns the key's prefix for logging when valid.
func (s *Store) EnrollKeyValid(keyHash string, now int64) (bool, string, error) {
	if keyHash == "" {
		return false, "", nil
	}
	var prefix string
	var expiresAt, maxUses, useCount int64
	var revoked int
	err := s.read.QueryRow(
		`SELECT key_prefix, expires_at, max_uses, use_count, revoked FROM enroll_keys WHERE key_hash=?`, keyHash).
		Scan(&prefix, &expiresAt, &maxUses, &useCount, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, "", nil
		}
		return false, "", err
	}
	valid := enrollKeyStatus(revoked != 0, expiresAt, maxUses, useCount, now) == "active"
	return valid, prefix, nil
}
