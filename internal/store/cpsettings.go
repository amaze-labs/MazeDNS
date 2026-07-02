package store

import (
	"encoding/json"
	"time"
)

// cpSettingsKey holds the control-plane runtime settings (JSON) in app_meta —
// everything the operator configures through the UI that used to live in env/YAML:
// SSO/OIDC, auth session TTL, cluster policy, and the query-log toggle. Resolver,
// classifier, and metrics/logs export settings have their own stores; this blob
// covers the remainder so the control plane is fully GUI-configurable.
const cpSettingsKey = "cp_settings"

// setupCompletedKey marks that first-boot setup finished (an admin exists). Once
// set, the setup wizard endpoints are permanently closed.
const setupCompletedKey = "setup_completed"

// OIDCSettings is the DB-backed SSO configuration (mirrors config.OIDC). The client
// secret is retrievable (needed to build the provider) but never returned by the
// API — handlers mask it and treat an empty value on write as "unchanged".
type OIDCSettings struct {
	Enabled              bool     `json:"enabled"`
	Issuer               string   `json:"issuer"`
	ClientID             string   `json:"client_id"`
	ClientSecret         string   `json:"client_secret"`
	RedirectURL          string   `json:"redirect_url"`
	Scopes               []string `json:"scopes"`
	GroupsClaim          string   `json:"groups_claim"`
	AdminGroup           string   `json:"admin_group"`
	DisablePasswordLogin bool     `json:"disable_password_login"`
	AutoLogin            bool     `json:"auto_login"`
}

// CPSettings is the control-plane's UI-editable runtime configuration.
type CPSettings struct {
	SessionTTLSec int          `json:"session_ttl_sec"` // auth session lifetime (seconds)
	OIDC          OIDCSettings `json:"oidc"`
	// Cluster policy.
	RequireApproval bool   `json:"require_approval"`
	KeyMaxAgeSec    int64  `json:"key_max_age_sec"` // 0 = default (server applies 30d)
	KeyGraceSec     int64  `json:"key_grace_sec"`   // 0 = default (server applies 15m)
	AdvertiseAddr   string `json:"advertise_addr"`  // mirrored to master_advertise_addr for enrollment
	// Misc.
	QueryLog bool `json:"query_log"` // query-log toggle (agent-facing; documented)
}

// LoadCPSettings returns the stored control-plane settings, or def when unset.
func (s *Store) LoadCPSettings(def CPSettings) CPSettings {
	raw, err := s.GetMeta(cpSettingsKey)
	if err != nil || raw == "" {
		return def
	}
	var c CPSettings
	if json.Unmarshal([]byte(raw), &c) != nil {
		return def
	}
	return c
}

// SaveCPSettings persists the control-plane settings. It mirrors AdvertiseAddr to
// the dedicated master_advertise_addr key that the enrollment path reads.
func (s *Store) SaveCPSettings(c CPSettings) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := s.SetMeta(cpSettingsKey, string(b)); err != nil {
		return err
	}
	return s.SetMasterAdvertiseAddr(c.AdvertiseAddr)
}

// EnsureCPSettings seeds the settings from def only if none are stored yet — the
// seed-once path so an existing env/YAML deployment upgrades transparently, after
// which the DB is the single source of truth. Returns true if it seeded.
func (s *Store) EnsureCPSettings(def CPSettings) (bool, error) {
	if raw, _ := s.GetMeta(cpSettingsKey); raw != "" {
		return false, nil
	}
	return true, s.SaveCPSettings(def)
}

// SetupCompleted reports whether first-boot setup has finished.
func (s *Store) SetupCompleted() bool {
	v, _ := s.GetMeta(setupCompletedKey)
	return v == "1"
}

// CreateFirstAdmin atomically creates the initial admin, but only if no users
// exist yet, and marks setup complete in the same transaction. It returns
// (created, error): created is false (with no error) when a user already exists,
// so concurrent setup attempts resolve to exactly one admin. Portable across
// SQLite and Postgres via INSERT … WHERE NOT EXISTS.
func (s *Store) CreateFirstAdmin(username, passwordHash string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	res, err := tx.Exec(
		`INSERT INTO users(username, role, source, subject, password_hash, updated_at)
		 SELECT ?, 'admin', 'local', '', ?, ?
		 WHERE NOT EXISTS (SELECT 1 FROM users)`,
		username, passwordHash, time.Now().Unix())
	if err != nil {
		_ = tx.Rollback()
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		_ = tx.Rollback()
		return false, nil // someone else already created the first admin
	}
	if _, err := tx.Exec(
		`INSERT INTO app_meta(key, value) VALUES(?, '1') ON CONFLICT(key) DO UPDATE SET value='1'`,
		setupCompletedKey); err != nil {
		_ = tx.Rollback()
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// --- settings audit log ---

const cpAuditKey = "cp_settings_audit"

// AuditEntry is one settings-change record (who/when/what — never secret values).
type AuditEntry struct {
	TS     int64  `json:"ts"`
	User   string `json:"user"`
	Action string `json:"action"` // e.g. "settings.oidc", "settings.cluster"
	Detail string `json:"detail"` // human summary of changed keys (no secrets)
}

// AppendAudit records a settings change, keeping the most recent 200 entries.
func (s *Store) AppendAudit(e AuditEntry) error {
	entries, _ := s.ListAudit()
	if e.TS == 0 {
		e.TS = time.Now().Unix()
	}
	entries = append(entries, e)
	if len(entries) > 200 {
		entries = entries[len(entries)-200:]
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return s.SetMeta(cpAuditKey, string(b))
}

// ListAudit returns the settings-change audit log (oldest first).
func (s *Store) ListAudit() ([]AuditEntry, error) {
	raw, err := s.GetMeta(cpAuditKey)
	if err != nil || raw == "" {
		return []AuditEntry{}, err
	}
	var out []AuditEntry
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []AuditEntry{}, nil
	}
	return out, nil
}
