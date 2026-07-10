package store

import (
	"path/filepath"
	"testing"
	"time"
)

// Finding #1: an OIDC login whose derived username matches an EXISTING local
// account must NOT merge into it (no takeover); it gets a separate, de-duplicated
// account, and the local account is left untouched (source + password preserved).
func TestOIDCUsernameCollisionCreatesSeparateAccount(t *testing.T) {
	s := openTestStore(t)

	adminID, err := s.CreateLocalUser("admin", "local-hash", "admin")
	if err != nil {
		t.Fatal(err)
	}

	// An IdP user presents preferred_username="admin" (the local admin's name).
	u, err := s.UpsertOIDCUser("oidc-subject-1", "admin", "readonly", "")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == adminID {
		t.Fatal("OIDC login merged into the local admin account (takeover)")
	}
	if u.Source != "oidc" {
		t.Fatalf("new SSO account should be source=oidc, got %q", u.Source)
	}
	if u.Username == "admin" {
		t.Fatalf("SSO account should get a de-duplicated username, got %q", u.Username)
	}

	// The local admin is unchanged: still local, still holds its password hash.
	local, _ := s.GetUserByID(adminID)
	if local == nil || local.Source != "local" || local.PasswordHash != "local-hash" {
		t.Fatalf("local admin was mutated by SSO login: %+v", local)
	}
	if n, _ := s.CountUsers(); n != 2 {
		t.Fatalf("expected 2 distinct accounts, got %d", n)
	}
}

// Finding #1: a returning OIDC user whose preferred_username changed at the IdP is
// still keyed on the stable subject — it stays ONE account (no duplicate).
func TestOIDCUsernameChangeKeepsOneAccount(t *testing.T) {
	s := openTestStore(t)

	first, err := s.UpsertOIDCUser("subject-xyz", "bob", "readonly", "")
	if err != nil {
		t.Fatal(err)
	}
	// Same subject, new preferred_username + role.
	second, err := s.UpsertOIDCUser("subject-xyz", "bob-renamed", "admin", "https://idp/a.png")
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("subject-keyed upsert should update the same row: %d != %d", second.ID, first.ID)
	}
	if second.Role != "admin" || second.AvatarURL != "https://idp/a.png" {
		t.Fatalf("role/avatar should refresh: %+v", second)
	}
	if n, _ := s.CountUsers(); n != 1 {
		t.Fatalf("username change must not create a second account, got %d users", n)
	}
}

// Finding #1 migration: a DB carrying legacy duplicate OIDC rows for one subject
// (an artifact of the old username-keyed upsert) is collapsed to a single account
// so the unique subject index can be enforced, without aborting startup.
func TestMigrationDedupesDuplicateOIDCSubjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dup.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a legacy DB: drop the unique subject index, then inject two rows with
	// the SAME subject but different usernames, as the old username-keyed upsert
	// could produce.
	if _, err := s.db.Exec(`DROP INDEX idx_users_oidc_subject`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, name := range []string{"alice", "alice2"} {
		if _, err := s.db.Exec(
			`INSERT INTO users(username, role, source, subject, password_hash, updated_at)
			 VALUES(?, 'readonly', 'oidc', 'shared-subject', '', ?)`, name, now); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	// Re-open: migrate() must dedupe and create the unique index without error.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-open with duplicate subjects should not fail: %v", err)
	}
	defer s2.Close()
	u, err := s2.GetOIDCUserBySubject("shared-subject")
	if err != nil || u == nil {
		t.Fatalf("subject should resolve to one row: %+v %v", u, err)
	}
	var n int
	if err := s2.read.QueryRow(`SELECT COUNT(*) FROM users WHERE subject='shared-subject'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("duplicate subjects should collapse to 1 row, got %d", n)
	}
}

// Finding #5: sessions are stored hashed — a raw token inserted directly (as old
// pre-upgrade rows were) no longer resolves, while the hashed round-trip does.
func TestSessionTokensHashed(t *testing.T) {
	s := openTestStore(t)
	exp := time.Now().Unix() + 3600

	if err := s.CreateSession("raw-token", 1, "admin", "admin", exp); err != nil {
		t.Fatal(err)
	}
	// The stored value is the hash, not the raw token.
	var stored string
	if err := s.read.QueryRow(`SELECT token FROM sessions WHERE user_id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "raw-token" {
		t.Fatal("session token stored in clear")
	}
	if stored != hashSessionToken("raw-token") {
		t.Fatalf("stored token is not the sha256 hash: %q", stored)
	}
	// Lookup by the raw token (as the cookie carries it) still works.
	if se, _ := s.GetSession("raw-token"); se == nil {
		t.Fatal("hashed lookup should resolve the raw cookie token")
	}

	// A legacy raw-token row (pre-upgrade) no longer matches -> invalidated.
	if _, err := s.db.Exec(`INSERT INTO sessions(token, user_id, username, role, expires_at) VALUES(?,?,?,?,?)`,
		"legacy-raw", 2, "old", "admin", exp); err != nil {
		t.Fatal(err)
	}
	if se, _ := s.GetSession("legacy-raw"); se != nil {
		t.Fatal("a raw legacy session token must not resolve after the hashing upgrade")
	}
}

// Finding #9: re-enroll (RotateNodeKeyByID) resets the rotation clock and clears
// the previous-key grace fields, so a fresh key never looks older than keyMaxAge.
func TestReEnrollResetsRotationBookkeeping(t *testing.T) {
	s := openTestStore(t)

	if err := s.CreateNodeWithID("node-1", "agent-1", "hashA", "prefA", true); err != nil {
		t.Fatal(err)
	}
	// Simulate an aged key with a lingering grace (previous) key.
	if _, err := s.db.Exec(
		`UPDATE nodes SET key_issued_at=1000, prev_key_hash='old', prev_key_expires_at=9999 WHERE id='node-1'`); err != nil {
		t.Fatal(err)
	}

	before := time.Now().Unix()
	if err := s.RotateNodeKeyByID("node-1", "hashB", "prefB"); err != nil {
		t.Fatal(err)
	}

	var issuedAt, prevExp int64
	var prevHash string
	if err := s.read.QueryRow(
		`SELECT key_issued_at, prev_key_hash, prev_key_expires_at FROM nodes WHERE id='node-1'`).
		Scan(&issuedAt, &prevHash, &prevExp); err != nil {
		t.Fatal(err)
	}
	if issuedAt < before {
		t.Fatalf("key_issued_at should be reset to ~now, got %d (before=%d)", issuedAt, before)
	}
	if prevHash != "" || prevExp != 0 {
		t.Fatalf("prev-key fields should be cleared, got hash=%q exp=%d", prevHash, prevExp)
	}
}
