package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestEnrollKeyConsumeAndStatus(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().Unix()

	// Unlimited, never-expiring: consumes repeatedly, stays active.
	if err := s.CreateEnrollKey("k1", "unlimited", "hashUL", "prefUL", "admin", 0, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ok, err := s.ConsumeEnrollKey("hashUL", now)
		if err != nil || !ok {
			t.Fatalf("unlimited consume %d: ok=%v err=%v", i, ok, err)
		}
	}

	// max_uses=2: third consume fails and the status flips to exhausted.
	if err := s.CreateEnrollKey("k2", "capped", "hashCap", "prefCap", "admin", 0, 2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if ok, _ := s.ConsumeEnrollKey("hashCap", now); !ok {
			t.Fatalf("capped consume %d should succeed", i)
		}
	}
	if ok, _ := s.ConsumeEnrollKey("hashCap", now); ok {
		t.Fatal("consuming past max_uses must fail")
	}

	// Expired key never consumes.
	if err := s.CreateEnrollKey("k3", "expired", "hashExp", "prefExp", "admin", now-1, 0); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeEnrollKey("hashExp", now); ok {
		t.Fatal("expired key must not consume")
	}
	if valid, _, _ := s.EnrollKeyValid("hashExp", now); valid {
		t.Fatal("expired key must not be valid")
	}

	// Revoked key never consumes.
	if err := s.RevokeEnrollKey("k1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeEnrollKey("hashUL", now); ok {
		t.Fatal("revoked key must not consume")
	}
	if valid, _, _ := s.EnrollKeyValid("hashUL", now); valid {
		t.Fatal("revoked key must not be valid")
	}

	// Statuses are derived correctly in the listing (secrets never returned).
	keys, err := s.ListEnrollKeys()
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, k := range keys {
		status[k.ID] = k.Status
	}
	if status["k1"] != "revoked" || status["k2"] != "exhausted" || status["k3"] != "expired" {
		t.Fatalf("derived statuses wrong: %+v", status)
	}
}

// EnsureEnrollKey imports a config join_token idempotently (keyed by hash), so a
// restart doesn't create duplicates — the migration path for existing deployments.
func TestEnsureEnrollKeyIdempotent(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 0; i < 3; i++ {
		if err := s.EnsureEnrollKey("id-a", "imported", "hashJT", "prefJT"); err != nil {
			t.Fatal(err)
		}
	}
	keys, _ := s.ListEnrollKeys()
	n := 0
	for _, k := range keys {
		if k.KeyPrefix == "prefJT" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("EnsureEnrollKey should import exactly once, found %d", n)
	}
	// The imported key authenticates enrollment (consumes).
	if ok, _ := s.ConsumeEnrollKey("hashJT", time.Now().Unix()); !ok {
		t.Fatal("imported join-token key should be usable for enrollment")
	}
}
