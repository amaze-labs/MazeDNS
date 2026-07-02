package store

import (
	"path/filepath"
	"sync"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// EnsureCPSettings seeds exactly once; later Ensure calls (e.g. a restart with
// different env) are ignored, so the DB stays the single source of truth.
func TestEnsureCPSettingsSeedsOnce(t *testing.T) {
	s := openTestStore(t)

	seeded, err := s.EnsureCPSettings(CPSettings{SessionTTLSec: 3600, RequireApproval: true})
	if err != nil || !seeded {
		t.Fatalf("first seed: seeded=%v err=%v", seeded, err)
	}
	// A second Ensure with DIFFERENT values must NOT overwrite (env ignored after init).
	seeded, err = s.EnsureCPSettings(CPSettings{SessionTTLSec: 99, RequireApproval: false})
	if err != nil || seeded {
		t.Fatalf("second seed should be a no-op: seeded=%v err=%v", seeded, err)
	}
	got := s.LoadCPSettings(CPSettings{})
	if got.SessionTTLSec != 3600 || !got.RequireApproval {
		t.Fatalf("stored settings changed after re-seed: %+v", got)
	}
}

// SaveCPSettings mirrors the advertise address to the enrollment-facing key.
func TestSaveCPSettingsMirrorsAdvertiseAddr(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveCPSettings(CPSettings{AdvertiseAddr: "10.0.0.9:53"}); err != nil {
		t.Fatal(err)
	}
	if got := s.MasterAdvertiseAddr(); got != "10.0.0.9:53" {
		t.Fatalf("advertise addr not mirrored: %q", got)
	}
}

// CreateFirstAdmin is atomic and idempotent: exactly one admin is created even
// under concurrency, and setup is marked complete.
func TestCreateFirstAdminAtomic(t *testing.T) {
	s := openTestStore(t)

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.CreateFirstAdmin("admin", "hash")
			if err == nil && ok {
				mu.Lock()
				created++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if created != 1 {
		t.Fatalf("exactly one admin should be created, got %d", created)
	}
	if c, _ := s.CountUsers(); c != 1 {
		t.Fatalf("user count = %d, want 1", c)
	}
	if !s.SetupCompleted() {
		t.Fatal("setup should be marked complete after first admin")
	}
	// A later call is a no-op (already have an admin).
	if ok, _ := s.CreateFirstAdmin("other", "hash2"); ok {
		t.Fatal("CreateFirstAdmin must not create a second admin")
	}
}

func TestAuditLogAppendAndTrim(t *testing.T) {
	s := openTestStore(t)
	for i := 0; i < 205; i++ {
		if err := s.AppendAudit(AuditEntry{User: "admin", Action: "settings.cp", Detail: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := s.ListAudit()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 200 {
		t.Fatalf("audit log should cap at 200, got %d", len(entries))
	}
	if entries[0].TS == 0 {
		t.Fatal("audit entries should get a timestamp")
	}
}
