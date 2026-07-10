package auth

import "testing"

// Finding #7: the shared password policy requires >=10 chars with variety.
func TestPasswordStrengthError(t *testing.T) {
	weak := []string{"", "short", "aaaaaaaaaa", "1234567890", "0123456789012345"}
	for _, p := range weak {
		if PasswordStrengthError(p) == "" {
			t.Errorf("expected %q to be rejected", p)
		}
	}
	strong := []string{"correcthorse7", "Tr0ub4dour&3xtra", "aaaaaaaaa1"}
	for _, p := range strong {
		if msg := PasswordStrengthError(p); msg != "" {
			t.Errorf("expected %q to be accepted, got %q", p, msg)
		}
	}
}

// Finding #2: the dummy hash used to equalize timing on the user-missing path is a
// valid argon2id hash — verifying against it runs a real (non-erroring) comparison,
// so the timing actually matches a real login.
func TestVerifyDummyIsRealWork(t *testing.T) {
	if dummyHash == "" {
		t.Fatal("dummyHash must be initialized")
	}
	ok, err := VerifyPassword(dummyHash, "anything")
	if err != nil {
		t.Fatalf("dummy hash must verify without error (real work), got %v", err)
	}
	if ok {
		t.Fatal("an arbitrary password must not match the dummy hash")
	}
	VerifyDummy("anything") // must not panic
}
