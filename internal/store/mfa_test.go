package store

import (
	"sync"
	"testing"
	"time"
)

func TestMFALifecycle(t *testing.T) {
	st := openTestStore(t)
	id, err := st.CreateLocalUser("anna", "x", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := st.GetMFA(id); m == nil || m.Secret != "" {
		t.Fatalf("fresh user: %+v", m)
	}

	// Only the pending secret the user confirmed can be enabled.
	if err := st.SetTOTPPending(id, "SECRETA"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetTOTPPending(id, "SECRETB"); err != nil { // a second setup tab
		t.Fatal(err)
	}
	if ok, _ := st.EnableTOTP(id, "SECRETA", 100, []string{"h1"}); ok {
		t.Fatal("enabled a secret that is no longer pending")
	}
	if ok, err := st.EnableTOTP(id, "SECRETB", 100, []string{"h1", "h2"}); !ok || err != nil {
		t.Fatalf("enable: %v %v", ok, err)
	}
	m, _ := st.GetMFA(id)
	if m.Secret != "SECRETB" || m.Pending != "" || m.LastStep != 100 || len(m.RecoveryCodes) != 2 {
		t.Fatalf("after enable: %+v", m)
	}
	if on, _ := st.MFAEnabledUsers(); !on[id] {
		t.Error("MFAEnabledUsers misses the user")
	}

	// Steps must increase: the confirming code's step, a replay and an older
	// step are refused.
	for step, want := range map[int64]bool{100: false, 99: false, 101: true} {
		if ok, _ := st.UseTOTPStep(id, step); ok != want {
			t.Errorf("UseTOTPStep(%d) = %v, want %v", step, ok, want)
		}
	}
	if ok, _ := st.UseTOTPStep(id, 101); ok {
		t.Error("replayed step 101 accepted")
	}

	// Recovery codes are single-use.
	if ok, left, _ := st.UseRecoveryCode(id, "h1"); !ok || left != 1 {
		t.Errorf("first use: %v %d", ok, left)
	}
	if ok, _, _ := st.UseRecoveryCode(id, "h1"); ok {
		t.Error("recovery code used twice")
	}
	if ok, _, _ := st.UseRecoveryCode(id, "nope"); ok {
		t.Error("unknown recovery code accepted")
	}

	if err := st.DisableTOTP(id); err != nil {
		t.Fatal(err)
	}
	if m, _ := st.GetMFA(id); m.Secret != "" || len(m.RecoveryCodes) != 0 {
		t.Errorf("after disable: %+v", m)
	}
	if ok, _ := st.UseTOTPStep(id, 500); ok {
		t.Error("step accepted with MFA off")
	}
	if ok, _, _ := st.UseRecoveryCode(id, "h2"); ok {
		t.Error("recovery code accepted with MFA off")
	}
}

func TestRecoveryCodeRace(t *testing.T) {
	st := openTestStore(t)
	id, _ := st.CreateLocalUser("anna", "x", "admin")
	_ = st.SetTOTPPending(id, "S")
	if ok, _ := st.EnableTOTP(id, "S", 1, []string{"a", "b", "c"}); !ok {
		t.Fatal("enable failed")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _, _ := st.UseRecoveryCode(id, "b"); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("code b spent %d times", wins)
	}
	if m, _ := st.GetMFA(id); len(m.RecoveryCodes) != 2 {
		t.Errorf("left %v", m.RecoveryCodes)
	}
}

func TestMFAChallenges(t *testing.T) {
	st := openTestStore(t)
	exp := time.Now().Add(time.Minute).Unix()
	if err := st.CreateMFAChallenge("tok", 7, "verify", exp); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.PeekMFAChallenge("tok"); c == nil || c.UserID != 7 || c.Kind != "verify" || c.Attempts != 0 {
		t.Fatalf("peek: %+v", c)
	}
	for i := 1; i <= 3; i++ {
		c, err := st.MFAChallengeAttempt("tok", 3)
		if err != nil || c == nil || c.Attempts != i {
			t.Fatalf("attempt %d: %+v %v", i, c, err)
		}
	}
	if c, _ := st.MFAChallengeAttempt("tok", 3); c != nil {
		t.Fatal("a 4th attempt was allowed")
	}
	if c, _ := st.PeekMFAChallenge("tok"); c != nil {
		t.Error("an exhausted challenge survived")
	}

	_ = st.CreateMFAChallenge("old", 7, "verify", time.Now().Add(-time.Second).Unix())
	if c, _ := st.MFAChallengeAttempt("old", 5); c != nil {
		t.Error("an expired challenge was accepted")
	}
	_ = st.CreateMFAChallenge("x", 8, "setup", exp)
	_ = st.DeleteMFAChallengesForUser(8)
	if c, _ := st.PeekMFAChallenge("x"); c != nil {
		t.Error("challenge survived its user's reset")
	}
}
