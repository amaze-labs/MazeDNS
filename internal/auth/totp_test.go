package auth

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 column (8 digits there; the 6-digit code is the
// last six, since both are the same truncated value mod 10^n).
func TestTOTPRFCVectors(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	for unix, want8 := range map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	} {
		want := want8[2:]
		step, ok := VerifyTOTP(secret, want, time.Unix(unix, 0))
		if !ok || step != unix/30 {
			t.Errorf("t=%d: VerifyTOTP(%s) = %d, %v; want step %d", unix, want, step, ok, unix/30)
		}
	}
}

func TestTOTPSkewAndRejects(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := decodeSecret(secret)
	now := time.Unix(1_800_000_000, 0)
	cur := now.Unix() / 30
	for d, inWindow := range map[int64]bool{-2: false, -1: true, 0: true, 1: true, 2: false} {
		step, ok := VerifyTOTP(secret, totpAt(key, cur+d), now)
		// Matching the code's own step is what counts: a code from outside the
		// window may still equal one inside it by chance (1 in 10^6).
		if got := ok && step == cur+d; got != inWindow {
			t.Errorf("drift %d: matched own step = %v, want %v", d, got, inWindow)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := VerifyTOTP(secret, bad, now); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, ok := VerifyTOTP("not base32!", "123456", now); ok {
		t.Error("accepted a code for an invalid secret")
	}
	// Spaces and lower case in the secret are forgiven (people type it).
	spaced := strings.ToLower(secret[:4] + " " + secret[4:])
	if _, ok := VerifyTOTP(spaced, totpAt(key, cur), now); !ok {
		t.Error("rejected a code for a spaced, lower-case secret")
	}
}

func TestTOTPURI(t *testing.T) {
	u, err := url.Parse(TOTPURI("MazeDNS", "anna@home", "ABC234"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || q.Get("secret") != "ABC234" || q.Get("issuer") != "MazeDNS" ||
		q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Errorf("bad URI %s", u)
	}
	if label, _ := url.PathUnescape(strings.TrimPrefix(u.EscapedPath(), "/")); label != "MazeDNS:anna@home" {
		t.Errorf("label %q", label)
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount {
		t.Fatalf("got %d codes, %d hashes", len(codes), len(hashes))
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 11 || c[5] != '-' || strings.ContainsAny(c, "01ilo") {
			t.Errorf("code %q has the wrong shape", c)
		}
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
		if hashes[i] != HashRecoveryCode(c) {
			t.Errorf("hash %d doesn't match its code", i)
		}
		// Typed loosely: upper case, no dash, stray spaces.
		if HashRecoveryCode(" "+strings.ToUpper(strings.Replace(c, "-", "", 1))+" ") != hashes[i] {
			t.Errorf("normalization failed for %q", c)
		}
		if LooksLikeTOTP(c) {
			t.Errorf("%q taken for a TOTP code", c)
		}
	}
	if !LooksLikeTOTP("123 456") || LooksLikeTOTP("12345a") {
		t.Error("LooksLikeTOTP misjudges")
	}
}
