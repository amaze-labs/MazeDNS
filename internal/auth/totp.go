package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP as authenticator apps implement it (RFC 6238): HMAC-SHA1, 6 digits,
// 30-second steps. These are the parameters every app supports; changing them
// would break existing enrollments.
const (
	totpDigits = 6
	totpPeriod = 30
	// totpSkew is how many steps either side of now a code may come from, to
	// absorb clock drift between the server and the phone.
	totpSkew = 1
	// RecoveryCodeCount is how many single-use recovery codes a user gets.
	RecoveryCodeCount = 10
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret, base32 without padding (the
// form authenticator apps take, typed or from a QR code).
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPURI is the otpauth:// URI an authenticator app reads from a QR code.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpAt is the code for one time step.
func totpAt(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, n%1_000_000)
}

// decodeSecret reads a base32 secret, forgiving case, spaces and padding.
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	return b32.DecodeString(strings.TrimRight(s, "="))
}

// VerifyTOTP checks code against secret at now, allowing totpSkew steps of
// drift. It returns the matched time step, which the caller must record and
// require to increase (store.UseTOTPStep), so a code can't be replayed within
// its window. Comparison is constant-time.
func VerifyTOTP(secret, code string, now time.Time) (step int64, ok bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := decodeSecret(secret)
	if err != nil || len(key) == 0 {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		if subtle.ConstantTimeCompare([]byte(totpAt(key, cur+d)), []byte(code)) == 1 {
			return cur + d, true
		}
	}
	return 0, false
}

// recoveryAlphabet leaves out look-alikes (0/o, 1/l/i) so codes copied by hand
// come out right.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewRecoveryCodes returns RecoveryCodeCount fresh codes ("xxxxx-xxxxx", about
// 49 bits each) and their at-rest hashes. Show the codes once; store the hashes.
func NewRecoveryCodes() (codes, hashes []string, err error) {
	for i := 0; i < RecoveryCodeCount; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		var sb strings.Builder
		for j, c := range b {
			if j == 5 {
				sb.WriteByte('-')
			}
			// 256 % 31 != 0, so this is very slightly biased; at ~49 bits per
			// code it doesn't matter.
			sb.WriteByte(recoveryAlphabet[int(c)%len(recoveryAlphabet)])
		}
		code := sb.String()
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// HashRecoveryCode is a recovery code's at-rest form. The codes are random and
// high-entropy, so a fast hash is enough (like session and API tokens); input is
// normalized so case, spaces and a missing dash don't matter.
func HashRecoveryCode(code string) string {
	c := strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte("mazedns-recovery:" + c))
	return hex.EncodeToString(sum[:])
}

// LooksLikeTOTP reports whether input is shaped like an authenticator code
// (digits only) rather than a recovery code.
func LooksLikeTOTP(code string) bool {
	c := strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(c) != totpDigits {
		return false
	}
	for _, r := range c {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// TOTPCode returns the code for secret at t, as an authenticator app shows it.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return totpAt(key, t.Unix()/totpPeriod), nil
}
