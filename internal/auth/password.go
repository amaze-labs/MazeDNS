// Package auth provides local password auth, sessions, and OIDC SSO.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword returns an argon2id PHC-encoded hash of password.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// PasswordStrengthError returns a validation message, or "" if the password is
// acceptable (>= 10 chars mixing letters with digits or symbols). This is the
// single password policy shared by every password-setting path.
func PasswordStrengthError(pw string) string {
	if len(pw) < 10 {
		return "password must be at least 10 characters"
	}
	var hasLetter, hasOther bool
	for _, r := range pw {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		default:
			hasOther = true
		}
	}
	if !hasLetter || !hasOther {
		return "password must mix letters with digits or symbols"
	}
	return ""
}

// dummyHash is a valid argon2id hash verified against when a login names a missing
// user (or one with no password), so the response time doesn't reveal whether the
// account exists — closing the username-enumeration timing oracle.
var dummyHash, _ = HashPassword("mazedns-timing-equalizer-not-a-real-password")

// VerifyDummy performs a throwaway password verification with the same cost as a
// real one. Callers use it on the user-missing path to equalize timing.
func VerifyDummy(password string) {
	_, _ = VerifyPassword(dummyHash, password)
}

// VerifyPassword reports whether password matches the PHC-encoded hash.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, err
	}
	var memory, tCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &tCost, &threads); err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, tCost, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
