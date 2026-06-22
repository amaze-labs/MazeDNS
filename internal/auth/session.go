package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// NewToken returns a cryptographically random URL-safe session token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
