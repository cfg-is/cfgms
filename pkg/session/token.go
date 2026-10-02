// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateToken generates a cryptographically random 32-byte bearer token encoded
// as base64url without padding (43 characters, 256 bits of entropy).
// Session tokens are distinguishable from API keys by length: API keys use
// base64url with padding (44 chars), session tokens use base64url without padding
// (43 chars). The middleware uses this length difference to route tokens correctly.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: failed to generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the lowercase hex-encoded SHA-256 hash of the token string.
// The controller stores only this hash; the raw token exists only in transit and
// in process memory during a single request.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
