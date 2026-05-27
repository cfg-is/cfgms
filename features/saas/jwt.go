// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package saas

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// extractJWTTenantID decodes the payload segment of a JWT and returns the tid
// (tenant ID) claim. Only the payload is decoded — the signature is NOT verified,
// per the scope of this check (tid claim extraction only).
//
// Returns an error when:
//   - the token has fewer than 3 dot-separated segments (not a JWT)
//   - the payload segment fails base64 URL decoding
//   - the payload cannot be JSON-unmarshalled
//   - the tid field is absent or empty
func extractJWTTenantID(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return "", fmt.Errorf("not a JWT: expected 3 dot-separated segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("JWT payload base64 decode failed: %w", err)
	}

	var claims struct {
		TID string `json:"tid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("JWT payload JSON unmarshal failed: %w", err)
	}

	if claims.TID == "" {
		return "", fmt.Errorf("JWT tid claim absent or empty")
	}

	return claims.TID, nil
}
