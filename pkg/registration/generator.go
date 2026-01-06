// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package registration

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"
)

const (
	// TokenPrefix is the prefix for all registration tokens
	TokenPrefix = "cfgms_reg_"

	// TokenLength is the length of the random part (before encoding)
	TokenLength = 16 // 16 bytes = 128 bits of entropy
)

// GenerateToken generates a new random registration token.
// Format: cfgms_reg_XXXXXXXXXXXXXXXXXXXXX (base32 encoded random bytes)
func GenerateToken() (string, error) {
	// Generate random bytes
	randomBytes := make([]byte, TokenLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base32 (no padding, lowercase)
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes))

	// Add prefix
	token := TokenPrefix + encoded

	return token, nil
}

// ParseExpiration parses expiration duration string (e.g., "24h", "7d", "30d")
func ParseExpiration(expiresIn string) (*time.Time, error) {
	if expiresIn == "" {
		return nil, nil // No expiration
	}

	// Parse duration with day support
	var duration time.Duration
	var err error

	if strings.HasSuffix(expiresIn, "d") {
		// Parse days (e.g., "7d" = 7 days)
		var days int
		if _, err := fmt.Sscanf(expiresIn, "%dd", &days); err != nil {
			return nil, fmt.Errorf("invalid duration format: %s", expiresIn)
		}
		duration = time.Duration(days) * 24 * time.Hour
	} else {
		// Parse standard Go duration (e.g., "24h", "30m")
		duration, err = time.ParseDuration(expiresIn)
		if err != nil {
			return nil, fmt.Errorf("invalid duration: %w", err)
		}
	}

	expiresAt := time.Now().Add(duration)
	return &expiresAt, nil
}

// CreateToken creates a new registration token from a request.
func CreateToken(req *TokenCreateRequest) (*Token, error) {
	// Validate required fields
	if req.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if req.ControllerURL == "" {
		return nil, fmt.Errorf("controller_url is required")
	}

	// Generate token string
	tokenStr, err := GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Parse expiration
	expiresAt, err := ParseExpiration(req.ExpiresIn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiration: %w", err)
	}

	// Create token
	token := &Token{
		Token:         tokenStr,
		TenantID:      req.TenantID,
		ControllerURL: req.ControllerURL,
		Group:         req.Group,
		CreatedAt:     time.Now(),
		ExpiresAt:     expiresAt,
		SingleUse:     req.SingleUse,
	}

	return token, nil
}
