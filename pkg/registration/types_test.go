// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package registration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToken_IsValid_Revoked(t *testing.T) {
	revokedAt := time.Now()
	tok := &Token{
		Token:     "test-token",
		TenantID:  "tenant-1",
		Revoked:   true,
		RevokedAt: &revokedAt,
		CreatedAt: time.Now(),
	}
	assert.False(t, tok.IsValid(), "revoked token must not be valid")
}

func TestToken_IsValid_Expired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	tok := &Token{
		Token:     "test-token",
		TenantID:  "tenant-1",
		ExpiresAt: &past,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	assert.False(t, tok.IsValid(), "expired token must not be valid")
}

func TestToken_IsValid_Valid(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	tok := &Token{
		Token:     "test-token",
		TenantID:  "tenant-1",
		ExpiresAt: &future,
		CreatedAt: time.Now(),
	}
	assert.True(t, tok.IsValid(), "non-expired non-revoked token must be valid")
}

func TestToken_IsValid_NoExpiry(t *testing.T) {
	tok := &Token{
		Token:     "test-token",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
	}
	assert.True(t, tok.IsValid(), "perennial token with no expiry must always be valid")
}

func TestToken_IsValid_RevokedAndExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	revokedAt := time.Now().Add(-30 * time.Minute)
	tok := &Token{
		Token:     "test-token",
		TenantID:  "tenant-1",
		ExpiresAt: &past,
		Revoked:   true,
		RevokedAt: &revokedAt,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	assert.False(t, tok.IsValid(), "revoked+expired token must not be valid")
}

func TestToken_Revoke(t *testing.T) {
	tok := &Token{
		Token:     "test-token",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
	}
	assert.True(t, tok.IsValid())

	tok.Revoke()

	assert.True(t, tok.Revoked)
	assert.NotNil(t, tok.RevokedAt)
	assert.False(t, tok.IsValid())
}
