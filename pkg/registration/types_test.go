// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestValidateLabel(t *testing.T) {
	ok := []string{"", "Front desk", "ünïcode ✓", strings.Repeat("é", MaxLabelLength)}
	for _, l := range ok {
		assert.NoError(t, ValidateLabel(l), "label %q", l)
	}
	bad := []string{strings.Repeat("a", MaxLabelLength+1), "a\nb", "a\x00b", "a\tb", "a\x7fb", "a\xffb"}
	for _, l := range bad {
		assert.Error(t, ValidateLabel(l), "label %q", l)
	}
}

func TestCreateToken_CarriesLabel(t *testing.T) {
	tok, err := CreateToken(&TokenCreateRequest{TenantID: "t", ControllerURL: "grpc://c:1", Label: "lbl"})
	require.NoError(t, err)
	assert.Equal(t, "lbl", tok.Label)
	assert.Equal(t, "lbl", tokenToData(tok).Label)
	assert.Equal(t, "lbl", dataToToken(tokenToData(tok)).Label)
}
