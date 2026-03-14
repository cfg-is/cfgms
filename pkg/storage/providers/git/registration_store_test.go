// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package git

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

func TestGitRegistrationTokenStore_CRUD(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "git-reg-store-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create store
	store, err := NewGitRegistrationTokenStore(tempDir, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize store
	err = store.Initialize(ctx)
	require.NoError(t, err)

	// Test SaveToken
	t.Run("SaveToken", func(t *testing.T) {
		now := time.Now()
		token := &interfaces.RegistrationTokenData{
			Token:         "test123",
			TenantID:      "tenant-1",
			ControllerURL: "tcp://localhost:1883",
			Group:         "test-group",
			CreatedAt:     now,
			SingleUse:     false,
			Revoked:       false,
		}

		err := store.SaveToken(ctx, token)
		require.NoError(t, err)
	})

	// Test GetToken
	t.Run("GetToken", func(t *testing.T) {
		token, err := store.GetToken(ctx, "test123")
		require.NoError(t, err)
		assert.Equal(t, "test123", token.Token)
		assert.Equal(t, "tenant-1", token.TenantID)
		assert.Equal(t, "tcp://localhost:1883", token.ControllerURL)
		assert.Equal(t, "test-group", token.Group)
		assert.False(t, token.SingleUse)
		assert.False(t, token.Revoked)
	})

	// Test GetToken not found
	t.Run("GetToken_NotFound", func(t *testing.T) {
		_, err := store.GetToken(ctx, "nonexistent_token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	// Test UpdateToken
	t.Run("UpdateToken", func(t *testing.T) {
		token, err := store.GetToken(ctx, "test123")
		require.NoError(t, err)

		// Mark as used
		now := time.Now()
		token.UsedAt = &now
		token.UsedBy = "steward-001"

		err = store.UpdateToken(ctx, token)
		require.NoError(t, err)

		// Verify update
		updated, err := store.GetToken(ctx, "test123")
		require.NoError(t, err)
		assert.NotNil(t, updated.UsedAt)
		assert.Equal(t, "steward-001", updated.UsedBy)
	})

	// Test ListTokens
	t.Run("ListTokens", func(t *testing.T) {
		// Add another token for the same tenant
		now := time.Now()
		token2 := &interfaces.RegistrationTokenData{
			Token:         "test456",
			TenantID:      "tenant-1",
			ControllerURL: "tcp://localhost:1883",
			Group:         "test-group-2",
			CreatedAt:     now,
			SingleUse:     true,
			Revoked:       false,
		}
		err := store.SaveToken(ctx, token2)
		require.NoError(t, err)

		// Add token for different tenant
		token3 := &interfaces.RegistrationTokenData{
			Token:         "other_tenant",
			TenantID:      "tenant-2",
			ControllerURL: "tcp://localhost:1883",
			Group:         "other-group",
			CreatedAt:     now,
			SingleUse:     false,
			Revoked:       false,
		}
		err = store.SaveToken(ctx, token3)
		require.NoError(t, err)

		// List all tokens for tenant-1
		filter := &interfaces.RegistrationTokenFilter{
			TenantID: "tenant-1",
		}
		tokens, err := store.ListTokens(ctx, filter)
		require.NoError(t, err)
		assert.Len(t, tokens, 2)

		// List all tokens (no filter)
		allTokens, err := store.ListTokens(ctx, nil)
		require.NoError(t, err)
		assert.Len(t, allTokens, 3)
	})

	// Test ListTokens with filters
	t.Run("ListTokens_Filters", func(t *testing.T) {
		// Filter by single-use
		singleUse := true
		filter := &interfaces.RegistrationTokenFilter{
			SingleUse: &singleUse,
		}
		tokens, err := store.ListTokens(ctx, filter)
		require.NoError(t, err)
		assert.Len(t, tokens, 1)
		assert.Equal(t, "test456", tokens[0].Token)

		// Filter by used status
		used := true
		filter = &interfaces.RegistrationTokenFilter{
			Used: &used,
		}
		tokens, err = store.ListTokens(ctx, filter)
		require.NoError(t, err)
		assert.Len(t, tokens, 1)
		assert.Equal(t, "test123", tokens[0].Token)
	})

	// Test DeleteToken
	t.Run("DeleteToken", func(t *testing.T) {
		err := store.DeleteToken(ctx, "test456")
		require.NoError(t, err)

		// Verify deleted
		_, err = store.GetToken(ctx, "test456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	// Test DeleteToken not found
	t.Run("DeleteToken_NotFound", func(t *testing.T) {
		err := store.DeleteToken(ctx, "nonexistent_token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestGitRegistrationTokenStore_TokenValidation(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "git-reg-validation-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create store
	store, err := NewGitRegistrationTokenStore(tempDir, "")
	require.NoError(t, err)

	ctx := context.Background()
	err = store.Initialize(ctx)
	require.NoError(t, err)

	t.Run("IsValid_Active", func(t *testing.T) {
		now := time.Now()
		token := &interfaces.RegistrationTokenData{
			Token:     "valid_token",
			TenantID:  "tenant-1",
			CreatedAt: now,
			SingleUse: false,
			Revoked:   false,
		}
		err := store.SaveToken(ctx, token)
		require.NoError(t, err)

		retrieved, err := store.GetToken(ctx, "valid_token")
		require.NoError(t, err)
		assert.True(t, retrieved.IsValid())
	})

	t.Run("IsValid_Expired", func(t *testing.T) {
		now := time.Now()
		expired := now.Add(-1 * time.Hour)
		token := &interfaces.RegistrationTokenData{
			Token:     "expired_token",
			TenantID:  "tenant-1",
			CreatedAt: now.Add(-2 * time.Hour),
			ExpiresAt: &expired,
			SingleUse: false,
			Revoked:   false,
		}
		err := store.SaveToken(ctx, token)
		require.NoError(t, err)

		retrieved, err := store.GetToken(ctx, "expired_token")
		require.NoError(t, err)
		assert.False(t, retrieved.IsValid())
	})

	t.Run("IsValid_Revoked", func(t *testing.T) {
		now := time.Now()
		token := &interfaces.RegistrationTokenData{
			Token:     "revoked_token",
			TenantID:  "tenant-1",
			CreatedAt: now,
			SingleUse: false,
			Revoked:   true,
			RevokedAt: &now,
		}
		err := store.SaveToken(ctx, token)
		require.NoError(t, err)

		retrieved, err := store.GetToken(ctx, "revoked_token")
		require.NoError(t, err)
		assert.False(t, retrieved.IsValid())
	})

	t.Run("IsValid_SingleUseUsed", func(t *testing.T) {
		now := time.Now()
		token := &interfaces.RegistrationTokenData{
			Token:     "singleuse_token",
			TenantID:  "tenant-1",
			CreatedAt: now,
			SingleUse: true,
			UsedAt:    &now,
			UsedBy:    "steward-001",
			Revoked:   false,
		}
		err := store.SaveToken(ctx, token)
		require.NoError(t, err)

		retrieved, err := store.GetToken(ctx, "singleuse_token")
		require.NoError(t, err)
		assert.False(t, retrieved.IsValid())
	})
}

func TestGitRegistrationTokenStore_PathTraversal(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "git-reg-security-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create store
	store, err := NewGitRegistrationTokenStore(tempDir, "")
	require.NoError(t, err)

	ctx := context.Background()
	err = store.Initialize(ctx)
	require.NoError(t, err)

	// Test that path traversal attempts in token string are sanitized
	t.Run("TokenWithPathTraversal", func(t *testing.T) {
		now := time.Now()
		// Token with path traversal attempt - should be sanitized
		token := &interfaces.RegistrationTokenData{
			Token:     "../../etc/passwd",
			TenantID:  "tenant-1",
			CreatedAt: now,
		}
		err := store.SaveToken(ctx, token)
		require.NoError(t, err)

		// Should be able to retrieve it safely
		retrieved, err := store.GetToken(ctx, "../../etc/passwd")
		require.NoError(t, err)
		assert.Equal(t, "../../etc/passwd", retrieved.Token)
	})
}

func TestGitRegistrationTokenStore_EmptyValidation(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "git-reg-empty-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create store
	store, err := NewGitRegistrationTokenStore(tempDir, "")
	require.NoError(t, err)

	ctx := context.Background()
	err = store.Initialize(ctx)
	require.NoError(t, err)

	t.Run("SaveToken_NilToken", func(t *testing.T) {
		err := store.SaveToken(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	t.Run("SaveToken_EmptyTokenString", func(t *testing.T) {
		token := &interfaces.RegistrationTokenData{
			Token:    "",
			TenantID: "tenant-1",
		}
		err := store.SaveToken(ctx, token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("GetToken_EmptyTokenString", func(t *testing.T) {
		_, err := store.GetToken(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("DeleteToken_EmptyTokenString", func(t *testing.T) {
		err := store.DeleteToken(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})
}
