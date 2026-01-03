// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package registration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/providers/git"
)

func TestStorageAdapter_WithGitStore(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "adapter-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create git store
	gitStore, err := git.NewGitRegistrationTokenStore(tempDir, "")
	require.NoError(t, err)

	ctx := context.Background()
	err = gitStore.Initialize(ctx)
	require.NoError(t, err)

	// Create adapter
	adapter := NewStorageAdapter(gitStore)

	// Test SaveToken
	t.Run("SaveToken", func(t *testing.T) {
		now := time.Now()
		token := &Token{
			Token:         "cfgms_reg_adapter_test",
			TenantID:      "tenant-adapter",
			ControllerURL: "tcp://localhost:1883",
			Group:         "adapter-group",
			CreatedAt:     now,
			SingleUse:     false,
			Revoked:       false,
		}

		err := adapter.SaveToken(ctx, token)
		require.NoError(t, err)
	})

	// Test GetToken
	t.Run("GetToken", func(t *testing.T) {
		token, err := adapter.GetToken(ctx, "cfgms_reg_adapter_test")
		require.NoError(t, err)
		assert.Equal(t, "cfgms_reg_adapter_test", token.Token)
		assert.Equal(t, "tenant-adapter", token.TenantID)
		assert.Equal(t, "tcp://localhost:1883", token.ControllerURL)
		assert.Equal(t, "adapter-group", token.Group)
	})

	// Test UpdateToken
	t.Run("UpdateToken", func(t *testing.T) {
		token, err := adapter.GetToken(ctx, "cfgms_reg_adapter_test")
		require.NoError(t, err)

		// Mark as used using the Token method
		token.MarkUsed("steward-adapter-001")

		err = adapter.UpdateToken(ctx, token)
		require.NoError(t, err)

		// Verify update
		updated, err := adapter.GetToken(ctx, "cfgms_reg_adapter_test")
		require.NoError(t, err)
		assert.NotNil(t, updated.UsedAt)
		assert.Equal(t, "steward-adapter-001", updated.UsedBy)
	})

	// Test ListTokens
	t.Run("ListTokens", func(t *testing.T) {
		// Add another token
		now := time.Now()
		token2 := &Token{
			Token:         "cfgms_reg_adapter_test2",
			TenantID:      "tenant-adapter",
			ControllerURL: "tcp://localhost:1883",
			Group:         "adapter-group-2",
			CreatedAt:     now,
			SingleUse:     true,
			Revoked:       false,
		}
		err := adapter.SaveToken(ctx, token2)
		require.NoError(t, err)

		// List tokens for tenant
		tokens, err := adapter.ListTokens(ctx, "tenant-adapter")
		require.NoError(t, err)
		assert.Len(t, tokens, 2)
	})

	// Test DeleteToken
	t.Run("DeleteToken", func(t *testing.T) {
		err := adapter.DeleteToken(ctx, "cfgms_reg_adapter_test2")
		require.NoError(t, err)

		// Verify deleted
		_, err = adapter.GetToken(ctx, "cfgms_reg_adapter_test2")
		require.Error(t, err)
	})

	// Test Token.IsValid method
	t.Run("Token_IsValid", func(t *testing.T) {
		token, err := adapter.GetToken(ctx, "cfgms_reg_adapter_test")
		require.NoError(t, err)
		// Token was marked as used but it's not single-use, so still valid
		assert.True(t, token.IsValid())
	})

	// Test Token.Revoke method
	t.Run("Token_Revoke", func(t *testing.T) {
		token, err := adapter.GetToken(ctx, "cfgms_reg_adapter_test")
		require.NoError(t, err)

		// Revoke the token
		token.Revoke()
		err = adapter.UpdateToken(ctx, token)
		require.NoError(t, err)

		// Verify it's no longer valid
		updated, err := adapter.GetToken(ctx, "cfgms_reg_adapter_test")
		require.NoError(t, err)
		assert.True(t, updated.Revoked)
		assert.NotNil(t, updated.RevokedAt)
		assert.False(t, updated.IsValid())
	})
}

func TestStorageAdapter_InterfaceCompliance(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "adapter-interface-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create git store
	gitStore, err := git.NewGitRegistrationTokenStore(tempDir, "")
	require.NoError(t, err)

	// Create adapter
	adapter := NewStorageAdapter(gitStore)

	// Verify adapter implements Store interface
	var _ Store = adapter
}
