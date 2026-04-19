// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func TestStorageAdapter_WithSQLiteStore(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "adapter-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create sqlite registration token store
	store, err := interfaces.CreateRegistrationTokenStoreFromConfig(
		"sqlite",
		map[string]interface{}{"path": tempDir + "/tokens.db"},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	err = store.Initialize(ctx)
	require.NoError(t, err)

	// Create adapter
	adapter := NewStorageAdapter(store)

	// Test SaveToken
	t.Run("SaveToken", func(t *testing.T) {
		now := time.Now()
		token := &Token{
			Token:         "adapter_test_token",
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
		token, err := adapter.GetToken(ctx, "adapter_test_token")
		require.NoError(t, err)
		assert.Equal(t, "adapter_test_token", token.Token)
		assert.Equal(t, "tenant-adapter", token.TenantID)
		assert.Equal(t, "tcp://localhost:1883", token.ControllerURL)
		assert.Equal(t, "adapter-group", token.Group)
	})

	// Test UpdateToken
	t.Run("UpdateToken", func(t *testing.T) {
		token, err := adapter.GetToken(ctx, "adapter_test_token")
		require.NoError(t, err)

		// Mark as used using the Token method
		token.MarkUsed("steward-adapter-001")

		err = adapter.UpdateToken(ctx, token)
		require.NoError(t, err)

		// Verify update
		updated, err := adapter.GetToken(ctx, "adapter_test_token")
		require.NoError(t, err)
		assert.NotNil(t, updated.UsedAt)
		assert.Equal(t, "steward-adapter-001", updated.UsedBy)
	})

	// Test ListTokens
	t.Run("ListTokens", func(t *testing.T) {
		// Add another token
		now := time.Now()
		token2 := &Token{
			Token:         "adapter_test_token2",
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
		err := adapter.DeleteToken(ctx, "adapter_test_token2")
		require.NoError(t, err)

		// Verify deleted
		_, err = adapter.GetToken(ctx, "adapter_test_token2")
		require.Error(t, err)
	})

	// Test Token.IsValid method
	t.Run("Token_IsValid", func(t *testing.T) {
		token, err := adapter.GetToken(ctx, "adapter_test_token")
		require.NoError(t, err)
		// Token was marked as used but it's not single-use, so still valid
		assert.True(t, token.IsValid())
	})

	// Test Token.Revoke method
	t.Run("Token_Revoke", func(t *testing.T) {
		token, err := adapter.GetToken(ctx, "adapter_test_token")
		require.NoError(t, err)

		// Revoke the token
		token.Revoke()
		err = adapter.UpdateToken(ctx, token)
		require.NoError(t, err)

		// Verify it's no longer valid
		updated, err := adapter.GetToken(ctx, "adapter_test_token")
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

	// Create sqlite registration token store
	store, err := interfaces.CreateRegistrationTokenStoreFromConfig(
		"sqlite",
		map[string]interface{}{"path": tempDir + "/tokens.db"},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	// Create adapter
	adapter := NewStorageAdapter(store)

	// Verify adapter implements Store interface
	var _ Store = adapter
}
