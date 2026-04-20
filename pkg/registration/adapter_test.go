// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func TestStorageAdapter_WithSQLiteStore(t *testing.T) {
	tempDir := t.TempDir()

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
	tempDir := t.TempDir()

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

func TestStorageAdapter_ConsumeToken_Race(t *testing.T) {
	tempDir := t.TempDir()

	store, err := interfaces.CreateRegistrationTokenStoreFromConfig(
		"sqlite",
		map[string]interface{}{"path": tempDir + "/tokens.db"},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))

	adapter := NewStorageAdapter(store)

	token := &Token{
		Token:     "sqlite-race-token",
		TenantID:  "tenant-race",
		SingleUse: true,
		CreatedAt: time.Now(),
	}
	require.NoError(t, adapter.SaveToken(ctx, token))

	const goroutines = 50
	var (
		successCount atomic.Int32
		alreadyUsed  atomic.Int32
		wg           sync.WaitGroup
		start        = make(chan struct{})
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			<-start
			err := adapter.ConsumeToken(ctx, "sqlite-race-token", "steward-"+string(rune('A'+id)))
			switch err {
			case nil:
				successCount.Add(1)
			case interfaces.ErrTokenAlreadyUsed:
				alreadyUsed.Add(1)
			default:
				t.Errorf("goroutine %d: unexpected error: %v", id, err)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), successCount.Load(), "exactly one goroutine must succeed")
	assert.Equal(t, int32(goroutines-1), alreadyUsed.Load(), "all others must get ErrTokenAlreadyUsed")
}
