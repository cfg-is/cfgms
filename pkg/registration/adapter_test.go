// SPDX-License-Identifier: AGPL-3.0-only
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
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/testing"
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

		// Revoke the token to test mutable state update
		token.Revoke()

		err = adapter.UpdateToken(ctx, token)
		require.NoError(t, err)

		// Verify update
		updated, err := adapter.GetToken(ctx, "adapter_test_token")
		require.NoError(t, err)
		assert.True(t, updated.Revoked)
		assert.NotNil(t, updated.RevokedAt)
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

	// Test Token.IsValid method (non-revoked token with future expiry)
	t.Run("Token_IsValid_FutureExpiry", func(t *testing.T) {
		future := time.Now().Add(24 * time.Hour)
		tok := &Token{
			Token:         "adapter_valid_token",
			TenantID:      "tenant-adapter",
			ControllerURL: "tcp://localhost:1883",
			Group:         "valid-group",
			CreatedAt:     time.Now(),
			ExpiresAt:     &future,
		}
		err := adapter.SaveToken(ctx, tok)
		require.NoError(t, err)

		got, err := adapter.GetToken(ctx, "adapter_valid_token")
		require.NoError(t, err)
		assert.True(t, got.IsValid())
	})
}

func TestStorageAdapter_GetTokenByID(t *testing.T) {
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

	created, err := CreateToken(&TokenCreateRequest{
		TenantID:      "tenant-byid",
		ControllerURL: "grpc://controller:7443",
		Group:         "byid-group",
	})
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	require.NoError(t, adapter.SaveToken(ctx, created))

	t.Run("round-trips the token metadata by its stable ID", func(t *testing.T) {
		got, err := adapter.GetTokenByID(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, got.ID)
		assert.Equal(t, "tenant-byid", got.TenantID)
		assert.Equal(t, "byid-group", got.Group)
		assert.Equal(t, "grpc://controller:7443", got.ControllerURL)
		assert.False(t, got.Revoked)
	})

	t.Run("lookup by ID never yields the bearer secret", func(t *testing.T) {
		got, err := adapter.GetTokenByID(ctx, created.ID)
		require.NoError(t, err)

		// Tokens are persisted as a non-reversible lookup key. The plaintext
		// exists only in the mint-window value returned by CreateToken, so an
		// ID lookup — which the web UI performs on every token listing — must
		// not be able to hand the secret back out.
		assert.NotEqual(t, created.Token, got.Token,
			"reading a token by ID must not reproduce the bearer secret")
		assert.Equal(t, business.RegistrationTokenLookupKey(created.Token), got.Token,
			"stored value must be the deterministic lookup key")
		assert.Equal(t, business.RegistrationTokenDisplayPrefix(created.Token),
			business.RegistrationTokenDisplayPrefix(got.Token),
			"the operator-facing prefix must survive so a token stays identifiable")
	})

	t.Run("GetToken also returns the stable ID", func(t *testing.T) {
		got, err := adapter.GetToken(ctx, created.Token)
		require.NoError(t, err)
		assert.Equal(t, created.ID, got.ID, "the ID must survive the storage round-trip")
	})

	t.Run("ListTokens returns the stable ID", func(t *testing.T) {
		tokens, err := adapter.ListTokens(ctx, "tenant-byid")
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, created.ID, tokens[0].ID)
	})

	t.Run("unknown ID returns a not-found error", func(t *testing.T) {
		_, err := adapter.GetTokenByID(ctx, "aaaaaaaa-0000-4000-8000-00000000dead")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("the secret string does not resolve as an ID", func(t *testing.T) {
		_, err := adapter.GetTokenByID(ctx, created.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("rotated token is addressable by its new ID", func(t *testing.T) {
		rotated, err := adapter.RotateToken(ctx, "tenant-byid", "byid-group")
		require.NoError(t, err)
		require.NotEmpty(t, rotated.ID)
		assert.NotEqual(t, created.ID, rotated.ID)

		got, err := adapter.GetTokenByID(ctx, rotated.ID)
		require.NoError(t, err)
		assert.Equal(t, business.RegistrationTokenLookupKey(rotated.Token), got.Token,
			"the rotated record must be stored under its lookup key, not its secret")
		assert.False(t, got.Revoked)

		// The freshly minted secret still resolves through the secret-keyed path,
		// which is what a registering steward actually presents.
		bySecret, err := adapter.GetToken(ctx, rotated.Token)
		require.NoError(t, err)
		assert.Equal(t, rotated.ID, bySecret.ID)
	})
}

func TestStorageAdapter_SaveToken_AssignsIDWhenMissing(t *testing.T) {
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
		Token:         "adapter-token-without-id",
		TenantID:      "tenant-noid",
		ControllerURL: "grpc://controller:7443",
		CreatedAt:     time.Now(),
	}
	require.NoError(t, adapter.SaveToken(ctx, token))
	require.NotEmpty(t, token.ID, "SaveToken must write the assigned ID back onto the caller's token")

	assert.Equal(t, "adapter-token-without-id", token.Token,
		"SaveToken must not overwrite the caller's plaintext token with its storage key")

	got, err := adapter.GetToken(ctx, token.Token)
	require.NoError(t, err)
	assert.Equal(t, token.ID, got.ID, "the persisted ID must match the one written back")

	byID, err := adapter.GetTokenByID(ctx, got.ID)
	require.NoError(t, err)
	assert.Equal(t, business.RegistrationTokenLookupKey(token.Token), byID.Token,
		"the record resolved by ID must carry the lookup key, not the bearer secret")
	assert.Equal(t, token.ID, byID.ID)
}

func TestStorageAdapter_InterfaceCompliance(t *testing.T) {
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

	now := time.Now().UTC().Truncate(time.Millisecond)
	expiresAt := now.Add(24 * time.Hour)
	original := &Token{
		Token:         "compliance-test-token",
		TenantID:      "tenant-compliance",
		ControllerURL: "grpc://localhost:7443",
		Group:         "compliance-group",
		CreatedAt:     now,
		ExpiresAt:     &expiresAt,
		Revoked:       false,
	}

	require.NoError(t, adapter.SaveToken(ctx, original))

	got, err := adapter.GetToken(ctx, original.Token)
	require.NoError(t, err)

	assert.Equal(t, original.Token, got.Token)
	assert.Equal(t, original.TenantID, got.TenantID)
	assert.Equal(t, original.ControllerURL, got.ControllerURL)
	assert.Equal(t, original.Group, got.Group)
	assert.WithinDuration(t, original.CreatedAt, got.CreatedAt, time.Second)
	require.NotNil(t, got.ExpiresAt)
	assert.WithinDuration(t, *original.ExpiresAt, *got.ExpiresAt, time.Second)
	assert.Nil(t, got.RevokedAt)
	assert.Equal(t, original.Revoked, got.Revoked)
}

func TestStorageAdapter_RotateToken_Race(t *testing.T) {
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

	// Seed initial token
	token := &Token{
		Token:         "sqlite-rotate-seed",
		TenantID:      "tenant-race",
		ControllerURL: "grpc://controller:7443",
		Group:         "race-group",
		CreatedAt:     time.Now(),
	}
	require.NoError(t, adapter.SaveToken(ctx, token))

	const goroutines = 20
	var (
		successCount atomic.Int32
		wg           sync.WaitGroup
		start        = make(chan struct{})
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			<-start
			_, err := adapter.RotateToken(ctx, "tenant-race", "race-group")
			if err == nil {
				successCount.Add(1)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	// All rotations must succeed (each one finds the previous rotation's token as active)
	assert.Equal(t, int32(goroutines), successCount.Load(), "all concurrent rotations must succeed")

	// Exactly one valid token must remain
	tokens, err := adapter.ListTokens(ctx, "tenant-race")
	require.NoError(t, err)

	validCount := 0
	for _, tok := range tokens {
		if !tok.Revoked {
			validCount++
		}
	}
	assert.Equal(t, 1, validCount, "exactly one valid token must exist after all rotations")
}
