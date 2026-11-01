// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_RotateToken_Basic(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	// Seed an initial token.
	initial := &Token{
		Token:         "initial-token",
		TenantID:      "tenant-1",
		ControllerURL: "grpc://controller:7443",
		Group:         "production",
		CreatedAt:     time.Now(),
	}
	require.NoError(t, store.SaveToken(ctx, initial))

	newTok, err := store.RotateToken(ctx, "tenant-1", "production")
	require.NoError(t, err)
	assert.NotEmpty(t, newTok.Token)
	assert.NotEqual(t, initial.Token, newTok.Token, "rotate must generate a different token string")
	assert.Equal(t, "tenant-1", newTok.TenantID)
	assert.Equal(t, "grpc://controller:7443", newTok.ControllerURL)
	assert.Equal(t, "production", newTok.Group)

	// Old token must now be revoked.
	got, err := store.GetToken(ctx, initial.Token)
	require.NoError(t, err)
	assert.True(t, got.Revoked, "initial token must be revoked after rotation")
}

func TestMemoryStore_GetTokenByID(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	tok, err := CreateToken(&TokenCreateRequest{
		TenantID:      "tenant-byid",
		ControllerURL: "grpc://controller:7443",
		Group:         "byid-group",
	})
	require.NoError(t, err)
	require.NotEmpty(t, tok.ID)
	require.NoError(t, store.SaveToken(ctx, tok))

	got, err := store.GetTokenByID(ctx, tok.ID)
	require.NoError(t, err)
	assert.Equal(t, tok.Token, got.Token, "lookup by ID must return the same token")
	assert.Equal(t, tok.ID, got.ID)
	assert.Equal(t, "tenant-byid", got.TenantID)
	assert.Equal(t, "byid-group", got.Group)
}

func TestMemoryStore_GetTokenByID_NotFound(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	_, err := store.GetTokenByID(ctx, "aaaaaaaa-0000-4000-8000-000000000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// The secret string must not resolve through the ID index.
	tok, err := CreateToken(&TokenCreateRequest{
		TenantID:      "tenant-byid",
		ControllerURL: "grpc://controller:7443",
	})
	require.NoError(t, err)
	require.NoError(t, store.SaveToken(ctx, tok))

	_, err = store.GetTokenByID(ctx, tok.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMemoryStore_SaveToken_AssignsIDWhenMissing(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	tok := &Token{
		Token:         "no-id-token",
		TenantID:      "tenant-noid",
		ControllerURL: "grpc://controller:7443",
		CreatedAt:     time.Now(),
	}
	require.NoError(t, store.SaveToken(ctx, tok))
	require.NotEmpty(t, tok.ID, "SaveToken must assign an ID when the caller supplies none")
	assignedID := tok.ID

	got, err := store.GetTokenByID(ctx, assignedID)
	require.NoError(t, err)
	assert.Equal(t, "no-id-token", got.Token)

	// Re-saving the same token string must keep the ID stable.
	resaved := &Token{
		Token:         "no-id-token",
		TenantID:      "tenant-noid",
		ControllerURL: "grpc://controller:7443",
		CreatedAt:     tok.CreatedAt,
	}
	require.NoError(t, store.SaveToken(ctx, resaved))
	assert.Equal(t, assignedID, resaved.ID, "token ID must be stable across saves")
}

func TestMemoryStore_DeleteToken_ClearsIDIndex(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	tok, err := CreateToken(&TokenCreateRequest{
		TenantID:      "tenant-del",
		ControllerURL: "grpc://controller:7443",
	})
	require.NoError(t, err)
	require.NoError(t, store.SaveToken(ctx, tok))
	require.NoError(t, store.DeleteToken(ctx, tok.Token))

	_, err = store.GetTokenByID(ctx, tok.ID)
	require.Error(t, err, "a deleted token must not remain addressable by ID")
	assert.Contains(t, err.Error(), "not found")
}

func TestMemoryStore_RotateToken_AssignsIDToNewToken(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	initial, err := CreateToken(&TokenCreateRequest{
		TenantID:      "tenant-rot-id",
		ControllerURL: "grpc://controller:7443",
		Group:         "rot-group",
	})
	require.NoError(t, err)
	require.NoError(t, store.SaveToken(ctx, initial))

	rotated, err := store.RotateToken(ctx, "tenant-rot-id", "rot-group")
	require.NoError(t, err)
	require.NotEmpty(t, rotated.ID)
	assert.NotEqual(t, initial.ID, rotated.ID, "rotation must mint a new ID")

	byID, err := store.GetTokenByID(ctx, rotated.ID)
	require.NoError(t, err)
	assert.Equal(t, rotated.Token, byID.Token)

	// The rotated-away token remains addressable by its own ID (and is revoked).
	old, err := store.GetTokenByID(ctx, initial.ID)
	require.NoError(t, err)
	assert.True(t, old.Revoked)
}

func TestMemoryStore_RotateToken_NoActiveTokens(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	_, err := store.RotateToken(ctx, "tenant-none", "group-none")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no active tokens found")
}

func TestRotateToken_InvalidatesOldTokenAtomically(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	// Seed an initial token.
	initial := &Token{
		Token:         "initial-concurrent-token",
		TenantID:      "tenant-concurrent",
		ControllerURL: "grpc://controller:7443",
		Group:         "concurrent-group",
		CreatedAt:     time.Now(),
	}
	require.NoError(t, store.SaveToken(ctx, initial))

	const goroutines = 20
	results := make([]*Token, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			<-start
			results[id], errs[id] = store.RotateToken(ctx, "tenant-concurrent", "concurrent-group")
		}(i)
	}

	close(start)
	wg.Wait()

	// All rotations must succeed.
	for i, err := range errs {
		require.NoError(t, err, "goroutine %d got unexpected error", i)
	}

	// After N concurrent rotations, exactly one token must be valid.
	allTokens, err := store.ListTokens(ctx, "tenant-concurrent")
	require.NoError(t, err)

	validCount := 0
	for _, tok := range allTokens {
		if !tok.Revoked {
			validCount++
		}
	}
	assert.Equal(t, 1, validCount, "exactly one valid token must exist after concurrent rotations")

	// The initial token must be revoked.
	gotInitial, err := store.GetToken(ctx, initial.Token)
	require.NoError(t, err)
	assert.True(t, gotInitial.Revoked, "initial token must be revoked after rotation")
}

func TestMemoryStore_RotateToken_RevokedTokenNotCounted(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	// Seed a revoked token — RotateToken must not consider it active.
	revoked := &Token{
		Token:         "already-revoked",
		TenantID:      "tenant-2",
		ControllerURL: "grpc://controller:7443",
		Group:         "group-a",
		Revoked:       true,
		CreatedAt:     time.Now(),
	}
	require.NoError(t, store.SaveToken(ctx, revoked))

	_, err := store.RotateToken(ctx, "tenant-2", "group-a")
	require.Error(t, err, "no active tokens should cause an error")
	assert.Contains(t, err.Error(), "no active tokens found")
}
