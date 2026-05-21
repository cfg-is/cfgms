// SPDX-License-Identifier: Apache-2.0
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
