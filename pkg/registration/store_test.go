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
)

func TestMemoryStore_ConsumeToken_SingleUse_Race(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	token := &Token{
		Token:     "single-use-race-token",
		TenantID:  "tenant-1",
		SingleUse: true,
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.SaveToken(ctx, token))

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
			err := store.ConsumeToken(ctx, "single-use-race-token", "steward-"+string(rune('A'+id)))
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

func TestMemoryStore_ConsumeToken_MultiUse(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	token := &Token{
		Token:     "multi-use-token",
		TenantID:  "tenant-1",
		SingleUse: false,
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.SaveToken(ctx, token))

	// Multiple consumes of a multi-use token must all succeed.
	require.NoError(t, store.ConsumeToken(ctx, "multi-use-token", "steward-1"))
	require.NoError(t, store.ConsumeToken(ctx, "multi-use-token", "steward-2"))
}

func TestMemoryStore_ConsumeToken_TokenNotFound(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	err := store.ConsumeToken(ctx, "nonexistent", "steward-1")
	require.Error(t, err)
	assert.NotEqual(t, interfaces.ErrTokenAlreadyUsed, err)
}

func TestMemoryStore_ConsumeToken_RevokedToken(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	token := &Token{
		Token:     "revoked-token",
		TenantID:  "tenant-1",
		SingleUse: true,
		Revoked:   true,
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.SaveToken(ctx, token))

	err := store.ConsumeToken(ctx, "revoked-token", "steward-1")
	require.Error(t, err)
	assert.NotEqual(t, interfaces.ErrTokenAlreadyUsed, err)
}

func TestMemoryStore_ConsumeToken_ExpiredToken(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	token := &Token{
		Token:     "expired-token",
		TenantID:  "tenant-1",
		SingleUse: false,
		ExpiresAt: &past,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	require.NoError(t, store.SaveToken(ctx, token))

	err := store.ConsumeToken(ctx, "expired-token", "steward-1")
	require.Error(t, err)
	assert.NotEqual(t, interfaces.ErrTokenAlreadyUsed, err)
}
