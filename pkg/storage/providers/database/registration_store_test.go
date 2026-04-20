// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestRegistrationStore(t *testing.T) *DatabaseRegistrationTokenStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateRegistrationTokensTable(ctx, db))
	return &DatabaseRegistrationTokenStore{db: db, config: nil, schemas: schemas}
}

func TestDatabaseRegistrationStore_ConsumeToken_SingleUse(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		Token:         "db-tok-consume-single",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
		SingleUse:     true,
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, token))

	// First consume must succeed.
	require.NoError(t, store.ConsumeToken(ctx, "db-tok-consume-single", "steward-1"))

	// Second consume must return ErrTokenAlreadyUsed.
	err := store.ConsumeToken(ctx, "db-tok-consume-single", "steward-2")
	require.ErrorIs(t, err, business.ErrTokenAlreadyUsed)
}

func TestDatabaseRegistrationStore_ConsumeToken_MultiUse(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		Token:         "db-tok-consume-multi",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
		SingleUse:     false,
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, token))

	// Multiple consumes of multi-use token must all succeed.
	require.NoError(t, store.ConsumeToken(ctx, "db-tok-consume-multi", "steward-1"))
	require.NoError(t, store.ConsumeToken(ctx, "db-tok-consume-multi", "steward-2"))
}

func TestDatabaseRegistrationStore_ConsumeToken_NotFound(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	err := store.ConsumeToken(ctx, "db-nonexistent", "steward-1")
	require.Error(t, err)
	require.NotErrorIs(t, err, business.ErrTokenAlreadyUsed)
}

func TestDatabaseRegistrationStore_ConsumeToken_Revoked(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		Token:         "db-tok-revoked",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
		SingleUse:     true,
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, token))
	token.Revoke()
	require.NoError(t, store.UpdateToken(ctx, token))

	err := store.ConsumeToken(ctx, "db-tok-revoked", "steward-1")
	require.Error(t, err)
	require.NotErrorIs(t, err, business.ErrTokenAlreadyUsed)
}

func TestDatabaseRegistrationStore_ConsumeToken_Race(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		Token:         "db-tok-race",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
		SingleUse:     true,
		CreatedAt:     time.Now().UTC(),
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
			err := store.ConsumeToken(ctx, "db-tok-race", "steward-"+string(rune('A'+id)))
			switch err {
			case nil:
				successCount.Add(1)
			case business.ErrTokenAlreadyUsed:
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
