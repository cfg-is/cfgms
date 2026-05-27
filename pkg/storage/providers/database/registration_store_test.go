// SPDX-License-Identifier: AGPL-3.0-only
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

func TestDatabaseRegistrationStore_RotateToken_Basic(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	seed := &business.RegistrationTokenData{
		Token:         "db-rotate-seed",
		TenantID:      "tenant-rotate",
		ControllerURL: "grpc://controller:7443",
		Group:         "prod",
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, seed))

	newTok, err := store.RotateToken(ctx, "tenant-rotate", "prod")
	require.NoError(t, err)
	assert.NotEmpty(t, newTok.Token)
	assert.NotEqual(t, seed.Token, newTok.Token)
	assert.Equal(t, "tenant-rotate", newTok.TenantID)
	assert.Equal(t, "grpc://controller:7443", newTok.ControllerURL)
	assert.Equal(t, "prod", newTok.Group)

	// Old token must be revoked.
	old, err := store.GetToken(ctx, seed.Token)
	require.NoError(t, err)
	assert.True(t, old.Revoked)

	// New token must be valid.
	got, err := store.GetToken(ctx, newTok.Token)
	require.NoError(t, err)
	assert.True(t, got.IsValid())
}

func TestDatabaseRegistrationStore_RotateToken_NoActiveTokens(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	_, err := store.RotateToken(ctx, "tenant-none", "group-none")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no active tokens found")
}

func TestDatabaseRegistrationStore_RotateToken_RevokedTokenNotCounted(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	revoked := &business.RegistrationTokenData{
		Token:         "db-already-revoked",
		TenantID:      "tenant-rev",
		ControllerURL: "grpc://controller:7443",
		Group:         "group-a",
		Revoked:       true,
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, revoked))

	_, err := store.RotateToken(ctx, "tenant-rev", "group-a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no active tokens found")
}

func TestDatabaseRegistrationStore_RotateToken_Race(t *testing.T) {
	store := newTestRegistrationStore(t)
	ctx := context.Background()

	seed := &business.RegistrationTokenData{
		Token:         "db-race-seed",
		TenantID:      "tenant-race",
		ControllerURL: "grpc://controller:7443",
		Group:         "race-group",
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, store.SaveToken(ctx, seed))

	const goroutines = 20
	var (
		successCount atomic.Int32
		wg           sync.WaitGroup
		start        = make(chan struct{})
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := store.RotateToken(ctx, "tenant-race", "race-group")
			if err == nil {
				successCount.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	// All rotations must succeed (each finds the previous rotation's token as active).
	assert.Equal(t, int32(goroutines), successCount.Load(), "all concurrent rotations must succeed")

	// Exactly one valid token must remain.
	tokens, err := store.ListTokens(ctx, &business.RegistrationTokenFilter{TenantID: "tenant-race"})
	require.NoError(t, err)

	validCount := 0
	for _, tok := range tokens {
		if !tok.Revoked {
			validCount++
		}
	}
	assert.Equal(t, 1, validCount, "exactly one valid token must exist after all rotations")
}
