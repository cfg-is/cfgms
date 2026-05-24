// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func newRegistrationStore(t *testing.T) business.RegistrationTokenStore {
	t.Helper()
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	store, err := p.CreateRegistrationTokenStore(map[string]interface{}{"path": filepath.Join(dir, "reg.db")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestRegistrationStore_SaveAndGet(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		Token:         "tok-abc123",
		TenantID:      "tenant-1",
		ControllerURL: "https://controller.example.com",
		Group:         "servers",
	}
	require.NoError(t, store.SaveToken(ctx, token))

	got, err := store.GetToken(ctx, "tok-abc123")
	require.NoError(t, err)
	assert.Equal(t, token.Token, got.Token)
	assert.Equal(t, token.TenantID, got.TenantID)
	assert.Equal(t, token.ControllerURL, got.ControllerURL)
	assert.Equal(t, token.Group, got.Group)
	assert.False(t, got.Revoked)
	assert.Nil(t, got.ExpiresAt)
}

func TestRegistrationStore_GetNotFound(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()
	_, err := store.GetToken(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestRegistrationStore_Update(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		Token:         "tok-upd",
		TenantID:      "tenant-1",
		ControllerURL: "https://c.example.com",
	}
	require.NoError(t, store.SaveToken(ctx, token))

	token.Revoke()
	require.NoError(t, store.UpdateToken(ctx, token))

	got, err := store.GetToken(ctx, "tok-upd")
	require.NoError(t, err)
	assert.True(t, got.Revoked)
	assert.NotNil(t, got.RevokedAt)
}

func TestRegistrationStore_SaveToken_Upsert(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	tok := &business.RegistrationTokenData{
		Token:         "tok-upsert",
		TenantID:      "tenant-1",
		ControllerURL: "https://c.example.com",
	}
	require.NoError(t, store.SaveToken(ctx, tok))

	// Second SaveToken with the same primary key must not fail and must
	// persist the updated state (revoked).
	tok.Revoke()
	require.NoError(t, store.SaveToken(ctx, tok))

	got, err := store.GetToken(ctx, "tok-upsert")
	require.NoError(t, err)
	assert.True(t, got.Revoked, "revoked state must be persisted after second SaveToken")
	assert.False(t, got.IsValid(), "revoked token must be invalid")
}

func TestRegistrationStore_Delete(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		Token:         "tok-del",
		TenantID:      "tenant-1",
		ControllerURL: "https://c.example.com",
	}
	require.NoError(t, store.SaveToken(ctx, token))
	require.NoError(t, store.DeleteToken(ctx, "tok-del"))
	_, err := store.GetToken(ctx, "tok-del")
	assert.Error(t, err)
}

func TestRegistrationStore_Delete_NotFound(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()
	assert.Error(t, store.DeleteToken(ctx, "nonexistent"))
}

func TestRegistrationStore_Expiry(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(1 * time.Hour)

	expired := &business.RegistrationTokenData{
		Token:         "tok-expired",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
		ExpiresAt:     &past,
	}
	valid := &business.RegistrationTokenData{
		Token:         "tok-valid",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
		ExpiresAt:     &future,
	}

	require.NoError(t, store.SaveToken(ctx, expired))
	require.NoError(t, store.SaveToken(ctx, valid))

	gotExpired, err := store.GetToken(ctx, "tok-expired")
	require.NoError(t, err)
	assert.False(t, gotExpired.IsValid(), "expired token should not be valid")

	gotValid, err := store.GetToken(ctx, "tok-valid")
	require.NoError(t, err)
	assert.True(t, gotValid.IsValid(), "non-expired token should be valid")
}

func TestRegistrationStore_Revoke(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	token := &business.RegistrationTokenData{
		Token:         "tok-rev",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
	}
	require.NoError(t, store.SaveToken(ctx, token))
	token.Revoke()
	require.NoError(t, store.UpdateToken(ctx, token))

	got, err := store.GetToken(ctx, "tok-rev")
	require.NoError(t, err)
	assert.True(t, got.Revoked)
	assert.False(t, got.IsValid())
}

func TestRegistrationStore_List(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	for _, tok := range []*business.RegistrationTokenData{
		{Token: "l-1", TenantID: "t-a", ControllerURL: "https://c.example.com", Group: "servers"},
		{Token: "l-2", TenantID: "t-b", ControllerURL: "https://c.example.com", Group: "servers"},
		{Token: "l-3", TenantID: "t-a", ControllerURL: "https://c.example.com", Group: "workstations"},
	} {
		require.NoError(t, store.SaveToken(ctx, tok))
	}

	all, err := store.ListTokens(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, all, 3)

	byTenant, err := store.ListTokens(ctx, &business.RegistrationTokenFilter{TenantID: "t-a"})
	require.NoError(t, err)
	assert.Len(t, byTenant, 2)

	byGroup, err := store.ListTokens(ctx, &business.RegistrationTokenFilter{Group: "servers"})
	require.NoError(t, err)
	assert.Len(t, byGroup, 2)
}

func TestRegistrationStore_RotateToken_Basic(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	seed := &business.RegistrationTokenData{
		Token:         "rotate-seed",
		TenantID:      "tenant-rotate",
		ControllerURL: "grpc://controller:7443",
		Group:         "prod",
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

func TestRegistrationStore_RotateToken_NoActiveTokens(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	_, err := store.RotateToken(ctx, "tenant-none", "group-none")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no active tokens found")
}

func TestRegistrationStore_RotateToken_RevokedTokenNotCounted(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	revoked := &business.RegistrationTokenData{
		Token:         "already-revoked",
		TenantID:      "tenant-rev",
		ControllerURL: "grpc://controller:7443",
		Group:         "group-a",
		Revoked:       true,
	}
	require.NoError(t, store.SaveToken(ctx, revoked))

	_, err := store.RotateToken(ctx, "tenant-rev", "group-a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no active tokens found")
}

func TestRegistrationStore_RotateToken_Race(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	seed := &business.RegistrationTokenData{
		Token:         "race-seed",
		TenantID:      "tenant-race",
		ControllerURL: "grpc://controller:7443",
		Group:         "race-group",
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

	// All rotations must succeed (each one finds the previous rotation's token as active).
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
