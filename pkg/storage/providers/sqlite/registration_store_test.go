// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func newRegistrationStore(t *testing.T) interfaces.RegistrationTokenStore {
	t.Helper()
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	store, err := p.CreateRegistrationTokenStore(map[string]interface{}{"path": filepath.Join(dir, "reg.db")})
	require.NoError(t, err)
	return store
}

func TestRegistrationStore_SaveAndGet(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	token := &interfaces.RegistrationTokenData{
		Token:         "tok-abc123",
		TenantID:      "tenant-1",
		ControllerURL: "https://controller.example.com",
		Group:         "servers",
		SingleUse:     true,
	}
	require.NoError(t, store.SaveToken(ctx, token))

	got, err := store.GetToken(ctx, "tok-abc123")
	require.NoError(t, err)
	assert.Equal(t, token.Token, got.Token)
	assert.Equal(t, token.TenantID, got.TenantID)
	assert.Equal(t, token.ControllerURL, got.ControllerURL)
	assert.Equal(t, token.Group, got.Group)
	assert.True(t, got.SingleUse)
	assert.False(t, got.Revoked)
	assert.Nil(t, got.UsedAt)
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

	token := &interfaces.RegistrationTokenData{
		Token:         "tok-upd",
		TenantID:      "tenant-1",
		ControllerURL: "https://c.example.com",
		SingleUse:     true,
	}
	require.NoError(t, store.SaveToken(ctx, token))

	// Mark as used
	token.MarkUsed("steward-xyz")
	require.NoError(t, store.UpdateToken(ctx, token))

	got, err := store.GetToken(ctx, "tok-upd")
	require.NoError(t, err)
	assert.NotNil(t, got.UsedAt)
	assert.Equal(t, "steward-xyz", got.UsedBy)
}

func TestRegistrationStore_Delete(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	token := &interfaces.RegistrationTokenData{
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

	expired := &interfaces.RegistrationTokenData{
		Token:         "tok-expired",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
		ExpiresAt:     &past,
	}
	valid := &interfaces.RegistrationTokenData{
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

	token := &interfaces.RegistrationTokenData{
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

	for _, tok := range []*interfaces.RegistrationTokenData{
		{Token: "l-1", TenantID: "t-a", ControllerURL: "https://c.example.com", Group: "servers"},
		{Token: "l-2", TenantID: "t-b", ControllerURL: "https://c.example.com", Group: "servers"},
		{Token: "l-3", TenantID: "t-a", ControllerURL: "https://c.example.com", Group: "workstations"},
	} {
		require.NoError(t, store.SaveToken(ctx, tok))
	}

	all, err := store.ListTokens(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, all, 3)

	byTenant, err := store.ListTokens(ctx, &interfaces.RegistrationTokenFilter{TenantID: "t-a"})
	require.NoError(t, err)
	assert.Len(t, byTenant, 2)

	byGroup, err := store.ListTokens(ctx, &interfaces.RegistrationTokenFilter{Group: "servers"})
	require.NoError(t, err)
	assert.Len(t, byGroup, 2)
}

func TestRegistrationStore_ListUsedFilter(t *testing.T) {
	store := newRegistrationStore(t)
	ctx := context.Background()

	tok := &interfaces.RegistrationTokenData{
		Token:         "tok-used",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
		SingleUse:     true,
	}
	require.NoError(t, store.SaveToken(ctx, tok))
	tok.MarkUsed("s-1")
	require.NoError(t, store.UpdateToken(ctx, tok))

	require.NoError(t, store.SaveToken(ctx, &interfaces.RegistrationTokenData{
		Token:         "tok-unused",
		TenantID:      "t",
		ControllerURL: "https://c.example.com",
	}))

	trueVal := true
	falseVal := false

	used, err := store.ListTokens(ctx, &interfaces.RegistrationTokenFilter{Used: &trueVal})
	require.NoError(t, err)
	assert.Len(t, used, 1)
	assert.Equal(t, "tok-used", used[0].Token)

	unused, err := store.ListTokens(ctx, &interfaces.RegistrationTokenFilter{Used: &falseVal})
	require.NoError(t, err)
	assert.Len(t, unused, 1)
	assert.Equal(t, "tok-unused", unused[0].Token)
}
