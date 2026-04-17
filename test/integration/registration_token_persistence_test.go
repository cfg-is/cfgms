// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newSQLiteTokenStore creates a SQLite-backed registration token store at path.
func newSQLiteTokenStore(t *testing.T, path string) interfaces.RegistrationTokenStore {
	t.Helper()
	store, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{
		"path": path,
	})
	require.NoError(t, err)
	return store
}

// TestRegistrationTokenPersistence_AcrossRestart validates that registration tokens
// persist across simulated controller restarts using SQLite-based storage.
// This is a critical test for Story #263.
func TestRegistrationTokenPersistence_AcrossRestart(t *testing.T) {
	// Create temporary directory for persistent storage
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "tokens.db")
	ctx := context.Background()

	// Phase 1: Create store and add tokens (simulates first controller run)
	t.Log("Phase 1: Creating tokens in first store instance")
	store1 := newSQLiteTokenStore(t, dbPath)
	err := store1.Initialize(ctx)
	require.NoError(t, err)

	// Create adapter for the first store
	adapter1 := registration.NewStorageAdapter(store1)

	// Create test tokens
	now := time.Now()
	futureExpiry := now.Add(24 * time.Hour)

	tokens := []*registration.Token{
		{
			Token:         "cfgms_reg_persist_test_1",
			TenantID:      "tenant-persistence-1",
			ControllerURL: "tcp://localhost:1883",
			Group:         "test-group",
			CreatedAt:     now,
			SingleUse:     false,
			Revoked:       false,
		},
		{
			Token:         "cfgms_reg_persist_test_2",
			TenantID:      "tenant-persistence-1",
			ControllerURL: "tcp://localhost:1883",
			Group:         "test-group",
			CreatedAt:     now,
			ExpiresAt:     &futureExpiry,
			SingleUse:     true,
			Revoked:       false,
		},
		{
			Token:         "cfgms_reg_persist_test_3",
			TenantID:      "tenant-persistence-2",
			ControllerURL: "tcp://localhost:1883",
			Group:         "other-group",
			CreatedAt:     now,
			SingleUse:     false,
			Revoked:       false,
		},
	}

	for _, token := range tokens {
		err := adapter1.SaveToken(ctx, token)
		require.NoError(t, err, "Failed to save token %s", token.Token)
		t.Logf("Saved token: %s (tenant: %s)", token.Token, token.TenantID)
	}

	// Mark one token as used
	token2, err := adapter1.GetToken(ctx, "cfgms_reg_persist_test_2")
	require.NoError(t, err)
	token2.MarkUsed("steward-001")
	err = adapter1.UpdateToken(ctx, token2)
	require.NoError(t, err)
	t.Log("Marked token 2 as used by steward-001")

	// Verify tokens exist in first store
	allTokens, err := adapter1.ListTokens(ctx, "tenant-persistence-1")
	require.NoError(t, err)
	assert.Len(t, allTokens, 2, "Should have 2 tokens for tenant-persistence-1")

	// Phase 2: Simulate controller restart by closing and reopening the store
	t.Log("Phase 2: Simulating controller restart - closing and reopening store")
	require.NoError(t, store1.Close())

	// Create new store instance pointing to same file
	store2 := newSQLiteTokenStore(t, dbPath)
	err = store2.Initialize(ctx)
	require.NoError(t, err)
	defer func() { _ = store2.Close() }()

	// Create new adapter
	adapter2 := registration.NewStorageAdapter(store2)

	// Phase 3: Verify all tokens persisted
	t.Log("Phase 3: Verifying tokens persisted after restart")

	// Verify token 1 exists and is valid
	retrieved1, err := adapter2.GetToken(ctx, "cfgms_reg_persist_test_1")
	require.NoError(t, err, "Token 1 should persist after restart")
	assert.Equal(t, "tenant-persistence-1", retrieved1.TenantID)
	assert.Equal(t, "test-group", retrieved1.Group)
	assert.True(t, retrieved1.IsValid(), "Token 1 should be valid")
	t.Log("Token 1 persisted correctly and is valid")

	// Verify token 2 exists with used status preserved
	retrieved2, err := adapter2.GetToken(ctx, "cfgms_reg_persist_test_2")
	require.NoError(t, err, "Token 2 should persist after restart")
	assert.NotNil(t, retrieved2.UsedAt, "Token 2 should retain used status")
	assert.Equal(t, "steward-001", retrieved2.UsedBy, "Token 2 should retain used_by")
	assert.False(t, retrieved2.IsValid(), "Token 2 should be invalid (single-use and used)")
	t.Log("Token 2 persisted with used status preserved")

	// Verify token 3 exists
	retrieved3, err := adapter2.GetToken(ctx, "cfgms_reg_persist_test_3")
	require.NoError(t, err, "Token 3 should persist after restart")
	assert.Equal(t, "tenant-persistence-2", retrieved3.TenantID)
	assert.True(t, retrieved3.IsValid(), "Token 3 should be valid")
	t.Log("Token 3 persisted correctly")

	// Verify list operations work after restart
	tenant1Tokens, err := adapter2.ListTokens(ctx, "tenant-persistence-1")
	require.NoError(t, err)
	assert.Len(t, tenant1Tokens, 2, "Should still have 2 tokens for tenant-persistence-1")

	tenant2Tokens, err := adapter2.ListTokens(ctx, "tenant-persistence-2")
	require.NoError(t, err)
	assert.Len(t, tenant2Tokens, 1, "Should have 1 token for tenant-persistence-2")

	t.Log("All tokens persisted successfully across simulated restart")
}

// TestRegistrationTokenPersistence_TokenExpiration validates that token expiration
// is correctly evaluated after storage reload
func TestRegistrationTokenPersistence_TokenExpiration(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "tokens.db")
	ctx := context.Background()

	// Create store and token with past expiry
	store := newSQLiteTokenStore(t, dbPath)
	err := store.Initialize(ctx)
	require.NoError(t, err)

	now := time.Now()
	pastExpiry := now.Add(-1 * time.Hour)

	expiredToken := &interfaces.RegistrationTokenData{
		Token:     "cfgms_reg_expired_test",
		TenantID:  "tenant-expiry",
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: &pastExpiry,
	}

	err = store.SaveToken(ctx, expiredToken)
	require.NoError(t, err)

	// Simulate restart
	require.NoError(t, store.Close())

	store2 := newSQLiteTokenStore(t, dbPath)
	err = store2.Initialize(ctx)
	require.NoError(t, err)
	defer func() { _ = store2.Close() }()

	// Retrieve and check validity
	retrieved, err := store2.GetToken(ctx, "cfgms_reg_expired_test")
	require.NoError(t, err)
	assert.False(t, retrieved.IsValid(), "Expired token should be invalid after reload")
}

// TestRegistrationTokenPersistence_TokenRevocation validates that revocation status
// is correctly persisted
func TestRegistrationTokenPersistence_TokenRevocation(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "tokens.db")
	ctx := context.Background()

	// Create store and add token
	store := newSQLiteTokenStore(t, dbPath)
	err := store.Initialize(ctx)
	require.NoError(t, err)

	adapter := registration.NewStorageAdapter(store)

	token := &registration.Token{
		Token:     "cfgms_reg_revoke_test",
		TenantID:  "tenant-revoke",
		CreatedAt: time.Now(),
	}
	err = adapter.SaveToken(ctx, token)
	require.NoError(t, err)

	// Revoke the token
	token.Revoke()
	err = adapter.UpdateToken(ctx, token)
	require.NoError(t, err)

	// Simulate restart
	require.NoError(t, store.Close())

	store2 := newSQLiteTokenStore(t, dbPath)
	err = store2.Initialize(ctx)
	require.NoError(t, err)
	defer func() { _ = store2.Close() }()

	adapter2 := registration.NewStorageAdapter(store2)

	// Verify revocation persisted
	retrieved, err := adapter2.GetToken(ctx, "cfgms_reg_revoke_test")
	require.NoError(t, err)
	assert.True(t, retrieved.Revoked, "Revocation status should persist")
	assert.NotNil(t, retrieved.RevokedAt, "Revocation time should persist")
	assert.False(t, retrieved.IsValid(), "Revoked token should be invalid")
}

// TestRegistrationTokenPersistence_DeletePersists validates that token deletion
// is persistent
func TestRegistrationTokenPersistence_DeletePersists(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "tokens.db")
	ctx := context.Background()

	// Create store and add token
	store := newSQLiteTokenStore(t, dbPath)
	err := store.Initialize(ctx)
	require.NoError(t, err)

	adapter := registration.NewStorageAdapter(store)

	token := &registration.Token{
		Token:     "cfgms_reg_delete_test",
		TenantID:  "tenant-delete",
		CreatedAt: time.Now(),
	}
	err = adapter.SaveToken(ctx, token)
	require.NoError(t, err)

	// Delete the token
	err = adapter.DeleteToken(ctx, "cfgms_reg_delete_test")
	require.NoError(t, err)

	// Simulate restart
	require.NoError(t, store.Close())

	store2 := newSQLiteTokenStore(t, dbPath)
	err = store2.Initialize(ctx)
	require.NoError(t, err)
	defer func() { _ = store2.Close() }()

	adapter2 := registration.NewStorageAdapter(store2)

	// Verify deletion persisted
	_, err = adapter2.GetToken(ctx, "cfgms_reg_delete_test")
	assert.Error(t, err, "Deleted token should not exist after reload")
	assert.Contains(t, err.Error(), "not found")
}
