// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerapi "github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// TestRegistrationTokenPersistence_AcrossRestart validates that registration tokens
// persist across simulated controller restarts using git-based storage.
// This is a critical test for Story #263.
func TestRegistrationTokenPersistence_AcrossRestart(t *testing.T) {
	// Create temporary directory for persistent storage
	tempDir, err := os.MkdirTemp("", "reg-token-persistence-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	ctx := context.Background()

	// Phase 1: Create store and add tokens (simulates first controller run)
	t.Log("Phase 1: Creating tokens in first store instance")
	store1, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{"path": tempDir + "/tokens.db"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store1.Close() })
	err = store1.Initialize(ctx)
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

	// Phase 2: Simulate controller restart by creating new store instance
	t.Log("Phase 2: Simulating controller restart - creating new store instance")

	// Close first store (optional - git store has no connection to close)
	// In production, this happens when controller process terminates

	// Create new store instance pointing to same directory
	store2, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{"path": tempDir + "/tokens.db"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store2.Close() })
	err = store2.Initialize(ctx)
	require.NoError(t, err)

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
	tempDir, err := os.MkdirTemp("", "reg-token-expiry-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	ctx := context.Background()

	// Create store and token with past expiry
	store, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{"path": tempDir + "/tokens.db"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	err = store.Initialize(ctx)
	require.NoError(t, err)

	now := time.Now()
	pastExpiry := now.Add(-1 * time.Hour)

	expiredToken := &business.RegistrationTokenData{
		Token:     "cfgms_reg_expired_test",
		TenantID:  "tenant-expiry",
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: &pastExpiry,
	}

	err = store.SaveToken(ctx, expiredToken)
	require.NoError(t, err)

	// Reload store
	store2, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{"path": tempDir + "/tokens.db"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store2.Close() })
	err = store2.Initialize(ctx)
	require.NoError(t, err)

	// Retrieve and check validity
	retrieved, err := store2.GetToken(ctx, "cfgms_reg_expired_test")
	require.NoError(t, err)
	assert.False(t, retrieved.IsValid(), "Expired token should be invalid after reload")
}

// TestRegistrationTokenPersistence_TokenRevocation validates that revocation status
// is correctly persisted
func TestRegistrationTokenPersistence_TokenRevocation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "reg-token-revoke-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	ctx := context.Background()

	// Create store and add token
	store, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{"path": tempDir + "/tokens.db"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	err = store.Initialize(ctx)
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

	// Reload store
	store2, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{"path": tempDir + "/tokens.db"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store2.Close() })
	err = store2.Initialize(ctx)
	require.NoError(t, err)

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
	tempDir, err := os.MkdirTemp("", "reg-token-delete-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	ctx := context.Background()

	// Create store and add token
	store, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{"path": tempDir + "/tokens.db"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	err = store.Initialize(ctx)
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

	// Reload store
	store2, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{"path": tempDir + "/tokens.db"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store2.Close() })
	err = store2.Initialize(ctx)
	require.NoError(t, err)

	adapter2 := registration.NewStorageAdapter(store2)

	// Verify deletion persisted
	_, err = adapter2.GetToken(ctx, "cfgms_reg_delete_test")
	assert.Error(t, err, "Deleted token should not exist after reload")
	assert.Contains(t, err.Error(), "not found")
}

// TestConcurrentRegistration_SingleUseToken_ExactlyOneSucceeds validates that two
// concurrent HTTP POST /api/v1/register requests with the same single-use token
// produce exactly one 200 OK and one 409 Conflict against a real Server backed
// by SQLite storage. This proves the TOCTOU race fixed in Issue #774 holds under
// real concurrent HTTP load.
func TestConcurrentRegistration_SingleUseToken_ExactlyOneSucceeds(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "reg-concurrent-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	ctx := context.Background()

	// Build storage manager (RBAC + tenant)
	storageManager, err := interfaces.CreateOSSStorageManager(
		tempDir+"/flatfile",
		tempDir+"/cfgms.db",
	)
	require.NoError(t, err)
	defer func() { _ = storageManager.Close() }()

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(ctx))
	t.Cleanup(func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.FlushAudit(flushCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	// Build cert manager so handleRegister can reach the 200 path
	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir + "/certs",
		CAConfig: &cert.CAConfig{
			Organization: "Test CFGMS Concurrent",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Build SQLite-backed registration token store
	regTokenStore, err := interfaces.CreateRegistrationTokenStoreFromConfig(
		"sqlite",
		map[string]interface{}{"path": tempDir + "/tokens.db"},
	)
	require.NoError(t, err)
	defer func() { _ = regTokenStore.Close() }()
	require.NoError(t, regTokenStore.Initialize(ctx))

	tokenStore := registration.NewStorageAdapter(regTokenStore)

	// Build minimal controller services
	logger := logging.NewNoopLogger()
	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	server, err := controllerapi.New(
		cfg, logger, controllerService, configService, nil, rbacService,
		certMgr, tenantManager, rbacManager,
		nil, nil, nil, nil,
		tokenStore,
		"",
		nil,
	)
	require.NoError(t, err)

	// Seed a single-use token
	tok := &registration.Token{
		Token:         "cfgms_reg_concurrent_integ_test",
		TenantID:      "integ-tenant",
		ControllerURL: "grpc://controller:7443",
		SingleUse:     true,
	}
	require.NoError(t, tokenStore.SaveToken(ctx, tok))

	// Serve over a real HTTP test server
	ts := httptest.NewServer(server.GetRouter())
	defer ts.Close()

	type result struct{ code int }
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{"token": "cfgms_reg_concurrent_integ_test"})
			resp, postErr := ts.Client().Post(
				ts.URL+"/api/v1/register",
				"application/json",
				bytes.NewReader(body),
			)
			if postErr != nil {
				return
			}
			defer resp.Body.Close()
			results[idx] = result{code: resp.StatusCode}
		}(i)
	}
	wg.Wait()

	codes := []int{results[0].code, results[1].code}
	assert.Contains(t, codes, http.StatusOK, "exactly one goroutine must succeed with 200")
	assert.Contains(t, codes, http.StatusConflict, "exactly one goroutine must get 409")

	okCount, conflictCount := 0, 0
	for _, r := range results {
		switch r.code {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			conflictCount++
		}
	}
	assert.Equal(t, 1, okCount, "exactly one 200")
	assert.Equal(t, 1, conflictCount, "exactly one 409")
}
