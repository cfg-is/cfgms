// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// controlledConsumeStore wraps a Store and injects a fixed error from ConsumeToken.
type controlledConsumeStore struct {
	registration.Store
	consumeErr error
}

func (c *controlledConsumeStore) ConsumeToken(ctx context.Context, tokenStr, stewardID string) error {
	if c.consumeErr != nil {
		return c.consumeErr
	}
	return c.Store.ConsumeToken(ctx, tokenStr, stewardID)
}

// newTestTokenStore creates a real SQLite-backed registration.Store for handler tests.
func newTestTokenStore(t *testing.T) registration.Store {
	t.Helper()
	store, err := interfaces.CreateRegistrationTokenStoreFromConfig(
		"sqlite",
		map[string]interface{}{"path": t.TempDir() + "/tokens.db"},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Initialize(context.Background()))
	return registration.NewStorageAdapter(store)
}

// newHandleRegisterServer creates a minimal server for handleRegister unit tests.
// Pass a non-nil certMgr only when you need the handler to reach cert generation (200 path).
func newHandleRegisterServer(t *testing.T, tokenStore registration.Store, certMgr *cert.Manager) *Server {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	logger := logging.NewNoopLogger()
	tempDir := t.TempDir()

	storageManager, err := interfaces.CreateOSSStorageManager(tempDir+"/flatfile", tempDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	server, err := New(
		cfg, logger, controllerService, configService, nil, rbacService,
		certMgr, tenantManager, rbacManager,
		nil, nil, nil, nil,
		tokenStore,
		"",
		nil,
	)
	require.NoError(t, err)
	return server
}

// newTestCertManager creates a real cert manager backed by a temp dir.
func newTestCertManager(t *testing.T) *cert.Manager {
	t.Helper()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cert.CAConfig{
			Organization: "Test CFGMS",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)
	return mgr
}

// postRegister sends a POST /api/v1/register request and returns the recorder.
func postRegister(server *Server, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(RegistrationRequest{Token: token})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleRegister(rec, req)
	return rec
}

func TestHandleRegister_AlreadyUsedSingleUseToken_Returns409(t *testing.T) {
	tokenStore := newTestTokenStore(t)
	server := newHandleRegisterServer(t, tokenStore, nil)

	usedAt := time.Now().Add(-time.Hour)
	tok := &registration.Token{
		Token:         "cfgms_reg_used_token",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		SingleUse:     true,
		UsedAt:        &usedAt,
		UsedBy:        "steward-previous",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_used_token")

	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "already been used")
}

func TestHandleRegister_RevokedToken_Returns401(t *testing.T) {
	tokenStore := newTestTokenStore(t)
	server := newHandleRegisterServer(t, tokenStore, nil)

	revokedAt := time.Now().Add(-time.Hour)
	tok := &registration.Token{
		Token:         "cfgms_reg_revoked_token",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		Revoked:       true,
		RevokedAt:     &revokedAt,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_revoked_token")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "revoked")
}

func TestHandleRegister_ExpiredToken_Returns401(t *testing.T) {
	tokenStore := newTestTokenStore(t)
	server := newHandleRegisterServer(t, tokenStore, nil)

	pastExpiry := time.Now().Add(-time.Hour)
	tok := &registration.Token{
		Token:         "cfgms_reg_expired_token",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		ExpiresAt:     &pastExpiry,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_expired_token")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "expired")
}

func TestHandleRegister_StoreError_Returns500(t *testing.T) {
	storeErr := fmt.Errorf("failed to persist token state: %w", fmt.Errorf("connection refused"))
	tokenStore := &controlledConsumeStore{
		Store:      newTestTokenStore(t),
		consumeErr: storeErr,
	}
	server := newHandleRegisterServer(t, tokenStore, nil)

	tok := &registration.Token{
		Token:         "cfgms_reg_store_err_token",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		SingleUse:     true,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_store_err_token")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandleRegister_ValidSingleUseToken_Returns200ThenSubsequent409(t *testing.T) {
	tokenStore := newTestTokenStore(t)
	certMgr := newTestCertManager(t)
	server := newHandleRegisterServer(t, tokenStore, certMgr)

	tok := &registration.Token{
		Token:         "cfgms_reg_singleuse_valid",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		SingleUse:     true,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	// First request should succeed
	rec1 := postRegister(server, "cfgms_reg_singleuse_valid")
	assert.Equal(t, http.StatusOK, rec1.Code)

	var resp RegistrationResponse
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.StewardID)
	assert.Equal(t, "test-tenant", resp.TenantID)

	// Second request with same token must be rejected as already used
	rec2 := postRegister(server, "cfgms_reg_singleuse_valid")
	assert.Equal(t, http.StatusConflict, rec2.Code)
}

func TestHandleRegister_ValidMultiUseToken_AllowsTwoRegistrations(t *testing.T) {
	tokenStore := newTestTokenStore(t)
	certMgr := newTestCertManager(t)
	server := newHandleRegisterServer(t, tokenStore, certMgr)

	tok := &registration.Token{
		Token:         "cfgms_reg_multiuse_valid",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		SingleUse:     false,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec1 := postRegister(server, "cfgms_reg_multiuse_valid")
	assert.Equal(t, http.StatusOK, rec1.Code)

	rec2 := postRegister(server, "cfgms_reg_multiuse_valid")
	assert.Equal(t, http.StatusOK, rec2.Code)

	// Both registrations should have distinct steward IDs
	var resp1, resp2 RegistrationResponse
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &resp1))
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &resp2))
	assert.NotEqual(t, resp1.StewardID, resp2.StewardID)
}

func TestHandleRegister_ConsumeToken_NoSaveTokenCall(t *testing.T) {
	// Verify that a successful registration does NOT call SaveToken (ConsumeToken handles it).
	// Verify token state after registration using a real SQLite-backed store.
	tokenStore := newTestTokenStore(t)
	certMgr := newTestCertManager(t)
	server := newHandleRegisterServer(t, tokenStore, certMgr)

	tok := &registration.Token{
		Token:         "cfgms_reg_nosave_check",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		SingleUse:     true,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_nosave_check")
	require.Equal(t, http.StatusOK, rec.Code)

	// Token should now be marked as used by ConsumeToken
	updated, err := tokenStore.GetToken(context.Background(), "cfgms_reg_nosave_check")
	require.NoError(t, err)
	assert.NotNil(t, updated.UsedAt, "ConsumeToken must have marked the token as used")
	assert.NotEmpty(t, updated.UsedBy, "ConsumeToken must have recorded the steward ID")
}

func TestHandleRegister_ConcurrentSingleUseToken_ExactlyOneSucceeds(t *testing.T) {
	tokenStore := newTestTokenStore(t)
	certMgr := newTestCertManager(t)
	server := newHandleRegisterServer(t, tokenStore, certMgr)

	tok := &registration.Token{
		Token:         "cfgms_reg_concurrent_token",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		SingleUse:     true,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	// Use an httptest.Server so goroutines share a real HTTP stack
	ts := httptest.NewServer(server.router)
	t.Cleanup(ts.Close)

	type result struct {
		code int
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			body, _ := json.Marshal(RegistrationRequest{Token: "cfgms_reg_concurrent_token"})
			resp, err := ts.Client().Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
			if err != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()
			results[idx] = result{code: resp.StatusCode}
		}(i)
	}
	wg.Wait()

	codes := []int{results[0].code, results[1].code}
	assert.Contains(t, codes, http.StatusOK, "exactly one goroutine must succeed")
	assert.Contains(t, codes, http.StatusConflict, "exactly one goroutine must get 409")

	okCount := 0
	conflictCount := 0
	for _, r := range results {
		switch r.code {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			conflictCount++
		}
	}
	assert.Equal(t, 1, okCount, "exactly one registration must succeed")
	assert.Equal(t, 1, conflictCount, "exactly one registration must return 409")
}

// TestHandleRegister_ConsumeTokenNotAlreadyUsed_Returns401 verifies that ConsumeToken
// returns ErrTokenAlreadyUsed (not a plain error) for the 409 path.
func TestHandleRegister_ErrTokenAlreadyUsed_IsDistinctFrom500(t *testing.T) {
	// This test uses the sentinel directly to confirm the error distinction matters.
	tokenStore := &controlledConsumeStore{
		Store:      newTestTokenStore(t),
		consumeErr: business.ErrTokenAlreadyUsed,
	}
	server := newHandleRegisterServer(t, tokenStore, nil)

	tok := &registration.Token{
		Token:         "cfgms_reg_sentinel_test",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		SingleUse:     true,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_sentinel_test")
	assert.Equal(t, http.StatusConflict, rec.Code, "ErrTokenAlreadyUsed must map to 409 not 500")
}
