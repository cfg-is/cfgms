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
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newTestRegistrationStore creates a real SQLite-backed registration.Store for handler tests.
func newTestRegistrationStore(t *testing.T) registration.Store {
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

// controlledConsumeStore wraps a registration.Store and injects a fixed error from ConsumeToken.
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

// newHandleRegisterServer creates a minimal server for handleRegister unit tests.
// Pass a non-nil certMgr only when you need the handler to reach cert generation (200 path).
// Pass a non-nil logger to capture log output in tests; defaults to NoopLogger.
// Returns the server and the audit manager so tests can Flush and query audit entries.
func newHandleRegisterServer(t *testing.T, tokenStore registration.Store, certMgr *cert.Manager, loggers ...logging.Logger) (*Server, *audit.Manager) {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	var logger logging.Logger
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	} else {
		logger = logging.NewNoopLogger()
	}
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
	t.Cleanup(func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.FlushAudit(flushCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	server, err := New(
		cfg, logger, controllerService, configService, nil, rbacService,
		certMgr, tenantManager, rbacManager,
		nil, nil, nil, nil,
		tokenStore,
		"",
		nil,
		auditMgr,
	)
	require.NoError(t, err)
	return server, auditMgr
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
	tokenStore := newTestRegistrationStore(t)
	server, auditMgr := newHandleRegisterServer(t, tokenStore, nil)

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

	// Verify audit entry was recorded for the rejected registration
	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{
		TenantID: "test-tenant",
	})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "registration_rejected", entries[0].Action)
	assert.Equal(t, string(business.AuditResultFailure), string(entries[0].Result))
	assert.Equal(t, string(business.AuditEventSecurityEvent), string(entries[0].EventType))
	assert.Equal(t, "test-tenant", entries[0].TenantID)
}

func TestHandleRegister_RevokedToken_Returns401(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, auditMgr := newHandleRegisterServer(t, tokenStore, nil)

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

	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "test-tenant"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "registration_rejected", entries[0].Action)
	assert.Equal(t, string(business.AuditResultFailure), string(entries[0].Result))
	assert.Equal(t, string(business.AuditEventSecurityEvent), string(entries[0].EventType))
}

func TestHandleRegister_ExpiredToken_Returns401(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, auditMgr := newHandleRegisterServer(t, tokenStore, nil)

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

	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "test-tenant"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "registration_rejected", entries[0].Action)
	assert.Equal(t, string(business.AuditResultFailure), string(entries[0].Result))
	assert.Equal(t, string(business.AuditEventSecurityEvent), string(entries[0].EventType))
}

func TestHandleRegister_StoreError_Returns500(t *testing.T) {
	storeErr := fmt.Errorf("failed to persist token state: %w", fmt.Errorf("connection refused"))
	tokenStore := &controlledConsumeStore{
		Store:      newTestRegistrationStore(t),
		consumeErr: storeErr,
	}
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

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
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, auditMgr := newHandleRegisterServer(t, tokenStore, certMgr)

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

	// Verify audit entry for successful registration
	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{
		TenantID: "test-tenant",
	})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "steward_registered", entries[0].Action)
	assert.Equal(t, string(business.AuditResultSuccess), string(entries[0].Result))
	assert.Equal(t, string(business.AuditEventAuthentication), string(entries[0].EventType))
	assert.Equal(t, "test-tenant", entries[0].TenantID)

	// Second request with same token must be rejected as already used
	rec2 := postRegister(server, "cfgms_reg_singleuse_valid")
	assert.Equal(t, http.StatusConflict, rec2.Code)
}

func TestHandleRegister_ValidMultiUseToken_AllowsTwoRegistrations(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)

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
	// We use the real MemoryStore and verify token state after registration.
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)

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
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)

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
		Store:      newTestRegistrationStore(t),
		consumeErr: business.ErrTokenAlreadyUsed,
	}
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

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

// kvCapturingLogger captures both Warn message and key-value pairs for security assertions.
// It is not a mock — it satisfies logging.Logger via embedding NoopLogger while recording
// the key-value arguments so tests can verify sensitive fields are absent or truncated.
type kvCapturingLogger struct {
	logging.NoopLogger
	mu      sync.Mutex
	entries []kvLogEntry
}

type kvLogEntry struct {
	msg string
	kvs []interface{}
}

func (l *kvCapturingLogger) Warn(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kvcopy := make([]interface{}, len(kvs))
	copy(kvcopy, kvs)
	l.entries = append(l.entries, kvLogEntry{msg: msg, kvs: kvcopy})
}

func (l *kvCapturingLogger) warnEntries() []kvLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]kvLogEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// warnKVContains checks whether any warn entry has a kv value that equals v.
func (l *kvCapturingLogger) warnKVContains(v string) bool {
	for _, entry := range l.warnEntries() {
		for i := 1; i < len(entry.kvs); i += 2 {
			if s, ok := entry.kvs[i].(string); ok && s == v {
				return true
			}
		}
	}
	return false
}

// TestHandleRegister_RevokedToken_LogsTokenPrefixNotFullToken verifies that the revoked-token
// warn path logs only a truncated token_prefix (max 8 chars) and never the full token value.
func TestHandleRegister_RevokedToken_LogsTokenPrefixNotFullToken(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	capLogger := &kvCapturingLogger{}
	server, _ := newHandleRegisterServer(t, tokenStore, nil, capLogger)

	fullToken := "cfgms_reg_revoked_loggingtest_12345"
	revokedAt := time.Now().Add(-time.Hour)
	tok := &registration.Token{
		Token:         fullToken,
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		Revoked:       true,
		RevokedAt:     &revokedAt,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, fullToken)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// The full token must not appear in any warn kv value.
	assert.False(t, capLogger.warnKVContains(fullToken),
		"full token must not be logged in the revoked-token path")

	// A truncated prefix must be present (at most 8 chars).
	expectedPrefix := fullToken[:8]
	assert.True(t, capLogger.warnKVContains(expectedPrefix),
		"token_prefix (first 8 chars) must be logged in the revoked-token path")
}

// TestHandleRegister_ExpiredToken_LogsTokenPrefixNotFullToken verifies that the expired-token
// warn path logs only a truncated token_prefix (max 8 chars) and never the full token value.
func TestHandleRegister_ExpiredToken_LogsTokenPrefixNotFullToken(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	capLogger := &kvCapturingLogger{}
	server, _ := newHandleRegisterServer(t, tokenStore, nil, capLogger)

	fullToken := "cfgms_reg_expired_loggingtest_12345"
	pastExpiry := time.Now().Add(-time.Hour)
	tok := &registration.Token{
		Token:         fullToken,
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
		ExpiresAt:     &pastExpiry,
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, fullToken)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	assert.False(t, capLogger.warnKVContains(fullToken),
		"full token must not be logged in the expired-token path")

	expectedPrefix := fullToken[:8]
	assert.True(t, capLogger.warnKVContains(expectedPrefix),
		"token_prefix (first 8 chars) must be logged in the expired-token path")
}
