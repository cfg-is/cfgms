// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
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

// newHandleRegisterServer creates a minimal server for handleRegister unit tests.
// Pass a non-nil certMgr only when you need the handler to reach cert generation (200 path).
// Pass a non-nil logger to capture log output in tests; defaults to NoopLogger.
// Returns the server and the audit manager so tests can Flush and query audit entries.
func newHandleRegisterServer(t *testing.T, tokenStore registration.Store, certMgr *cert.Manager, loggers ...logging.Logger) (*Server, *audit.Manager) {
	t.Helper()

	// Isolate secrets storage per test to prevent shared-path contention on Windows CI.
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	var logger logging.Logger
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	} else {
		logger = logging.NewNoopLogger()
	}

	storageManager := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
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
		nil, nil,
		tokenStore,
		"",
		nil,
		auditMgr,
		nil, // No command publisher for basic tests
		nil, // No push store for basic tests
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Close(closeCtx); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	})
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
	// audit.RedactedKeys includes "token", so token_prefix is stored as [REDACTED] — never raw.
	assert.Equal(t, "[REDACTED]", entries[0].Details["token_prefix"],
		"token_prefix in audit detail must be redacted by the audit manager")
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
	// audit.RedactedKeys includes "token", so token_prefix is stored as [REDACTED] — never raw.
	assert.Equal(t, "[REDACTED]", entries[0].Details["token_prefix"],
		"token_prefix in audit detail must be redacted by the audit manager")
}

func TestHandleRegister_PerennialToken_AllowsMultipleRegistrations(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)
	// Explicitly use always-approve hook: this test verifies perennial token behaviour
	// on the approve path, not registration approval policy.
	server.SetApprovalHook(&AlwaysApproveHook{})

	tok := &registration.Token{
		Token:         "cfgms_reg_perennial_valid",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec1 := postRegister(server, "cfgms_reg_perennial_valid")
	assert.Equal(t, http.StatusOK, rec1.Code)

	rec2 := postRegister(server, "cfgms_reg_perennial_valid")
	assert.Equal(t, http.StatusOK, rec2.Code)

	// Both registrations should have distinct steward IDs
	var resp1, resp2 RegistrationResponse
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &resp1))
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &resp2))
	assert.NotEqual(t, resp1.StewardID, resp2.StewardID)
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
	level string
	msg   string
	kvs   []interface{}
}

func (l *kvCapturingLogger) Info(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kvcopy := make([]interface{}, len(kvs))
	copy(kvcopy, kvs)
	l.entries = append(l.entries, kvLogEntry{level: "info", msg: msg, kvs: kvcopy})
}

func (l *kvCapturingLogger) Warn(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kvcopy := make([]interface{}, len(kvs))
	copy(kvcopy, kvs)
	l.entries = append(l.entries, kvLogEntry{level: "warn", msg: msg, kvs: kvcopy})
}

func (l *kvCapturingLogger) allEntries() []kvLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]kvLogEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *kvCapturingLogger) warnEntries() []kvLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []kvLogEntry
	for _, e := range l.entries {
		if e.level == "warn" {
			out = append(out, e)
		}
	}
	return out
}

// allKVContains checks whether any captured log entry (any level) has a kv value that equals v.
func (l *kvCapturingLogger) allKVContains(v string) bool {
	for _, entry := range l.allEntries() {
		for i := 1; i < len(entry.kvs); i += 2 {
			if s, ok := entry.kvs[i].(string); ok && s == v {
				return true
			}
		}
	}
	return false
}

// allKVKeyHasValue checks whether any captured log entry has the given key with the given value.
func (l *kvCapturingLogger) allKVKeyHasValue(key, value string) bool {
	for _, entry := range l.allEntries() {
		for i := 0; i < len(entry.kvs)-1; i += 2 {
			if k, ok := entry.kvs[i].(string); ok && k == key {
				if v, ok2 := entry.kvs[i+1].(string); ok2 && v == value {
					return true
				}
			}
		}
	}
	return false
}

// warnKVContains checks whether any warn-level entry has a kv value that equals v.
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

	// RedactedID produces an 8-char prefix followed by U+2026 ellipsis.
	expectedPrefix := fullToken[:8] + "…"
	assert.True(t, capLogger.warnKVContains(expectedPrefix),
		"token_prefix (first 8 chars + ellipsis) must be logged in the revoked-token path")
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

	// RedactedID produces an 8-char prefix followed by U+2026 ellipsis.
	expectedPrefix := fullToken[:8] + "…"
	assert.True(t, capLogger.warnKVContains(expectedPrefix),
		"token_prefix (first 8 chars + ellipsis) must be logged in the expired-token path")
}

// TestHandleRegister_ValidToken_LogsRedactedPrefixNotFullToken verifies that the success path
// logs only the RedactedID form of the token and never the raw token value.
func TestHandleRegister_ValidToken_LogsRedactedPrefixNotFullToken(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	capLogger := &kvCapturingLogger{}
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr, capLogger)
	// Explicitly use always-approve hook: this test exercises the success (approve) log path.
	server.SetApprovalHook(&AlwaysApproveHook{})

	fullToken := "cfgms_reg_valid_loggingtest_12345"
	tok := &registration.Token{
		Token:         fullToken,
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, fullToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Raw token must not appear in any logged kv value.
	assert.False(t, capLogger.allKVContains(fullToken),
		"raw token must not appear in any log field value on the success path")

	// The token_prefix key specifically must hold the RedactedID form (8 chars + U+2026 ellipsis).
	expectedPrefix := fullToken[:8] + "…"
	assert.True(t, capLogger.allKVKeyHasValue("token_prefix", expectedPrefix),
		"token_prefix key must hold the 8-char+ellipsis redacted form on the success path")
}

// newRegistrationApprovalServer creates a minimal server with a test API key that has
// all three registration approval permissions, wired to a real httptest.Server and a durable
// pending registration store (Issue #1696).
// Returns the server, the httptest.Server (caller must close it), and the pending store.
func newRegistrationApprovalServer(t *testing.T) (*Server, *httptest.Server, business.PendingRegistrationStore) {
	t.Helper()
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	// Wire a real SQLite-backed pending store (Issue #1696).
	pendingStore := pkgtesting.SetupTestStorage(t).GetPendingRegistrationStore()
	require.NotNil(t, pendingStore, "test storage must provide a PendingRegistrationStore")
	server.SetPendingStore(pendingStore)

	// Add a test API key with all registration approval permissions.
	server.apiKeys["reg-approval-key"] = &APIKey{
		ID:          "reg-approval-key-id",
		Key:         "reg-approval-key",
		Permissions: []string{"registration:list-pending", "registration:approve", "registration:deny"},
		TenantID:    "default",
	}

	ts := httptest.NewServer(server.router)
	return server, ts, pendingStore
}

func TestHandleListPendingRegistrations(t *testing.T) {
	_, ts, pendingStore := newRegistrationApprovalServer(t)
	defer ts.Close()

	makeRequest := func(t *testing.T) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/api/v1/registration/pending", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer reg-approval-key")
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("empty store returns empty array", func(t *testing.T) {
		resp := makeRequest(t)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var pending []PendingRegistration
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&pending))
		assert.Empty(t, pending)
	})

	t.Run("returns pending entries from durable store", func(t *testing.T) {
		now := time.Now().UTC()
		entry := &business.PendingRegistrationEntry{
			PendingID:    "pending-list-test-1",
			StewardID:    "steward-list-test-1",
			TenantID:     "tenant-a",
			TokenStr:     "tok-list-1",
			SourceIP:     "192.168.1.1",
			RegisteredAt: now,
			ExpiresAt:    now.Add(5 * 24 * time.Hour),
			Status:       business.PendingRegistrationStatusPending,
		}
		require.NoError(t, pendingStore.AddPending(context.Background(), entry))

		resp := makeRequest(t)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var pending []PendingRegistration
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&pending))
		require.Len(t, pending, 1)
		assert.Equal(t, "pending-list-test-1", pending[0].PendingID)
		assert.Equal(t, "steward-list-test-1", pending[0].StewardID)
		assert.Equal(t, "tenant-a", pending[0].TenantID)
		assert.Equal(t, "192.168.1.1", pending[0].SourceIP)
	})
}

func TestHandleApproveRegistration(t *testing.T) {
	_, ts, pendingStore := newRegistrationApprovalServer(t)
	defer ts.Close()

	makeApprove := func(t *testing.T, pendingID string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), "POST",
			ts.URL+"/api/v1/registration/"+pendingID+"/approve", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer reg-approval-key")
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("happy path - marks pending entry as approved", func(t *testing.T) {
		now := time.Now().UTC()
		entry := &business.PendingRegistrationEntry{
			PendingID:    "pending-approve-1",
			StewardID:    "steward-approve-1",
			TenantID:     "tenant-a",
			TokenStr:     "tok-approve-1",
			SourceIP:     "10.0.0.1",
			RegisteredAt: now,
			ExpiresAt:    now.Add(5 * 24 * time.Hour),
			Status:       business.PendingRegistrationStatusPending,
		}
		require.NoError(t, pendingStore.AddPending(context.Background(), entry))

		resp := makeApprove(t, "pending-approve-1")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Entry status must be updated to "approved" in the durable store.
		got, err := pendingStore.GetPendingByID(context.Background(), "pending-approve-1")
		require.NoError(t, err)
		assert.Equal(t, business.PendingRegistrationStatusApproved, got.Status)
	})

	t.Run("not found returns 404", func(t *testing.T) {
		resp := makeApprove(t, "nonexistent-pending-id")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
	})
}

// quarantineHookForTest is a test-only RegistrationApprovalHook that always quarantines.
type quarantineHookForTest struct{}

func (*quarantineHookForTest) Evaluate(_ context.Context, _ RegistrationInput) (ApprovalDecision, string, error) {
	return DecisionQuarantine, "test quarantine", nil
}

// rejectHookForTest is a test-only RegistrationApprovalHook that always rejects.
type rejectHookForTest struct{}

func (*rejectHookForTest) Evaluate(_ context.Context, _ RegistrationInput) (ApprovalDecision, string, error) {
	return DecisionReject, "test rejection", nil
}

func TestHandleRegister_QuarantineReturns202NoCert(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	// No cert manager: quarantine path must not reach cert generation.
	server, auditMgr := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&quarantineHookForTest{})

	tok := &registration.Token{
		Token:         "cfgms_reg_quarantine_test",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_quarantine_test")

	assert.Equal(t, http.StatusAccepted, rec.Code, "quarantine decision must return HTTP 202")

	var pending RegistrationPendingResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pending))
	assert.NotEmpty(t, pending.PendingID, "pending_id must be non-empty")
	assert.Equal(t, "test-tenant", pending.TenantID)
	assert.Equal(t, "pending", pending.Status)

	// Verify no cert fields in the raw JSON — the struct definition must not carry them.
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.NotContains(t, raw, "client_cert", "quarantine response must not contain client_cert")
	assert.NotContains(t, raw, "client_key", "quarantine response must not contain client_key")
	assert.NotContains(t, raw, "ca_cert", "quarantine response must not contain ca_cert")

	// Verify the quarantine audit event was emitted.
	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "test-tenant"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "registration_quarantined", entries[0].Action)
	assert.Equal(t, string(business.AuditResultSuccess), string(entries[0].Result))
	assert.Equal(t, string(business.AuditEventAuthentication), string(entries[0].EventType))
}

func TestHandleRegister_ApproveReturns200WithCert(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)
	// Explicitly use always-approve hook: this test exercises the 200+cert approve path.
	server.SetApprovalHook(&AlwaysApproveHook{})

	tok := &registration.Token{
		Token:         "cfgms_reg_approve_test",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_approve_test")

	assert.Equal(t, http.StatusOK, rec.Code, "approve decision must return HTTP 200")

	var resp RegistrationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.ClientCert, "client_cert must be present and non-empty on approve")
	assert.NotEmpty(t, resp.ClientKey, "client_key must be present and non-empty on approve")
	assert.NotEmpty(t, resp.CACert, "ca_cert must be present and non-empty on approve")
	assert.NotEmpty(t, resp.StewardID, "steward_id must be present on approve")
	assert.Equal(t, "test-tenant", resp.TenantID)
}

func TestHandleRegister_RejectReturns403(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, auditMgr := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&rejectHookForTest{})

	tok := &registration.Token{
		Token:         "cfgms_reg_reject_test",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_reject_test")

	assert.Equal(t, http.StatusForbidden, rec.Code, "reject decision must return HTTP 403")

	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "test-tenant"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "registration_rejected", entries[0].Action)
	assert.Equal(t, string(business.AuditResultDenied), string(entries[0].Result))
	assert.Equal(t, string(business.AuditEventSecurityEvent), string(entries[0].EventType))
}

func TestHandleDenyRegistration(t *testing.T) {
	_, ts, pendingStore := newRegistrationApprovalServer(t)
	defer ts.Close()

	makeDeny := func(t *testing.T, pendingID, body string) *http.Response {
		t.Helper()
		var reqBody *bytes.Reader
		if body != "" {
			reqBody = bytes.NewReader([]byte(body))
		} else {
			reqBody = bytes.NewReader(nil)
		}
		req, err := http.NewRequestWithContext(context.Background(), "POST",
			ts.URL+"/api/v1/registration/"+pendingID+"/deny", reqBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer reg-approval-key")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		return resp
	}

	addEntry := func(t *testing.T, pendingID, stewardID, tenantID, sourceIP string) {
		t.Helper()
		now := time.Now().UTC()
		require.NoError(t, pendingStore.AddPending(context.Background(), &business.PendingRegistrationEntry{
			PendingID:    pendingID,
			StewardID:    stewardID,
			TenantID:     tenantID,
			TokenStr:     "tok-" + pendingID,
			SourceIP:     sourceIP,
			RegisteredAt: now,
			ExpiresAt:    now.Add(5 * 24 * time.Hour),
			Status:       business.PendingRegistrationStatusPending,
		}))
	}

	t.Run("happy path - marks entry as denied in durable store", func(t *testing.T) {
		addEntry(t, "pending-deny-1", "steward-deny-1", "tenant-b", "10.0.0.2")

		resp := makeDeny(t, "pending-deny-1", "")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		got, err := pendingStore.GetPendingByID(context.Background(), "pending-deny-1")
		require.NoError(t, err)
		assert.Equal(t, business.PendingRegistrationStatusDenied, got.Status)
	})

	t.Run("deny with reason - marks entry as denied", func(t *testing.T) {
		addEntry(t, "pending-deny-2", "steward-deny-2", "tenant-b", "10.0.0.3")

		resp := makeDeny(t, "pending-deny-2", `{"reason":"Unauthorized deployment"}`)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		got, err := pendingStore.GetPendingByID(context.Background(), "pending-deny-2")
		require.NoError(t, err)
		assert.Equal(t, business.PendingRegistrationStatusDenied, got.Status)
	})

	t.Run("not found returns 404", func(t *testing.T) {
		resp := makeDeny(t, "nonexistent-pending-id", "")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// TestExtractSourceIP_XFFIgnoredWhenPeerNotProxy verifies that a spoofed
// X-Forwarded-For header is ignored when the TCP peer is not in the
// TrustedProxies list. The TCP peer address must be used instead (Issue #1695).
func TestExtractSourceIP_XFFIgnoredWhenPeerNotProxy(t *testing.T) {
	const peerAddr = "203.0.113.5"  // "legitimate" attacker IP
	const spoofedXFF = "10.0.0.100" // attacker claims to be this trusted-looking IP
	const trustedProxy = "192.168.1.0/24"

	_, trustedNet, err := net.ParseCIDR(trustedProxy)
	require.NoError(t, err)
	proxies := []net.IPNet{*trustedNet}

	// Request with spoofed XFF from an untrusted peer.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	req.RemoteAddr = peerAddr + ":54321"
	req.Header.Set("X-Forwarded-For", spoofedXFF)

	// With empty trusted proxies: XFF must be ignored.
	got := extractSourceIP(req, nil)
	assert.Equal(t, peerAddr, got,
		"empty trustedProxies: must use TCP peer, not XFF")

	// With trustedProxies configured but peerAddr NOT in the list:
	// XFF must still be ignored.
	got = extractSourceIP(req, proxies)
	assert.Equal(t, peerAddr, got,
		"peer not in trustedProxies: must use TCP peer, not the spoofed XFF")

	// When the peer IS in trustedProxies, XFF should be honored.
	reqFromProxy := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	reqFromProxy.RemoteAddr = "192.168.1.10:54321" // inside 192.168.1.0/24
	reqFromProxy.Header.Set("X-Forwarded-For", spoofedXFF)

	got = extractSourceIP(reqFromProxy, proxies)
	assert.Equal(t, spoofedXFF, got,
		"peer in trustedProxies: XFF must be honored")

	// When the peer IS in trustedProxies but XFF is absent, use peer address.
	reqFromProxyNoXFF := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	reqFromProxyNoXFF.RemoteAddr = "192.168.1.10:54321"

	got = extractSourceIP(reqFromProxyNoXFF, proxies)
	assert.Equal(t, "192.168.1.10", got,
		"peer in trustedProxies but no XFF: must use TCP peer address")

	// IPv6 peer address: net.SplitHostPort must correctly strip brackets and port.
	reqIPv6 := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	reqIPv6.RemoteAddr = "[::1]:54321"
	reqIPv6.Header.Set("X-Forwarded-For", spoofedXFF)

	got = extractSourceIP(reqIPv6, nil)
	assert.Equal(t, "::1", got,
		"IPv6 peer: must return bare IPv6 address without brackets or port")
}

// TestHandleRegistrationStatus_Lifecycle verifies the full poll lifecycle for Issue #1696:
// pending → approve → poll returns cert bundle and marks claimed → second poll returns 410.
func TestHandleRegistrationStatus_Lifecycle(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)

	// Wire a real pending store.
	pendingStore := pkgtesting.SetupTestStorage(t).GetPendingRegistrationStore()
	require.NotNil(t, pendingStore)
	server.SetPendingStore(pendingStore)

	ts := httptest.NewServer(server.router)
	defer ts.Close()

	// Seed a valid registration token.
	const regToken = "cfgms_reg_lifecycle_tok"
	const tenantID = "test-tenant"
	tok := &registration.Token{
		Token:         regToken,
		TenantID:      tenantID,
		ControllerURL: "grpc://controller:7443",
		Group:         "prod",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	// Create a pending entry in the store.
	now := time.Now().UTC()
	entry := &business.PendingRegistrationEntry{
		PendingID:    "pending-lifecycle-1",
		StewardID:    "steward-lifecycle-1",
		TenantID:     tenantID,
		TokenStr:     regToken,
		SourceIP:     "10.0.0.1",
		RegisteredAt: now,
		ExpiresAt:    now.Add(5 * 24 * time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}
	require.NoError(t, pendingStore.AddPending(context.Background(), entry))

	pollStatus := func(t *testing.T, pendingID, bearerToken string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), "GET",
			ts.URL+"/api/v1/registration/status/"+pendingID, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+bearerToken)
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("pending status returns 200 with status=pending", func(t *testing.T) {
		resp := pollStatus(t, "pending-lifecycle-1", regToken)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var body RegistrationStatusResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "pending", body.Status)
		assert.Empty(t, body.ClientCert, "no cert in pending response")
	})

	t.Run("after approve, poll returns cert bundle and status=claimed", func(t *testing.T) {
		// Operator approves.
		require.NoError(t, pendingStore.UpdateStatus(context.Background(),
			"pending-lifecycle-1", business.PendingRegistrationStatusApproved))

		resp := pollStatus(t, "pending-lifecycle-1", regToken)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var body RegistrationStatusResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "claimed", body.Status)
		assert.NotEmpty(t, body.ClientCert, "client_cert must be present after approval")
		assert.NotEmpty(t, body.ClientKey, "client_key must be present after approval")
		assert.NotEmpty(t, body.CACert, "ca_cert must be present after approval")

		// Entry must be persisted as claimed.
		got, err := pendingStore.GetPendingByID(context.Background(), "pending-lifecycle-1")
		require.NoError(t, err)
		assert.Equal(t, business.PendingRegistrationStatusClaimed, got.Status)
	})

	t.Run("second poll after claim returns 410 Gone", func(t *testing.T) {
		resp := pollStatus(t, "pending-lifecycle-1", regToken)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusGone, resp.StatusCode,
			"second poll after claim must return 410 Gone — cert must not be re-issued")
	})
}

// TestHandleRegistrationStatus_TenantIsolation verifies that a token from a different tenant
// cannot observe or interact with another tenant's pending entry.
func TestHandleRegistrationStatus_TenantIsolation(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	pendingStore := pkgtesting.SetupTestStorage(t).GetPendingRegistrationStore()
	require.NotNil(t, pendingStore)
	server.SetPendingStore(pendingStore)

	ts := httptest.NewServer(server.router)
	defer ts.Close()

	// Token for tenant-a.
	tokA := &registration.Token{Token: "tok-tenant-a", TenantID: "tenant-a", ControllerURL: "grpc://c:7443"}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tokA))

	// Token for tenant-b.
	tokB := &registration.Token{Token: "tok-tenant-b", TenantID: "tenant-b", ControllerURL: "grpc://c:7443"}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tokB))

	now := time.Now().UTC()
	require.NoError(t, pendingStore.AddPending(context.Background(), &business.PendingRegistrationEntry{
		PendingID:    "pending-tenant-a-1",
		StewardID:    "steward-a-1",
		TenantID:     "tenant-a",
		TokenStr:     "tok-tenant-a",
		SourceIP:     "10.0.0.1",
		RegisteredAt: now,
		ExpiresAt:    now.Add(5 * 24 * time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}))

	// tenant-b token must not be able to observe tenant-a's pending entry.
	req, err := http.NewRequestWithContext(context.Background(), "GET",
		ts.URL+"/api/v1/registration/status/pending-tenant-a-1", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer tok-tenant-b")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"cross-tenant token must receive 403 Forbidden")
}

// TestHandleRegistrationStatus_NoAuth verifies that the status endpoint requires Bearer auth.
func TestHandleRegistrationStatus_NoAuth(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	pendingStore := pkgtesting.SetupTestStorage(t).GetPendingRegistrationStore()
	require.NotNil(t, pendingStore)
	server.SetPendingStore(pendingStore)

	ts := httptest.NewServer(server.router)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), "GET",
		ts.URL+"/api/v1/registration/status/pending-noauth-1", nil)
	require.NoError(t, err)
	// No Authorization header.
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// newBulkApprovalServer creates a test server with approve + approve-all + approve-by-cidr permissions.
func newBulkApprovalServer(t *testing.T) (*Server, *httptest.Server, business.PendingRegistrationStore) {
	t.Helper()
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	pendingStore := pkgtesting.SetupTestStorage(t).GetPendingRegistrationStore()
	require.NotNil(t, pendingStore, "test storage must provide a PendingRegistrationStore")
	server.SetPendingStore(pendingStore)

	server.apiKeys["bulk-key"] = &APIKey{
		ID:          "bulk-key-id",
		Key:         "bulk-key",
		Permissions: []string{"registration:list-pending", "registration:approve", "registration:deny"},
		TenantID:    "default",
	}

	ts := httptest.NewServer(server.router)
	return server, ts, pendingStore
}

// addPendingEntry is a helper that inserts a pending entry into the store.
func addPendingEntry(t *testing.T, store business.PendingRegistrationStore, pendingID, stewardID, tenantID, sourceIP string) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, store.AddPending(context.Background(), &business.PendingRegistrationEntry{
		PendingID:    pendingID,
		StewardID:    stewardID,
		TenantID:     tenantID,
		TokenStr:     "tok-" + pendingID,
		SourceIP:     sourceIP,
		RegisteredAt: now,
		ExpiresAt:    now.Add(5 * 24 * time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}))
}

// TestApproveByCIDR_FiltersCorrectly verifies that only entries whose source IP is in the
// CIDR are approved; entries outside it remain pending (required test from AC).
func TestApproveByCIDR_FiltersCorrectly(t *testing.T) {
	_, ts, pendingStore := newBulkApprovalServer(t)
	defer ts.Close()

	// Two entries inside the CIDR 192.168.1.0/24, one outside.
	addPendingEntry(t, pendingStore, "pending-cidr-in-1", "steward-in-1", "tenant-a", "192.168.1.10")
	addPendingEntry(t, pendingStore, "pending-cidr-in-2", "steward-in-2", "tenant-a", "192.168.1.200")
	addPendingEntry(t, pendingStore, "pending-cidr-out-1", "steward-out-1", "tenant-a", "10.0.0.5")

	body := `{"cidr":"192.168.1.0/24"}`
	req, err := http.NewRequestWithContext(context.Background(), "POST",
		ts.URL+"/api/v1/registration/approve-by-cidr",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer bulk-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		Approved int `json:"approved"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, 2, result.Approved, "only two entries inside the CIDR should be approved")

	// Verify store state: inside entries approved, outside entry still pending.
	in1, err := pendingStore.GetPendingByID(context.Background(), "pending-cidr-in-1")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusApproved, in1.Status)

	in2, err := pendingStore.GetPendingByID(context.Background(), "pending-cidr-in-2")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusApproved, in2.Status)

	out1, err := pendingStore.GetPendingByID(context.Background(), "pending-cidr-out-1")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusPending, out1.Status,
		"entry outside CIDR must remain pending")
}

// TestApproveAll_Idempotent verifies that calling approve-all twice does not error and
// the second call returns 0 approved (required test from AC).
func TestApproveAll_Idempotent(t *testing.T) {
	_, ts, pendingStore := newBulkApprovalServer(t)
	defer ts.Close()

	addPendingEntry(t, pendingStore, "pending-idem-1", "steward-idem-1", "tenant-a", "10.0.0.1")
	addPendingEntry(t, pendingStore, "pending-idem-2", "steward-idem-2", "tenant-a", "10.0.0.2")

	doApproveAll := func(t *testing.T) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), "POST",
			ts.URL+"/api/v1/registration/approve-all", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer bulk-key")

		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Approved int `json:"approved"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		return result.Approved
	}

	// First call: both pending entries should be approved.
	count1 := doApproveAll(t)
	assert.Equal(t, 2, count1, "first approve-all should approve all pending entries")

	// Second call: no pending entries remain, count must be 0.
	count2 := doApproveAll(t)
	assert.Equal(t, 0, count2, "second approve-all must return 0 (idempotent)")
}

// TestHandleApproveByCIDR_InvalidCIDR verifies that a malformed CIDR returns 400.
func TestHandleApproveByCIDR_InvalidCIDR(t *testing.T) {
	_, ts, _ := newBulkApprovalServer(t)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), "POST",
		ts.URL+"/api/v1/registration/approve-by-cidr",
		strings.NewReader(`{"cidr":"not-a-cidr"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer bulk-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestHandleApproveByCIDR_NoPendingStore verifies 503 when pendingStore is nil.
func TestHandleApproveByCIDR_NoPendingStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	// Do NOT set pendingStore.
	server.apiKeys["bulk-key"] = &APIKey{
		ID:          "bulk-key-id",
		Key:         "bulk-key",
		Permissions: []string{"registration:approve"},
		TenantID:    "default",
	}
	ts := httptest.NewServer(server.router)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), "POST",
		ts.URL+"/api/v1/registration/approve-by-cidr",
		strings.NewReader(`{"cidr":"10.0.0.0/8"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer bulk-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestHandleApproveAll_NoPendingStore verifies 503 when pendingStore is nil.
func TestHandleApproveAll_NoPendingStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	// Do NOT set pendingStore.
	server.apiKeys["bulk-key"] = &APIKey{
		ID:          "bulk-key-id",
		Key:         "bulk-key",
		Permissions: []string{"registration:approve"},
		TenantID:    "default",
	}
	ts := httptest.NewServer(server.router)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), "POST",
		ts.URL+"/api/v1/registration/approve-all", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer bulk-key")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
