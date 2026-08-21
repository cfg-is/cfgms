// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
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

// testValidDeviceID is a 64-character lowercase hex string used across registration handler tests.
const testValidDeviceID = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"

// testValidIdentityKeyPub is a base64-encoded 32-byte Ed25519 public key generated once per
// test binary run. Using a fixed-per-run key keeps tests deterministic within a run while
// avoiding a hardcoded test credential.
var testValidIdentityKeyPub string

func init() {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("test setup: failed to generate Ed25519 key: " + err.Error())
	}
	testValidIdentityKeyPub = base64.StdEncoding.EncodeToString([]byte(pub))
}

// newTestRegistrationStore creates a real SQLite-backed registration.Store for handler tests.
//
// The database is in-memory rather than a file under t.TempDir(). A file-backed
// path takes the provider's full schema-DDL path (~15 CREATE TABLEs plus indexes
// and the back-fill probes) against a WAL journal on real disk, measured at
// 0.4s-2.6s per call under -race; that cost is paid by every test in this file and
// is what pushed this package past the 10-minute per-binary hang detector. The
// in-memory path takes the provider's deserialize fast-path instead (~10ms) and is
// what pkg/testing.SetupTestStorage already uses for every other store in these
// tests. Isolation is unchanged: pkg/storage/providers/sqlite.openDB collapses any
// in-memory request to a *private*, single-connection database owned by this pool,
// so each call still gets its own store with no cross-test sharing. The store is a
// real SQLite store either way — no fake, no mock.
func newTestRegistrationStore(t *testing.T) registration.Store {
	t.Helper()
	store, err := interfaces.CreateRegistrationTokenStoreFromConfig(
		"sqlite",
		map[string]interface{}{"path": ":memory:"},
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
	setTestSecretsEnv(t)

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false
	// Default config binds 0.0.0.0:4433; set ExternalAddress so getTransportAddress() succeeds.
	if cfg.Transport != nil {
		cfg.Transport.ExternalAddress = "localhost"
	}

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
		nil, // No blob store for basic tests
	)
	require.NoError(t, err)
	server.SetPendingStore(storageManager.GetPendingRegistrationStore())
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

// postRegister sends a POST /api/v1/register request with valid device identity fields
// and returns the recorder. Use postRegisterWithBody for custom field combinations.
func postRegister(server *Server, token string) *httptest.ResponseRecorder {
	return postRegisterWithBody(server, RegistrationRequest{
		Token:          token,
		DeviceID:       testValidDeviceID,
		IdentityKeyPub: testValidIdentityKeyPub,
	})
}

// postRegisterWithBody sends a POST /api/v1/register with an arbitrary request body,
// allowing tests to set specific DeviceID, IdentityKeyPub, or KeyProtectionLevel values.
func postRegisterWithBody(server *Server, regReq RegistrationRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(regReq)
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

func TestHandleRegister_RetryDoesNotIssueSecondCertificate(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)
	server.SetApprovalHook(&AlwaysApproveHook{})

	tok := &registration.Token{
		Token:         "cfgms_reg_retry_once",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec1 := postRegister(server, tok.Token)
	require.Equal(t, http.StatusOK, rec1.Code)
	var resp RegistrationResponse
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.ClientCert)

	// A transport retry of the same request is safe: it cannot generate a second
	// private key/certificate after the durable REST claim has committed.
	rec2 := postRegister(server, tok.Token)
	assert.Equal(t, http.StatusConflict, rec2.Code)
	assert.NotContains(t, rec2.Body.String(), "BEGIN CERTIFICATE")
}

func TestHandleRegister_ConcurrentClaimsIssueAtMostOneCertificate(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)
	server.SetApprovalHook(&AlwaysApproveHook{})

	const tokenStr = "cfgms_reg_parallel_certificate"
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token: tokenStr, TenantID: "test-tenant", ControllerURL: "grpc://controller:7443",
	}))

	// One device racing itself. Only one of these may receive a private key —
	// that is the double-issuance the REST claim exists to prevent.
	const contenders = 16
	const deviceID = "00000000000000000000000000000000000000000000000000000000000000ab"
	start := make(chan struct{})
	recorders := make([]*httptest.ResponseRecorder, contenders)
	var wg sync.WaitGroup
	wg.Add(contenders)
	for i := 0; i < contenders; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			recorders[i] = postRegisterWithBody(server, RegistrationRequest{
				Token:          tokenStr,
				DeviceID:       deviceID,
				IdentityKeyPub: testValidIdentityKeyPub,
			})
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	conflicts := 0
	for _, rec := range recorders {
		switch rec.Code {
		case http.StatusOK:
			successes++
			var resp RegistrationResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			assert.NotEmpty(t, resp.ClientCert)
			assert.NotEmpty(t, resp.ClientKey)
		case http.StatusConflict:
			conflicts++
			assert.NotContains(t, rec.Body.String(), "BEGIN CERTIFICATE")
		default:
			t.Errorf("unexpected registration status %d: %s", rec.Code, rec.Body.String())
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, contenders-1, conflicts)
}

// The claim is scoped to the device, not the token: a perennial fleet token
// (Issue #1690) must keep enrolling endpoints after the first one registers.
func TestHandleRegister_PerennialTokenEnrollsManyDevices(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)
	server.SetApprovalHook(&AlwaysApproveHook{})

	const tokenStr = "cfgms_reg_fleet_enrolment"
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token: tokenStr, TenantID: "test-tenant", ControllerURL: "grpc://controller:7443",
	}))

	stewardIDs := make(map[string]bool)
	for i := 0; i < 5; i++ {
		rec := postRegisterWithBody(server, RegistrationRequest{
			Token:          tokenStr,
			DeviceID:       fmt.Sprintf("%064x", i+1),
			IdentityKeyPub: testValidIdentityKeyPub,
		})
		require.Equal(t, http.StatusOK, rec.Code,
			"device %d must enrol on the perennial token: %s", i, rec.Body.String())

		var resp RegistrationResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.ClientCert, "device %d must receive its own certificate", i)
		assert.False(t, stewardIDs[resp.StewardID], "steward IDs must be unique")
		stewardIDs[resp.StewardID] = true
	}

	tok, err := tokenStore.GetToken(context.Background(), tokenStr)
	require.NoError(t, err)
	assert.True(t, tok.IsValid(), "enrolment must not spend the fleet token")
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
		// Use the same TenantID as the API key created in newRegistrationApprovalServer
		// ("default") so the scoped list returns this entry (Issue #2932 tenant scoping).
		entry := &business.PendingRegistrationEntry{
			PendingID:    "pending-list-test-1",
			StewardID:    "steward-list-test-1",
			TenantID:     "default",
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
		assert.Equal(t, "default", pending[0].TenantID)
		assert.Equal(t, "192.168.1.1", pending[0].SourceIP)
	})
}

func TestHandleApproveRegistration(t *testing.T) {
	server, ts, pendingStore := newRegistrationApprovalServer(t)
	defer ts.Close()

	makeApprove := func(t *testing.T, pendingID string) *httptest.ResponseRecorder {
		t.Helper()
		req := makeAdminRequest(t, "POST", "/api/v1/registration/"+pendingID+"/approve", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		return rec
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

		rec := makeApprove(t, "pending-approve-1")

		assert.Equal(t, http.StatusOK, rec.Code)

		// Entry status must be updated to "approved" in the durable store.
		got, err := pendingStore.GetPendingByID(context.Background(), "pending-approve-1")
		require.NoError(t, err)
		assert.Equal(t, business.PendingRegistrationStatusApproved, got.Status)
	})

	t.Run("not found returns 404", func(t *testing.T) {
		rec := makeApprove(t, "nonexistent-pending-id")

		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
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

	// Same-device retry is idempotent: return the same durable pending record
	// rather than creating a second pending registration.
	retry := postRegister(server, "cfgms_reg_quarantine_test")
	require.Equal(t, http.StatusAccepted, retry.Code)
	var retryPending RegistrationPendingResponse
	require.NoError(t, json.Unmarshal(retry.Body.Bytes(), &retryPending))
	assert.Equal(t, pending.PendingID, retryPending.PendingID)
	entries, err := server.pendingStore.ListPending(context.Background(), "test-tenant")
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	// Verify no cert fields in the raw JSON — the struct definition must not carry them.
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.NotContains(t, raw, "client_cert", "quarantine response must not contain client_cert")
	assert.NotContains(t, raw, "client_key", "quarantine response must not contain client_key")
	assert.NotContains(t, raw, "ca_cert", "quarantine response must not contain ca_cert")

	// Verify the quarantine audit event was emitted.
	require.NoError(t, auditMgr.Flush(context.Background()))
	auditEntries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "test-tenant"})
	require.NoError(t, err)
	require.Len(t, auditEntries, 1)
	assert.Equal(t, "registration_quarantined", auditEntries[0].Action)
	assert.Equal(t, string(business.AuditResultSuccess), string(auditEntries[0].Result))
	assert.Equal(t, string(business.AuditEventAuthentication), string(auditEntries[0].EventType))
}

func TestHandleRegister_ConcurrentClaimsCreateAtMostOnePendingRegistration(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&quarantineHookForTest{})

	const tokenStr = "cfgms_reg_parallel_pending"
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token: tokenStr, TenantID: "test-tenant", ControllerURL: "grpc://controller:7443",
	}))

	// One device racing itself must produce exactly one quarantine entry, and the
	// retries that lose the race must be handed back that same entry rather than
	// a second one.
	const contenders = 16
	const deviceID = "00000000000000000000000000000000000000000000000000000000000000cd"
	start := make(chan struct{})
	recorders := make([]*httptest.ResponseRecorder, contenders)
	var wg sync.WaitGroup
	wg.Add(contenders)
	for i := 0; i < contenders; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			recorders[i] = postRegisterWithBody(server, RegistrationRequest{
				Token:          tokenStr,
				DeviceID:       deviceID,
				IdentityKeyPub: testValidIdentityKeyPub,
			})
		}(i)
	}
	close(start)
	wg.Wait()

	pendingIDs := make(map[string]bool)
	for _, rec := range recorders {
		switch rec.Code {
		case http.StatusAccepted:
			assert.NotContains(t, rec.Body.String(), "BEGIN CERTIFICATE")
			var resp RegistrationPendingResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			pendingIDs[resp.PendingID] = true
		case http.StatusConflict:
			// A retry that raced the entry's creation.
		default:
			t.Errorf("unexpected registration status %d: %s", rec.Code, rec.Body.String())
		}
	}
	assert.Len(t, pendingIDs, 1, "the device must only ever be told about one pending entry")

	entries, err := server.pendingStore.ListPending(context.Background(), "test-tenant")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

// Quarantined devices sharing a perennial token must each get their own pending
// entry — never a handle to another device's registration.
func TestHandleRegister_QuarantineKeepsPerennialTokenUsableAndDeviceScoped(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&quarantineHookForTest{})

	const tokenStr = "cfgms_reg_quarantine_fleet"
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token: tokenStr, TenantID: "test-tenant", ControllerURL: "grpc://controller:7443",
	}))

	pendingIDs := make(map[string]string)
	for i := 0; i < 3; i++ {
		deviceID := fmt.Sprintf("%064x", i+1)
		rec := postRegisterWithBody(server, RegistrationRequest{
			Token:          tokenStr,
			DeviceID:       deviceID,
			IdentityKeyPub: testValidIdentityKeyPub,
		})
		require.Equal(t, http.StatusAccepted, rec.Code,
			"device %d must be quarantined, not refused: %s", i, rec.Body.String())
		var resp RegistrationPendingResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.NotEmpty(t, resp.PendingID)
		pendingIDs[deviceID] = resp.PendingID
	}
	assert.Len(t, pendingIDs, 3, "each device must receive a distinct pending_id")

	// A device retrying gets its own entry back, not one of its peers'.
	for deviceID, want := range pendingIDs {
		rec := postRegisterWithBody(server, RegistrationRequest{
			Token:          tokenStr,
			DeviceID:       deviceID,
			IdentityKeyPub: testValidIdentityKeyPub,
		})
		require.Equal(t, http.StatusAccepted, rec.Code, "retry body: %s", rec.Body.String())
		var resp RegistrationPendingResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, want, resp.PendingID, "device %s must recover its own pending entry", deviceID)
	}

	entries, err := server.pendingStore.ListPending(context.Background(), "test-tenant")
	require.NoError(t, err)
	assert.Len(t, entries, 3)
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
		// "default" matches the API key's TenantID (Issue #2932: deny enforces caller subtree).
		addEntry(t, "pending-deny-1", "steward-deny-1", "default", "10.0.0.2")

		resp := makeDeny(t, "pending-deny-1", "")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		got, err := pendingStore.GetPendingByID(context.Background(), "pending-deny-1")
		require.NoError(t, err)
		assert.Equal(t, business.PendingRegistrationStatusDenied, got.Status)
	})

	t.Run("deny with reason - marks entry as denied", func(t *testing.T) {
		addEntry(t, "pending-deny-2", "steward-deny-2", "default", "10.0.0.3")

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

	// Standard proxies append the observed upstream address. Walk from the
	// trusted edge toward the client so an attacker-controlled leftmost value
	// cannot replace the address actually observed by the proxy.
	reqFromProxy.Header.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.5")
	got = extractSourceIP(reqFromProxy, proxies)
	assert.Equal(t, peerAddr, got,
		"trusted proxy chain: first untrusted hop from the right is the client")

	reqFromProxy.Header.Del("X-Forwarded-For")
	reqFromProxy.Header.Add("X-Forwarded-For", "198.51.100.99")
	reqFromProxy.Header.Add("X-Forwarded-For", "203.0.113.5")
	got = extractSourceIP(reqFromProxy, proxies)
	assert.Equal(t, peerAddr, got,
		"multiple X-Forwarded-For fields must form one right-to-left chain")

	reqFromProxy.Header.Set("X-Forwarded-For", "198.51.100.99, not-an-ip")
	got = extractSourceIP(reqFromProxy, proxies)
	assert.Equal(t, "192.168.1.10", got,
		"malformed trusted-proxy chain must fall back to the TCP peer")

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
	server, ts, pendingStore := newBulkApprovalServer(t)
	defer ts.Close()

	// Two entries inside the CIDR 192.168.1.0/24, one outside.
	addPendingEntry(t, pendingStore, "pending-cidr-in-1", "steward-in-1", "tenant-a", "192.168.1.10")
	addPendingEntry(t, pendingStore, "pending-cidr-in-2", "steward-in-2", "tenant-a", "192.168.1.200")
	addPendingEntry(t, pendingStore, "pending-cidr-out-1", "steward-out-1", "tenant-a", "10.0.0.5")

	req := makeAdminRequest(t, "POST", "/api/v1/registration/approve-by-cidr",
		strings.NewReader(`{"cidr":"192.168.1.0/24"}`))
	req.Header.Set("Content-Type", "application/json")
	// registration:approve-by-cidr requires RequireUserPresence (Issue #2969).
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, "test-admin"))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var result struct {
		Approved int `json:"approved"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&result))
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
	server, ts, pendingStore := newBulkApprovalServer(t)
	defer ts.Close()

	addPendingEntry(t, pendingStore, "pending-idem-1", "steward-idem-1", "tenant-a", "10.0.0.1")
	addPendingEntry(t, pendingStore, "pending-idem-2", "steward-idem-2", "tenant-a", "10.0.0.2")

	doApproveAll := func(t *testing.T) int {
		t.Helper()
		req := makeAdminRequest(t, "POST", "/api/v1/registration/approve-all", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var result struct {
			Approved int `json:"approved"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&result))
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
	server, ts, _ := newBulkApprovalServer(t)
	defer ts.Close()

	req := makeAdminRequest(t, "POST", "/api/v1/registration/approve-by-cidr",
		strings.NewReader(`{"cidr":"not-a-cidr"}`))
	req.Header.Set("Content-Type", "application/json")
	// Presence token required even for error paths — gate is enforced before handler logic.
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, "test-admin"))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleApproveByCIDR_NoPendingStore verifies 503 when pendingStore is nil.
func TestHandleApproveByCIDR_NoPendingStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetPendingStore(nil)

	req := makeAdminRequest(t, "POST", "/api/v1/registration/approve-by-cidr",
		strings.NewReader(`{"cidr":"10.0.0.0/8"}`))
	req.Header.Set("Content-Type", "application/json")
	// Presence token required — gate fires before handler's pendingStore nil check.
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, "test-admin"))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleApproveByCIDR_RequiresPresence verifies that calling approve-by-cidr without
// a presence token returns 401 with presence="required" in WWW-Authenticate.
func TestHandleApproveByCIDR_RequiresPresence(t *testing.T) {
	server, ts, _ := newBulkApprovalServer(t)
	defer ts.Close()

	// No presence token attached — should be rejected before reaching the handler.
	req := makeAdminRequest(t, "POST", "/api/v1/registration/approve-by-cidr",
		strings.NewReader(`{"cidr":"10.0.0.0/8"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`,
		"approve-by-cidr must require a user-presence proof (Issue #2969)")
}

// TestHandleApproveByCIDRPreview_HappyPath verifies that the preview endpoint returns
// the count, IDs, and source IPs of matching pending entries without mutating state.
func TestHandleApproveByCIDRPreview_HappyPath(t *testing.T) {
	server, ts, pendingStore := newBulkApprovalServer(t)
	defer ts.Close()

	addPendingEntry(t, pendingStore, "prev-in-1", "stwd-in-1", "tenant-a", "192.168.1.10")
	addPendingEntry(t, pendingStore, "prev-in-2", "stwd-in-2", "tenant-a", "192.168.1.20")
	addPendingEntry(t, pendingStore, "prev-out-1", "stwd-out-1", "tenant-a", "10.0.0.5")

	req := makeAdminRequest(t, "GET", "/api/v1/registration/approve-by-cidr/preview?cidr=192.168.1.0/24", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var result approveByCIDRPreviewResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&result))
	assert.Equal(t, 2, result.Count)
	assert.ElementsMatch(t, []string{"prev-in-1", "prev-in-2"}, result.PendingIDs)
	assert.ElementsMatch(t, []string{"192.168.1.10", "192.168.1.20"}, result.SourceIPs)

	// Verify the store is unmodified — preview must not mutate state.
	for _, id := range []string{"prev-in-1", "prev-in-2", "prev-out-1"} {
		e, err := pendingStore.GetPendingByID(context.Background(), id)
		require.NoError(t, err)
		assert.Equal(t, business.PendingRegistrationStatusPending, e.Status,
			"preview must not mutate entry %q", id)
	}
}

// TestHandleApproveByCIDRPreview_EmptyResult verifies that the preview returns an empty
// JSON array (not null) when no entries match.
func TestHandleApproveByCIDRPreview_EmptyResult(t *testing.T) {
	server, ts, _ := newBulkApprovalServer(t)
	defer ts.Close()

	req := makeAdminRequest(t, "GET", "/api/v1/registration/approve-by-cidr/preview?cidr=10.0.0.0/8", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var result approveByCIDRPreviewResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&result))
	assert.Equal(t, 0, result.Count)
	assert.NotNil(t, result.PendingIDs, "pending_ids must be an empty array, not null")
	assert.NotNil(t, result.SourceIPs, "source_ips must be an empty array, not null")
}

// TestHandleApproveByCIDRPreview_InvalidCIDR verifies that a malformed CIDR returns 400.
func TestHandleApproveByCIDRPreview_InvalidCIDR(t *testing.T) {
	server, ts, _ := newBulkApprovalServer(t)
	defer ts.Close()

	req := makeAdminRequest(t, "GET", "/api/v1/registration/approve-by-cidr/preview?cidr=not-a-cidr", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleApproveByCIDRPreview_MissingCIDR verifies that a missing cidr parameter returns 400.
func TestHandleApproveByCIDRPreview_MissingCIDR(t *testing.T) {
	server, ts, _ := newBulkApprovalServer(t)
	defer ts.Close()

	req := makeAdminRequest(t, "GET", "/api/v1/registration/approve-by-cidr/preview", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleApproveByCIDRPreview_NoPendingStore verifies 503 when pendingStore is nil.
func TestHandleApproveByCIDRPreview_NoPendingStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetPendingStore(nil)

	req := makeAdminRequest(t, "GET", "/api/v1/registration/approve-by-cidr/preview?cidr=10.0.0.0/8", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleApproveAll_NoPendingStore verifies 503 when pendingStore is nil.
func TestHandleApproveAll_NoPendingStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetPendingStore(nil)
	// Do NOT set pendingStore.

	req := makeAdminRequest(t, "POST", "/api/v1/registration/approve-all", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestGetTransportAddress_ExternalAddressConfig verifies that transport.external_address
// is returned as the steward-facing address when ListenAddr binds 0.0.0.0.
func TestGetTransportAddress_ExternalAddressConfig(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	srv, _ := newHandleRegisterServer(t, tokenStore, nil)
	srv.cfg.Transport = &config.TransportConfig{
		ListenAddr:      "0.0.0.0:4433",
		ExternalAddress: "controller.example.com",
	}

	addr, err := srv.getTransportAddress()
	require.NoError(t, err)
	assert.Equal(t, "controller.example.com:4433", addr)
}

// TestGetTransportAddress_EnvVarFallback verifies that CFGMS_EXTERNAL_HOSTNAME is used
// when no transport.external_address is configured.
func TestGetTransportAddress_EnvVarFallback(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "env-controller.example.com")
	tokenStore := newTestRegistrationStore(t)
	srv, _ := newHandleRegisterServer(t, tokenStore, nil)
	srv.cfg.Transport = &config.TransportConfig{ListenAddr: "0.0.0.0:9433"}

	addr, err := srv.getTransportAddress()
	require.NoError(t, err)
	assert.Equal(t, "env-controller.example.com:9433", addr)
}

// TestGetTransportAddress_ConfigPrecedenceOverEnvVar verifies that transport.external_address
// takes precedence over CFGMS_EXTERNAL_HOSTNAME when both are set.
func TestGetTransportAddress_ConfigPrecedenceOverEnvVar(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "env-controller.example.com")
	tokenStore := newTestRegistrationStore(t)
	srv, _ := newHandleRegisterServer(t, tokenStore, nil)
	srv.cfg.Transport = &config.TransportConfig{
		ListenAddr:      "0.0.0.0:4433",
		ExternalAddress: "config-controller.example.com",
	}

	addr, err := srv.getTransportAddress()
	require.NoError(t, err)
	assert.Equal(t, "config-controller.example.com:4433", addr)
}

// TestGetTransportAddress_NonBindAll verifies that a specific bind address is
// returned unchanged without requiring an external address.
func TestGetTransportAddress_NonBindAll(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	srv, _ := newHandleRegisterServer(t, tokenStore, nil)
	srv.cfg.Transport = &config.TransportConfig{ListenAddr: "192.168.1.10:4433"}

	addr, err := srv.getTransportAddress()
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.10:4433", addr)
}

// TestGetTransportAddress_BindAll_NoExternalAddress_ReturnsError verifies that
// getTransportAddress() returns an informative error when ListenAddr is 0.0.0.0
// and no external address is available.
func TestGetTransportAddress_BindAll_NoExternalAddress_ReturnsError(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	tokenStore := newTestRegistrationStore(t)
	srv, _ := newHandleRegisterServer(t, tokenStore, nil)
	srv.cfg.Transport = &config.TransportConfig{ListenAddr: "0.0.0.0:4433"}

	_, err := srv.getTransportAddress()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transport.external_address")
	assert.Contains(t, err.Error(), "CFGMS_EXTERNAL_HOSTNAME")
}

// TestHandleRegister_QuarantinePath_TransportAddressError verifies that the quarantine
// branch returns HTTP 500 when getTransportAddress() fails (misconfigured 0.0.0.0 bind
// with no external address). This can only occur if startup validation is bypassed.
func TestHandleRegister_QuarantinePath_TransportAddressError(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	tokenStore := newTestRegistrationStore(t)
	// newHandleRegisterServer sets ExternalAddress="localhost" so the server builds.
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	// Now simulate a misconfigured transport address (clears the ExternalAddress).
	server.cfg.Transport = &config.TransportConfig{ListenAddr: "0.0.0.0:4433"}
	server.SetApprovalHook(&quarantineHookForTest{})

	tok := &registration.Token{
		Token:         "cfgms_reg_quarantine_transport_err",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_quarantine_transport_err")

	assert.Equal(t, http.StatusInternalServerError, rec.Code,
		"quarantine path must return HTTP 500 when transport address is misconfigured")
	assert.Contains(t, rec.Body.String(), "transport address not configured")
}

// TestHandleRegister_ApprovePath_TransportAddressError verifies that the approve
// branch returns HTTP 500 when getTransportAddress() fails (misconfigured 0.0.0.0 bind
// with no external address). This can only occur if startup validation is bypassed.
func TestHandleRegister_ApprovePath_TransportAddressError(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	// newHandleRegisterServer sets ExternalAddress="localhost" so the server builds.
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)
	// Now simulate a misconfigured transport address (clears the ExternalAddress).
	server.cfg.Transport = &config.TransportConfig{ListenAddr: "0.0.0.0:4433"}
	server.SetApprovalHook(&AlwaysApproveHook{})

	tok := &registration.Token{
		Token:         "cfgms_reg_approve_transport_err",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_approve_transport_err")

	assert.Equal(t, http.StatusInternalServerError, rec.Code,
		"approve path must return HTTP 500 when transport address is misconfigured")
	assert.Contains(t, rec.Body.String(), "transport address not configured")

	// The failure occurred before the atomic issuance boundary, so correcting
	// the prerequisite and retrying the same request must still succeed.
	server.cfg.Transport.ExternalAddress = "localhost"
	retry := postRegister(server, "cfgms_reg_approve_transport_err")
	assert.Equal(t, http.StatusOK, retry.Code)
	assert.Contains(t, retry.Body.String(), "BEGIN CERTIFICATE")
}

// newHandleRegisterServerWithStewardStore creates a server wired with a real
// SQLite-backed StewardStore (from the OSS composite storage manager) for device
// identity persistence tests. No fakes — CFGMS mandates real component testing.
func newHandleRegisterServerWithStewardStore(t *testing.T, tokenStore registration.Store, certMgr *cert.Manager) (*Server, business.StewardStore) {
	t.Helper()
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)
	ss := pkgtesting.SetupTestStorage(t).GetStewardStore()
	require.NotNil(t, ss, "test storage must provide a StewardStore")
	server.SetStewardStore(ss)
	return server, ss
}

// TestHandleRegister_PersistsDeviceIdentity verifies that after a successful registration
// the controller has stored the DeviceID and IdentityKeyPub on the StewardRecord.
func TestHandleRegister_PersistsDeviceIdentity(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, stewardSt := newHandleRegisterServerWithStewardStore(t, tokenStore, certMgr)
	server.SetApprovalHook(&AlwaysApproveHook{})

	tok := &registration.Token{
		Token:         "cfgms_reg_persist_identity",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	deviceID := "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
	identityKeyPub := base64.StdEncoding.EncodeToString([]byte(pub))

	rec := postRegisterWithBody(server, RegistrationRequest{
		Token:              "cfgms_reg_persist_identity",
		DeviceID:           deviceID,
		IdentityKeyPub:     identityKeyPub,
		KeyProtectionLevel: "tpm",
	})
	require.Equal(t, http.StatusOK, rec.Code)

	var resp RegistrationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.StewardID)

	stored, lookupErr := stewardSt.GetSteward(context.Background(), resp.StewardID)
	require.NoError(t, lookupErr, "StewardRecord must be present in the store after registration")
	assert.Equal(t, deviceID, stored.DeviceID, "stored DeviceID must match the sent value")
	assert.Equal(t, []byte(pub), stored.IdentityKeyPub, "stored IdentityKeyPub must match the sent public key bytes")
	assert.Equal(t, "tpm", stored.KeyProtectionLevel)
	assert.Equal(t, "test-tenant", stored.TenantID)
}

// TestHandleRegister_MissingDeviceID_400 verifies that a registration request without
// a DeviceID returns HTTP 400.
func TestHandleRegister_MissingDeviceID_400(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	tok := &registration.Token{
		Token:         "cfgms_reg_no_device_id",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegisterWithBody(server, RegistrationRequest{
		Token:          "cfgms_reg_no_device_id",
		IdentityKeyPub: testValidIdentityKeyPub,
		// DeviceID intentionally omitted
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "device_id")
}

// TestHandleRegister_MalformedDeviceID_400 verifies that a registration request with
// a DeviceID that is not 64 lowercase hex characters returns HTTP 400.
func TestHandleRegister_MalformedDeviceID_400(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	tok := &registration.Token{
		Token:         "cfgms_reg_bad_device_id",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	for _, badID := range []string{
		"tooshort",
		strings.Repeat("a", 63), // 63 chars
		strings.Repeat("A", 64), // uppercase hex — invalid
		strings.Repeat("g", 64), // non-hex character
		strings.Repeat("a", 65), // 65 chars
	} {
		rec := postRegisterWithBody(server, RegistrationRequest{
			Token:          "cfgms_reg_bad_device_id",
			DeviceID:       badID,
			IdentityKeyPub: testValidIdentityKeyPub,
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code, "DeviceID %q must be rejected with 400", badID)
	}
}

// TestHandleRegister_MissingIdentityKeyPub_400 verifies that a registration request
// without an IdentityKeyPub returns HTTP 400.
func TestHandleRegister_MissingIdentityKeyPub_400(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	tok := &registration.Token{
		Token:         "cfgms_reg_no_key_pub",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegisterWithBody(server, RegistrationRequest{
		Token:    "cfgms_reg_no_key_pub",
		DeviceID: testValidDeviceID,
		// IdentityKeyPub intentionally omitted
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "identity_key_pub")
}

// TestHandleRegister_InvalidIdentityKeyPub_400 verifies that a registration request
// with an IdentityKeyPub that does not decode to 32 bytes returns HTTP 400.
func TestHandleRegister_InvalidIdentityKeyPub_400(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	tok := &registration.Token{
		Token:         "cfgms_reg_bad_key_pub",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	for _, badPub := range []string{
		"notbase64!!!",
		base64.StdEncoding.EncodeToString([]byte("tooshort")), // <32 bytes
		base64.StdEncoding.EncodeToString(make([]byte, 33)),   // 33 bytes
		base64.StdEncoding.EncodeToString(make([]byte, 64)),   // 64 bytes (wrong size)
	} {
		rec := postRegisterWithBody(server, RegistrationRequest{
			Token:          "cfgms_reg_bad_key_pub",
			DeviceID:       testValidDeviceID,
			IdentityKeyPub: badPub,
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code, "IdentityKeyPub %q must be rejected with 400", badPub)
	}
}

// TestHandleRegister_DuplicateDeviceIDWithinTenant_409 verifies that registering the
// same DeviceID twice in the same tenant is rejected with HTTP 409.
func TestHandleRegister_DuplicateDeviceIDWithinTenant_409(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServerWithStewardStore(t, tokenStore, certMgr)
	server.SetApprovalHook(&AlwaysApproveHook{})

	tok := &registration.Token{
		Token:         "cfgms_reg_dup_device_id",
		TenantID:      "tenant-dup",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	// First registration with this DeviceID — must succeed.
	rec1 := postRegisterWithBody(server, RegistrationRequest{
		Token:          "cfgms_reg_dup_device_id",
		DeviceID:       testValidDeviceID,
		IdentityKeyPub: testValidIdentityKeyPub,
	})
	assert.Equal(t, http.StatusOK, rec1.Code, "first registration must succeed")

	// Second registration with the same DeviceID in the same tenant — must be rejected.
	rec2 := postRegisterWithBody(server, RegistrationRequest{
		Token:          "cfgms_reg_dup_device_id",
		DeviceID:       testValidDeviceID,
		IdentityKeyPub: testValidIdentityKeyPub,
	})
	assert.Equal(t, http.StatusConflict, rec2.Code,
		"duplicate DeviceID within the same tenant must return HTTP 409")
}

// TestHandleRegister_DuplicateDeviceIDCrossTenant_200 verifies that the same DeviceID
// may be used in different tenants without conflict (tenant namespaces are independent).
func TestHandleRegister_DuplicateDeviceIDCrossTenant_200(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServerWithStewardStore(t, tokenStore, certMgr)
	server.SetApprovalHook(&AlwaysApproveHook{})

	tokA := &registration.Token{
		Token:         "cfgms_reg_cross_tenant_a",
		TenantID:      "tenant-a",
		ControllerURL: "grpc://controller:7443",
	}
	tokB := &registration.Token{
		Token:         "cfgms_reg_cross_tenant_b",
		TenantID:      "tenant-b",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tokA))
	require.NoError(t, tokenStore.SaveToken(context.Background(), tokB))

	deviceID := "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyPub := base64.StdEncoding.EncodeToString([]byte(pub))

	// Register under tenant-a — must succeed.
	rec1 := postRegisterWithBody(server, RegistrationRequest{
		Token:          "cfgms_reg_cross_tenant_a",
		DeviceID:       deviceID,
		IdentityKeyPub: keyPub,
	})
	assert.Equal(t, http.StatusOK, rec1.Code, "registration under tenant-a must succeed")

	// Register the same DeviceID under tenant-b — must also succeed (different namespace).
	rec2 := postRegisterWithBody(server, RegistrationRequest{
		Token:          "cfgms_reg_cross_tenant_b",
		DeviceID:       deviceID,
		IdentityKeyPub: keyPub,
	})
	assert.Equal(t, http.StatusOK, rec2.Code,
		"same DeviceID under a different tenant must be accepted (namespaces are independent)")
}

// TestProvisionedVMRegistration_IPTrustGate covers ADR-010 §3 (Issue #2082):
// a steward provisioned by the HyperV module registers via the standard
// POST /api/v1/register endpoint; the IP-trust evaluator (#1694) is the
// admission gate — the same gate used for all steward registrations. No separate
// provisioning-registration path exists that bypasses the evaluator.
//
// Both admission paths are exercised with real components (real IPTrustStore,
// real IPTrustApprovalHook, real PendingRegistrationStore, real cert.Manager)
// to verify end-to-end that the gate is not bypassed for provisioned VMs.
func TestProvisionedVMRegistration_IPTrustGate(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)

	// Wire real components from the OSS composite storage manager.
	storageManager := pkgtesting.SetupTestStorage(t)
	ipTrustStore := storageManager.GetIPTrustStore()
	require.NotNil(t, ipTrustStore, "test storage must provide an IPTrustStore")
	pendingStore := storageManager.GetPendingRegistrationStore()
	require.NotNil(t, pendingStore, "test storage must provide a PendingRegistrationStore")

	// Wire the real IPTrustApprovalHook and durable pending store.
	server.SetApprovalHook(NewIPTrustApprovalHook(ipTrustStore, logging.NewNoopLogger()))
	server.SetPendingStore(pendingStore)

	const tenantID = "hv-tenant"
	const hvTrustedIP = "10.10.0.50"     // HV host's tenant-network IP, added to trust store below
	const hvUntrustedIP = "198.51.100.1" // not in any trusted range

	// Seed a registration token for the HV tenant (mirrors the join token the
	// steward bakes into its answer file per ADR-010 §2).
	tok := &registration.Token{
		Token:         "cfgms_reg_hv_iptest",
		TenantID:      tenantID,
		ControllerURL: "grpc://controller:7443",
		Group:         "hv-vms",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))
	trustedTok := &registration.Token{
		Token:         "cfgms_reg_hv_iptest_trusted",
		TenantID:      tenantID,
		ControllerURL: "grpc://controller:7443",
		Group:         "hv-vms",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), trustedTok))

	// sendFrom posts a registration request with the given source IP and returns
	// the raw response body bytes alongside the recorder so both decoded fields
	// and raw content (e.g. cert PEM checks) can be verified.
	sendFrom := func(t *testing.T, sourceIP, tokenStr string) (*httptest.ResponseRecorder, []byte) {
		t.Helper()
		body, err := json.Marshal(RegistrationRequest{
			Token:          tokenStr,
			DeviceID:       testValidDeviceID,
			IdentityKeyPub: testValidIdentityKeyPub,
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = sourceIP + ":54321"
		rec := httptest.NewRecorder()
		server.handleRegister(rec, req)
		return rec, rec.Body.Bytes()
	}

	t.Run("untrusted_network_requires_manual_approval", func(t *testing.T) {
		// HV host IP is NOT in the trust store → evaluator returns DecisionQuarantine
		// → handler returns HTTP 202 Accepted with a pending_id for operator review.
		rec, rawBody := sendFrom(t, hvUntrustedIP, tok.Token)
		require.Equal(t, http.StatusAccepted, rec.Code,
			"provisioned VM registering from an untrusted network must be quarantined (202 Accepted)")

		var resp RegistrationPendingResponse
		require.NoError(t, json.NewDecoder(bytes.NewReader(rawBody)).Decode(&resp))
		assert.Equal(t, "pending", resp.Status,
			"quarantined registration must have status 'pending'")
		assert.NotEmpty(t, resp.PendingID,
			"quarantined response must include a pending_id for operator approval")
		assert.Equal(t, tenantID, resp.TenantID,
			"quarantined response must reflect the registering tenant")

		// No cert-bundle PEM must appear — issuance is gated on operator approval (Issue #1693).
		assert.NotContains(t, string(rawBody), "-----BEGIN",
			"cert PEM must not appear in quarantine response: issuance gated on manual approval")

		// Pending entry must be persisted in durable store for operator action.
		entry, err := pendingStore.GetPendingByID(context.Background(), resp.PendingID)
		require.NoError(t, err, "pending entry must be durably persisted for operator review")
		assert.Equal(t, tenantID, entry.TenantID)
		assert.Equal(t, business.PendingRegistrationStatusPending, entry.Status,
			"pending entry must be in 'pending' state awaiting operator approval")
		assert.Equal(t, hvUntrustedIP, entry.SourceIP,
			"source IP must be recorded in the pending entry for operator review")
	})

	// Operator action: seed the HV host's network as trusted
	// (mirrors 'cfg registration ip-trust add' or the 30-min liveness promotion).
	require.NoError(t,
		ipTrustStore.AddTrustedRange(context.Background(), tenantID, hvTrustedIP+"/32", false),
		"seeding trusted IP range for HV tenant must succeed")

	t.Run("trusted_network_auto_admits", func(t *testing.T) {
		// HV host IP IS in the trust store → evaluator returns DecisionApprove
		// → handler returns HTTP 200 with a full mTLS cert bundle.
		rec, rawBody := sendFrom(t, hvTrustedIP, trustedTok.Token)
		require.Equal(t, http.StatusOK, rec.Code,
			"provisioned VM registering from the HV host's trusted network must be auto-admitted (200 OK)")

		var resp RegistrationResponse
		require.NoError(t, json.NewDecoder(bytes.NewReader(rawBody)).Decode(&resp))
		assert.NotEmpty(t, resp.ClientCert, "auto-admitted registration must include a client cert")
		assert.NotEmpty(t, resp.ClientKey, "auto-admitted registration must include a client key")
		assert.NotEmpty(t, resp.CACert, "auto-admitted registration must include the CA cert")
		assert.Equal(t, tenantID, resp.TenantID,
			"auto-admission response must reflect the registering tenant")
		assert.Equal(t, "hv-vms", resp.Group,
			"auto-admission response must include the token's fleet group")
	})
}

// TestHandleRegister_HostnameSeededBeforeDNASync verifies that a hostname sent at
// registration is visible in GetStewardInfo immediately after the registration
// completes — before any SyncDNA call (Issue #2640, AC #1).
func TestHandleRegister_HostnameSeededBeforeDNASync(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)
	server.SetApprovalHook(&AlwaysApproveHook{})

	tok := &registration.Token{
		Token:         "cfgms_reg_hostname_seed",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	deviceID := "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"

	rec := postRegisterWithBody(server, RegistrationRequest{
		Token:          "cfgms_reg_hostname_seed",
		DeviceID:       deviceID,
		IdentityKeyPub: base64.StdEncoding.EncodeToString([]byte(pub)),
		Hostname:       "worker-node-42",
		OS:             "linux",
	})
	require.Equal(t, http.StatusOK, rec.Code, "registration with hostname must succeed")

	var resp RegistrationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.StewardID)

	// No SyncDNA has been called — hostname must be visible solely from registration.
	info, ok := server.controllerService.GetStewardInfo(resp.StewardID)
	require.True(t, ok, "registered steward must be present in controller service")
	require.NotNil(t, info.DNA)
	assert.Equal(t, "worker-node-42", info.DNA.Attributes["hostname"],
		"hostname must be visible in DNA immediately after registration, before any SyncDNA")
	assert.Equal(t, "linux", info.DNA.Attributes["os"],
		"os must be visible in DNA immediately after registration, before any SyncDNA")
}

// TestHandleRegister_EmptyHostnameStillRegisters verifies that a registration with no
// hostname field still succeeds (hostname is optional — Issue #2640, AC #2).
func TestHandleRegister_EmptyHostnameStillRegisters(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, _ := newHandleRegisterServer(t, tokenStore, certMgr)
	server.SetApprovalHook(&AlwaysApproveHook{})

	tok := &registration.Token{
		Token:         "cfgms_reg_no_hostname",
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	rec := postRegister(server, "cfgms_reg_no_hostname")
	assert.Equal(t, http.StatusOK, rec.Code, "registration without hostname must still succeed")

	var resp RegistrationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.StewardID)

	info, ok := server.controllerService.GetStewardInfo(resp.StewardID)
	require.True(t, ok)
	require.NotNil(t, info.DNA)
	assert.Empty(t, info.DNA.Attributes["hostname"],
		"no hostname attribute should be set when none was sent at registration")
}

// TestHandleListPendingRegistrations_ClusterMode_Returns200Not503 is the REQUIRED TEST for
// Issue #3401: against a cluster-mode controller — one whose pending-registration store is
// the PostgreSQL store the database provider returns — GET /api/v1/registration/pending must
// return 200 rather than the 503 "registration store unavailable" the nil store produced
// before DatabaseProvider.CreatePendingRegistrationStore was wired.
//
// The first subtest is the negative control: it reproduces the pre-fix 503 by leaving the
// store nil, so a regression that unwires the provider fails here rather than passing
// silently. The remaining subtests run only when the test database is reachable
// (make test-integration-db); they are skipped, not failed, when it is not.
func TestHandleListPendingRegistrations_ClusterMode_Returns200Not503(t *testing.T) {
	server, ts, _ := newRegistrationApprovalServer(t)
	defer ts.Close()

	listPending := func(t *testing.T) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/api/v1/registration/pending", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer reg-approval-key")
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("nil pending store reproduces the pre-fix 503", func(t *testing.T) {
		server.SetPendingStore(nil)
		resp := listPending(t)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
			"a controller with no pending-registration store must return 503 — this is the failure Issue #3401 removes")
	})

	pendingStore := tryNewDatabasePendingRegistrationStore(t)
	if pendingStore == nil {
		t.Skip("PostgreSQL test database not reachable — run `make test-integration-setup && make test-integration-db` to exercise the cluster-mode path")
	}
	server.SetPendingStore(pendingStore)

	t.Run("postgres-backed store returns 200", func(t *testing.T) {
		resp := listPending(t)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode,
			"a cluster-mode controller backed by the database provider must return 200, not 503")

		var pending []PendingRegistration
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&pending))
	})

	t.Run("postgres-backed store returns entries end to end", func(t *testing.T) {
		now := time.Now().UTC()
		// "default" matches the API key's TenantID in newRegistrationApprovalServer, so the
		// tenant-scoped list returns this entry. The PendingID is unique per run because the
		// Postgres table is shared across tests and retains rows between them.
		pendingID := fmt.Sprintf("pending-cluster-%d", now.UnixNano())
		entry := &business.PendingRegistrationEntry{
			PendingID:    pendingID,
			StewardID:    "steward-" + pendingID,
			TenantID:     "default",
			TokenStr:     "cfgms_reg_tok_" + pendingID,
			SourceIP:     "10.20.30.40",
			RegisteredAt: now,
			ExpiresAt:    now.Add(5 * 24 * time.Hour),
			Status:       business.PendingRegistrationStatusPending,
		}
		require.NoError(t, pendingStore.AddPending(context.Background(), entry))
		t.Cleanup(func() {
			_ = pendingStore.UpdateStatus(context.Background(), pendingID, business.PendingRegistrationStatusDenied)
		})

		resp := listPending(t)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var pending []PendingRegistration
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&pending))

		var found *PendingRegistration
		for i := range pending {
			if pending[i].PendingID == pendingID {
				found = &pending[i]
				break
			}
		}
		require.NotNil(t, found, "the entry written through the Postgres store must be returned by the handler")
		assert.Equal(t, "steward-"+pendingID, found.StewardID)
		assert.Equal(t, "default", found.TenantID)
		assert.Equal(t, "10.20.30.40", found.SourceIP)
	})
}

// stubRegistrationLeaderStatus is a minimal test double for the registrationLeaderStatus
// interface. It is NOT a mock: it has no expectations and carries only a fixed boolean.
// Defined here (package api test) and shared with handlers_registration_tokens_test.go.
type stubRegistrationLeaderStatus struct{ hasLeadership bool }

func (s *stubRegistrationLeaderStatus) HasLeadership() bool { return s.hasLeadership }

// TestRegistrationHandlerLeaderGate verifies that all seven mutating
// registration/token handlers return 503 when HasLeadership() is false
// (Raft leader flag set, lease expired — the partition scenario in ADR-029).
// One table covers all handlers per the acceptance criteria for Issue #3471.
func TestRegistrationHandlerLeaderGate(t *testing.T) {
	// follower is the stub used for "Raft leader but lease expired" cases.
	follower := &stubRegistrationLeaderStatus{hasLeadership: false}

	// newFollowerServer returns a minimal server with the registration leader
	// status set to the follower stub and nil stores (the leadership check runs
	// before any store access for all seven handlers).
	newFollowerServer := func(t *testing.T) *Server {
		t.Helper()
		tokenStore := newTestRegistrationStore(t)
		s, _ := newHandleRegisterServer(t, tokenStore, nil)
		s.registrationLeaderStatus = follower
		return s
	}

	// approveReq wraps a request with a mux "id" variable for approve endpoints.
	approveReq := func(method, url, id string) *http.Request {
		r := httptest.NewRequest(method, url, nil)
		return mux.SetURLVars(r, map[string]string{"id": id})
	}

	tests := []struct {
		name    string
		handler func(s *Server) (http.ResponseWriter, *http.Request)
	}{
		{
			name: "handleApproveRegistration rejects follower",
			handler: func(s *Server) (http.ResponseWriter, *http.Request) {
				w := httptest.NewRecorder()
				r := approveReq(http.MethodPost, "/api/v1/registration/reg-1/approve", "reg-1")
				s.handleApproveRegistration(w, r)
				return w, r
			},
		},
		{
			name: "handleApproveAllRegistrations rejects follower",
			handler: func(s *Server) (http.ResponseWriter, *http.Request) {
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodPost, "/api/v1/registration/approve-all", nil)
				s.handleApproveAllRegistrations(w, r)
				return w, r
			},
		},
		{
			name: "handleApproveByCIDR rejects follower",
			handler: func(s *Server) (http.ResponseWriter, *http.Request) {
				w := httptest.NewRecorder()
				body := strings.NewReader(`{"cidr":"10.0.0.0/8"}`)
				r := httptest.NewRequest(http.MethodPost, "/api/v1/registration/approve-by-cidr", body)
				r.Header.Set("Content-Type", "application/json")
				s.handleApproveByCIDR(w, r)
				return w, r
			},
		},
		{
			name: "handleCreateRegistrationToken rejects follower",
			handler: func(s *Server) (http.ResponseWriter, *http.Request) {
				w := httptest.NewRecorder()
				body := strings.NewReader(`{"tenant_id":"t1","controller_url":"grpc://x:7443"}`)
				r := httptest.NewRequest(http.MethodPost, "/api/v1/registration/tokens", body)
				r.Header.Set("Content-Type", "application/json")
				s.handleCreateRegistrationToken(w, r)
				return w, r
			},
		},
		{
			name: "handleDeleteRegistrationToken rejects follower",
			handler: func(s *Server) (http.ResponseWriter, *http.Request) {
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodDelete, "/api/v1/registration/tokens/tok1", nil)
				r = mux.SetURLVars(r, map[string]string{"token": "tok1"})
				s.handleDeleteRegistrationToken(w, r)
				return w, r
			},
		},
		{
			name: "handleRevokeRegistrationToken rejects follower",
			handler: func(s *Server) (http.ResponseWriter, *http.Request) {
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodPost, "/api/v1/registration/tokens/tok1/revoke", nil)
				r = mux.SetURLVars(r, map[string]string{"token": "tok1"})
				s.handleRevokeRegistrationToken(w, r)
				return w, r
			},
		},
		{
			name: "handleRotateRegistrationToken rejects follower",
			handler: func(s *Server) (http.ResponseWriter, *http.Request) {
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodPost, "/api/v1/registration/tokens/t1/rotate", nil)
				r = mux.SetURLVars(r, map[string]string{"tenant_id": "t1"})
				s.handleRotateRegistrationToken(w, r)
				return w, r
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newFollowerServer(t)
			w, _ := tc.handler(s)
			rec := w.(*httptest.ResponseRecorder)

			assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
				"follower must return 503")

			// AC: response body must not name or imply which node holds leadership.
			body := rec.Body.String()
			assert.NotContains(t, body, "node", "503 body must not name a node")
			assert.NotContains(t, body, "leader", "503 body must not imply which node holds leadership")
		})
	}
}

// TestRegistrationHandlerLeaderGate_SingleServerMode verifies that a nil
// registrationLeaderStatus (OSS single-server deployment) never rejects
// registration or token operations — no new rejection path for single-node.
func TestRegistrationHandlerLeaderGate_SingleServerMode(t *testing.T) {
	// newSingleServerServer returns a server with nil registrationLeaderStatus
	// (the default from New() when haManager is nil).
	newSingleServerServer := func(t *testing.T) *Server {
		t.Helper()
		tokenStore := newTestRegistrationStore(t)
		s, _ := newHandleRegisterServer(t, tokenStore, nil)
		// registrationLeaderStatus is nil by default (nil haManager path).
		return s
	}

	t.Run("handleApproveAllRegistrations passes gate with nil checker", func(t *testing.T) {
		s := newSingleServerServer(t)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/registration/approve-all", nil)
		s.handleApproveAllRegistrations(w, r)
		// nil pendingStore returns 503 "registration store unavailable" — but NOT from the leader gate.
		// The gate itself must NOT have fired: body must differ from the gate's message.
		assert.NotEqual(t, "service unavailable\n", w.Body.String(),
			"single-server mode must not be rejected by the leader gate")
	})

	t.Run("handleCreateRegistrationToken passes gate with nil checker", func(t *testing.T) {
		s := newSingleServerServer(t)
		w := httptest.NewRecorder()
		body := strings.NewReader(`{"tenant_id":"t1","controller_url":"grpc://x:7443"}`)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/registration/tokens", body)
		r.Header.Set("Content-Type", "application/json")
		s.handleCreateRegistrationToken(w, r)
		// nil tokenStore → 500 "Registration service unavailable"; gate must not have fired.
		assert.NotEqual(t, http.StatusServiceUnavailable, w.Code,
			"single-server mode must not be rejected by the leader gate")
	})
}

// TestHandleRegister_LeaderGate covers AC #4 of Issue #3471: enrollment itself —
// not only the approve/token endpoints — must be rejected by a controller that
// holds the raw Raft leader flag but has lost its lease. Gating token creation
// alone does not close the path, because an already-issued (perennial) token
// stays usable, so a stale leader could still enroll a steward or complete a
// re-enrollment that clears that steward's fencing ratchet (#3390-B).
func TestHandleRegister_LeaderGate(t *testing.T) {
	const regToken = "cfgms_reg_leader_gate_tok"

	seedToken := func(t *testing.T, tokenStore registration.Store) {
		t.Helper()
		require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
			Token:         regToken,
			TenantID:      "test-tenant",
			ControllerURL: "grpc://controller:7443",
			Group:         "prod",
		}))
	}

	t.Run("follower rejects enrollment with 503 and grants no trust", func(t *testing.T) {
		tokenStore := newTestRegistrationStore(t)
		// A real cert manager is wired so the test proves the gate stops the
		// request before certificate issuance, not that issuance was impossible.
		server, _ := newHandleRegisterServer(t, tokenStore, newTestCertManager(t))
		// Approve, so the request would reach inline certificate issuance if the
		// gate did not stop it first.
		server.SetApprovalHook(&AlwaysApproveHook{})
		seedToken(t, tokenStore)
		server.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}

		rec := postRegister(server, regToken)

		require.Equal(t, http.StatusServiceUnavailable, rec.Code,
			"enrollment against a non-authoritative controller must be rejected")

		var resp RegistrationResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.Empty(t, resp.ClientCert, "no client certificate may be issued by a follower")
		assert.Empty(t, resp.ClientKey, "no client key may be issued by a follower")

		// The 503 must not name or imply which node holds leadership.
		body := rec.Body.String()
		assert.NotContains(t, body, "node", "503 body must not name a node")
		assert.NotContains(t, body, "leader", "503 body must not imply which node holds leadership")

		// The token must remain unclaimed: a rejected enrollment must leave no
		// durable side effect for the authoritative controller to trip over.
		keyBytes, err := base64.StdEncoding.DecodeString(testValidIdentityKeyPub)
		require.NoError(t, err)
		created, err := tokenStore.ClaimToken(context.Background(), regToken,
			registrationClaimID(testValidDeviceID, keyBytes))
		require.NoError(t, err)
		assert.True(t, created,
			"rejected enrollment must not have claimed the registration token")
	})

	t.Run("single-server mode enrolls unconditionally", func(t *testing.T) {
		tokenStore := newTestRegistrationStore(t)
		server, _ := newHandleRegisterServer(t, tokenStore, newTestCertManager(t))
		server.SetApprovalHook(&AlwaysApproveHook{})
		seedToken(t, tokenStore)
		// registrationLeaderStatus stays nil: no lease, no expiry, no new rejection.

		rec := postRegister(server, regToken)

		require.Equal(t, http.StatusOK, rec.Code,
			"single-server mode must not be rejected by the leader gate")
		var resp RegistrationResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.ClientCert, "single-server enrollment must still issue a cert")
	})
}

// TestHandleRegistrationStatus_ClaimLeaderGate covers the second half of the
// enrollment path. Issue #3471 excluded handleRegistrationStatus as "read-only"
// and asked for that judgment to be confirmed at implementation time: it does
// not hold for the approved branch, which transitions the entry to "claimed" and
// mints a client certificate. Only that branch is gated — status polling itself
// stays available on a non-authoritative controller.
func TestHandleRegistrationStatus_ClaimLeaderGate(t *testing.T) {
	const regToken = "cfgms_reg_claim_gate_tok"
	const tenantID = "test-tenant"
	const pendingID = "pending-claim-gate-1"

	// newStatusServer wires a real token store, pending store and cert manager,
	// seeds an approved pending entry, and applies the given leadership state.
	newStatusServer := func(t *testing.T, checker registrationLeaderStatus) *Server {
		t.Helper()
		tokenStore := newTestRegistrationStore(t)
		server, _ := newHandleRegisterServer(t, tokenStore, newTestCertManager(t))
		pendingStore := pkgtesting.SetupTestStorage(t).GetPendingRegistrationStore()
		require.NotNil(t, pendingStore)
		server.SetPendingStore(pendingStore)
		if checker != nil {
			server.registrationLeaderStatus = checker
		}

		require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
			Token:         regToken,
			TenantID:      tenantID,
			ControllerURL: "grpc://controller:7443",
			Group:         "prod",
		}))

		now := time.Now().UTC()
		require.NoError(t, pendingStore.AddPending(context.Background(), &business.PendingRegistrationEntry{
			PendingID:    pendingID,
			StewardID:    "steward-claim-gate-1",
			TenantID:     tenantID,
			TokenStr:     regToken,
			SourceIP:     "10.0.0.1",
			RegisteredAt: now,
			ExpiresAt:    now.Add(5 * 24 * time.Hour),
			Status:       business.PendingRegistrationStatusPending,
		}))
		require.NoError(t, pendingStore.UpdateStatus(context.Background(), pendingID,
			business.PendingRegistrationStatusApproved))
		return server
	}

	pollStatus := func(server *Server, id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/registration/status/"+id, nil)
		r.Header.Set("Authorization", "Bearer "+regToken)
		r = mux.SetURLVars(r, map[string]string{"pending_id": id})
		rec := httptest.NewRecorder()
		server.handleRegistrationStatus(rec, r)
		return rec
	}

	t.Run("follower does not mint a cert for an approved entry", func(t *testing.T) {
		server := newStatusServer(t, &stubRegistrationLeaderStatus{hasLeadership: false})

		rec := pollStatus(server, pendingID)

		require.Equal(t, http.StatusServiceUnavailable, rec.Code,
			"claiming a cert from a non-authoritative controller must be rejected")
		var body RegistrationStatusResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		assert.Empty(t, body.ClientCert, "no client certificate may be issued by a follower")
		assert.Empty(t, body.ClientKey, "no client key may be issued by a follower")
		assert.NotContains(t, rec.Body.String(), "node", "503 body must not name a node")
		assert.NotContains(t, rec.Body.String(), "leader",
			"503 body must not imply which node holds leadership")

		// The entry must stay "approved" so the authoritative controller can
		// serve the claim once the steward retries.
		got, err := server.pendingStore.GetPendingByID(context.Background(), pendingID)
		require.NoError(t, err)
		assert.Equal(t, business.PendingRegistrationStatusApproved, got.Status,
			"a rejected claim must not consume the approval")
	})

	t.Run("leader serves the claim", func(t *testing.T) {
		server := newStatusServer(t, &stubRegistrationLeaderStatus{hasLeadership: true})

		rec := pollStatus(server, pendingID)

		require.Equal(t, http.StatusOK, rec.Code)
		var body RegistrationStatusResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, business.PendingRegistrationStatusClaimed, body.Status)
		assert.NotEmpty(t, body.ClientCert, "an authoritative controller must still serve the claim")
	})

	t.Run("follower still answers a pending status poll", func(t *testing.T) {
		server := newStatusServer(t, &stubRegistrationLeaderStatus{hasLeadership: false})
		require.NoError(t, server.pendingStore.UpdateStatus(context.Background(), pendingID,
			business.PendingRegistrationStatusPending))

		rec := pollStatus(server, pendingID)

		require.Equal(t, http.StatusOK, rec.Code,
			"read-only status polling must stay available on a non-authoritative controller")
		var body RegistrationStatusResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "pending", body.Status)
	})
}

// TestHandleRegister_ClaimPath_WritesDurableRecordAndSurvivesRestart: AC1 + AC2 —
// the quarantine→approve→claim flow must write a StewardRecord to the durable
// StewardStore at claim time (buildClaimResponse), and that record must be visible
// in the registry after a simulated controller restart (new ControllerService +
// LoadFromStorage from the same StewardStore), even though the steward never sent
// a gRPC check-in. Issue #3403.
func TestHandleRegister_ClaimPath_WritesDurableRecordAndSurvivesRestart(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, stewardSt := newHandleRegisterServerWithStewardStore(t, tokenStore, certMgr)
	server.SetApprovalHook(&quarantineHookForTest{})

	// Use a separate pending store (the default one from newHandleRegisterServer is
	// replaced here so the claim poll hits the same store as the approve step).
	pendingStore := pkgtesting.SetupTestStorage(t).GetPendingRegistrationStore()
	require.NotNil(t, pendingStore)
	server.SetPendingStore(pendingStore)

	ts := httptest.NewServer(server.router)
	defer ts.Close()

	const regToken = "cfgms_reg_claim_durable_ac1"
	const tenantID = "tenant-claim-ac1"
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token:         regToken,
		TenantID:      tenantID,
		ControllerURL: "grpc://controller:7443",
	}))

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	deviceID := "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4"
	identityKeyPub := base64.StdEncoding.EncodeToString([]byte(pub))

	// Step 1: Register → quarantine (HTTP 202).
	rec1 := postRegisterWithBody(server, RegistrationRequest{
		Token:          regToken,
		DeviceID:       deviceID,
		IdentityKeyPub: identityKeyPub,
	})
	require.Equal(t, http.StatusAccepted, rec1.Code, "quarantine must return 202")
	var qResp RegistrationPendingResponse
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &qResp))
	require.NotEmpty(t, qResp.PendingID, "quarantine response must include a pending_id")

	// Step 2: Operator approves.
	require.NoError(t, pendingStore.UpdateStatus(context.Background(),
		qResp.PendingID, business.PendingRegistrationStatusApproved))

	// Step 3: Steward polls → claim (cert issued, StewardStore written by buildClaimResponse).
	pollReq, err := http.NewRequestWithContext(context.Background(), "GET",
		ts.URL+"/api/v1/registration/status/"+qResp.PendingID, nil)
	require.NoError(t, err)
	pollReq.Header.Set("Authorization", "Bearer "+regToken)
	pollResp, err := ts.Client().Do(pollReq)
	require.NoError(t, err)
	defer func() { _ = pollResp.Body.Close() }()
	require.Equal(t, http.StatusOK, pollResp.StatusCode, "claim poll must return 200")

	var claimBody RegistrationStatusResponse
	require.NoError(t, json.NewDecoder(pollResp.Body).Decode(&claimBody))
	require.Equal(t, business.PendingRegistrationStatusClaimed, claimBody.Status,
		"status must be 'claimed' after successful cert issuance")
	require.NotEmpty(t, claimBody.StewardID, "claim response must include steward_id")

	// StewardStore must have a durable "registered" record immediately after claim
	// (before any gRPC check-in).
	stored, storeErr := stewardSt.GetSteward(context.Background(), claimBody.StewardID)
	require.NoError(t, storeErr,
		"StewardStore must contain a record for the steward immediately after cert claim")
	assert.Equal(t, business.StewardStatusRegistered, stored.Status,
		"durable status must be 'registered' at enrollment: cert issued, no check-in yet")
	assert.Equal(t, tenantID, stored.TenantID,
		"durable record must be scoped to the correct tenant (AC4)")
	assert.Equal(t, deviceID, stored.DeviceID,
		"durable record must include the DeviceID from the pending entry (AC2 identity fields)")
	assert.Equal(t, []byte(pub), stored.IdentityKeyPub,
		"durable record must include the IdentityKeyPub from the pending entry")

	// Simulate controller restart: fresh ControllerService with no DNA storage,
	// backed by the same StewardStore. The steward has never sent a gRPC check-in.
	restarted := service.NewControllerService(logging.NewNoopLogger())
	restarted.SetStewardStore(stewardSt)
	require.NoError(t, restarted.LoadFromStorage(context.Background()))

	assert.Equal(t, 1, restarted.GetStewardCount(),
		"enrolled steward must appear in the new controller's registry after restart (AC1)")
	info, ok := restarted.GetStewardInfo(claimBody.StewardID)
	require.True(t, ok, "enrolled steward must be retrievable by ID after restart")
	assert.Equal(t, tenantID, info.TenantID)
	assert.Equal(t, string(business.StewardStatusRegistered), info.Status,
		"status must remain 'registered' in the restarted controller (never connected)")
}

// TestHandleRegistrationStatus_ClaimRejectsDuplicateDeviceIDInTenant verifies that the
// quarantine→approve→claim route enforces the same tenant-scoped duplicate-device_id
// guard handleRegister applies to its direct-approval write. Two enrollments asserting
// one device_id with different identity keys get distinct pending IDs (pendingRegistrationID
// hashes the token with the device identity), so both pass the register-time 409 gate —
// no StewardRecord exists yet at that point. The second claim must be refused with 409 and
// must not mint a certificate or write a sibling StewardRecord, because two records sharing
// a device_id break GetStewardByDeviceID, the single lookup feeding the refresh revocation
// gate (ADR-010 §1, §3).
func TestHandleRegistrationStatus_ClaimRejectsDuplicateDeviceIDInTenant(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, stewardSt := newHandleRegisterServerWithStewardStore(t, tokenStore, certMgr)
	server.SetApprovalHook(&quarantineHookForTest{})

	pendingStore := pkgtesting.SetupTestStorage(t).GetPendingRegistrationStore()
	require.NotNil(t, pendingStore)
	server.SetPendingStore(pendingStore)

	ts := httptest.NewServer(server.router)
	defer ts.Close()

	const regToken = "cfgms_reg_claim_dup_device"
	const tenantID = "tenant-claim-dup"
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token:         regToken,
		TenantID:      tenantID,
		ControllerURL: "grpc://controller:7443",
	}))

	// One device_id, two different identity keys — isValidDeviceID never verifies
	// device_id == SHA-256(identity_key_pub), so this is reachable from the wire.
	deviceID := "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	quarantine := func(identityKeyPub string) string {
		rec := postRegisterWithBody(server, RegistrationRequest{
			Token:          regToken,
			DeviceID:       deviceID,
			IdentityKeyPub: identityKeyPub,
		})
		require.Equal(t, http.StatusAccepted, rec.Code, "quarantine must return 202")
		var qResp RegistrationPendingResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &qResp))
		require.NotEmpty(t, qResp.PendingID)
		return qResp.PendingID
	}

	// Both registrations happen before either claim, so no StewardRecord exists to
	// trip the register-time duplicate gate.
	pendingA := quarantine(base64.StdEncoding.EncodeToString([]byte(pubA)))
	pendingB := quarantine(base64.StdEncoding.EncodeToString([]byte(pubB)))
	require.NotEqual(t, pendingA, pendingB,
		"distinct identity keys must yield distinct pending entries for the same device_id")

	for _, id := range []string{pendingA, pendingB} {
		require.NoError(t, pendingStore.UpdateStatus(context.Background(),
			id, business.PendingRegistrationStatusApproved))
	}

	claim := func(pendingID string) *http.Response {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet,
			ts.URL+"/api/v1/registration/status/"+pendingID, nil)
		require.NoError(t, reqErr)
		req.Header.Set("Authorization", "Bearer "+regToken)
		resp, doErr := ts.Client().Do(req)
		require.NoError(t, doErr)
		return resp
	}

	// First claim succeeds and writes the durable record.
	respA := claim(pendingA)
	require.Equal(t, http.StatusOK, respA.StatusCode, "first claim must succeed")
	var claimA RegistrationStatusResponse
	require.NoError(t, json.NewDecoder(respA.Body).Decode(&claimA))
	require.NoError(t, respA.Body.Close())
	require.NotEmpty(t, claimA.StewardID)

	// Second claim asserts the same device_id in the same tenant: refused.
	respB := claim(pendingB)
	body, readErr := io.ReadAll(respB.Body)
	require.NoError(t, readErr)
	require.NoError(t, respB.Body.Close())
	assert.Equal(t, http.StatusConflict, respB.StatusCode,
		"a claim asserting a device_id already held in the tenant must be refused")
	assert.NotContains(t, string(body), "BEGIN CERTIFICATE",
		"a refused claim must not mint a client certificate")

	// Exactly one steward record carries the device_id, so GetStewardByDeviceID
	// remains unambiguous for the revocation gate.
	all, listErr := stewardSt.ListStewards(context.Background())
	require.NoError(t, listErr)
	matching := make([]string, 0, len(all))
	for _, rec := range all {
		if rec.DeviceID == deviceID && rec.TenantID == tenantID {
			matching = append(matching, rec.ID)
		}
	}
	assert.Equal(t, []string{claimA.StewardID}, matching,
		"only the first claim may hold a StewardRecord for this device_id")
}

// TestBuildClaimResponse_DuplicateDeviceIDAcrossTenantsAllowed verifies the guard is
// tenant-scoped: the same device_id enrolled under a different tenant is a distinct
// namespace and must still be able to claim, matching handleRegister's register-time
// behaviour (cross-tenant collision allowed).
func TestBuildClaimResponse_DuplicateDeviceIDAcrossTenantsAllowed(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, stewardSt := newHandleRegisterServerWithStewardStore(t, tokenStore, certMgr)

	const regToken = "cfgms_reg_claim_xtenant"
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token:         regToken,
		TenantID:      "tenant-claim-x2",
		ControllerURL: "grpc://controller:7443",
	}))

	deviceID := "e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7"
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// An existing record in a *different* tenant holds the same device_id.
	require.NoError(t, stewardSt.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-other-tenant",
		TenantID: "tenant-claim-x1",
		Status:   business.StewardStatusRegistered,
		DeviceID: deviceID,
	}))

	resp, err := server.buildClaimResponse(context.Background(), &business.PendingRegistrationEntry{
		PendingID:      "pend-xtenant",
		StewardID:      "steward-claim-x2",
		TenantID:       "tenant-claim-x2",
		DeviceID:       deviceID,
		IdentityKeyPub: []byte(pub),
		RegisteredAt:   time.Now().UTC(),
	}, regToken)
	require.NoError(t, err, "a device_id held in another tenant must not block this claim")
	require.NotNil(t, resp)
	assert.Contains(t, resp.ClientCert, "BEGIN CERTIFICATE")

	stored, lookupErr := stewardSt.GetSteward(context.Background(), "steward-claim-x2")
	require.NoError(t, lookupErr, "the cross-tenant claim must still persist its own record")
	assert.Equal(t, deviceID, stored.DeviceID)
}

// TestBuildClaimResponse_SameStewardIDReclaimIsNotAConflict verifies the guard keys on
// the steward ID: a concurrent or retried claim poll for the *same* steward re-runs the
// write path and must not be mistaken for a duplicate-device enrollment.
func TestBuildClaimResponse_SameStewardIDReclaimIsNotAConflict(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, stewardSt := newHandleRegisterServerWithStewardStore(t, tokenStore, certMgr)

	const regToken = "cfgms_reg_claim_reclaim"
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token:         regToken,
		TenantID:      "tenant-reclaim",
		ControllerURL: "grpc://controller:7443",
	}))

	deviceID := "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8"
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	entry := &business.PendingRegistrationEntry{
		PendingID:      "pend-reclaim",
		StewardID:      "steward-reclaim",
		TenantID:       "tenant-reclaim",
		DeviceID:       deviceID,
		IdentityKeyPub: []byte(pub),
		RegisteredAt:   time.Now().UTC(),
	}

	_, err = server.buildClaimResponse(context.Background(), entry, regToken)
	require.NoError(t, err)

	// Second pass over the same entry: the existing record belongs to this steward.
	_, err = server.buildClaimResponse(context.Background(), entry, regToken)
	require.NoError(t, err, "re-running the claim for the same steward must not conflict")

	all, listErr := stewardSt.ListStewards(context.Background())
	require.NoError(t, listErr)
	count := 0
	for _, rec := range all {
		if rec.DeviceID == deviceID {
			count++
		}
	}
	assert.Equal(t, 1, count, "the retried claim must not create a second record")
}
