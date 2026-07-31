// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	storageinterfaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// setupCertTestServer creates a server wired with a real cert manager and a real
// steward store for certificate handler tests. The steward store mirrors the
// production composition (server.go wires it whenever the storage provider
// supplies one) and is required by the list endpoint for any tenant-scoped caller.
func setupCertTestServer(t *testing.T) (*Server, *cert.Manager) {
	t.Helper()
	setTestSecretsEnv(t)

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	logger := logging.NewNoopLogger()
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

	certMgr := newTestCertManager(t)

	server, err := New(
		cfg, logger, controllerService, configService,
		nil, rbacService, certMgr, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr,
		nil, // No command publisher for basic tests
		nil, // No push store for basic tests
		nil, // No blob store for basic tests
	)
	require.NoError(t, err)
	server.SetStewardStore(storageManager.GetStewardStore())
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Close(closeCtx); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	})

	return server, certMgr
}

// TestHandleListCertificates_ReturnsRealData verifies the list endpoint returns
// actual certificate data from the cert manager after a client cert has been issued.
func TestHandleListCertificates_ReturnsRealData(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	apiKey := NewTestKey(t, server, []string{"certificate:list"})

	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-test-01",
		Organization: "Test CFGMS",
		ClientID:     "steward-test-01",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.GreaterOrEqual(t, len(resp.Data), 1, "response must contain at least one certificate")

	found := false
	for _, c := range resp.Data {
		if c.CommonName == "steward-test-01" {
			found = true
			assert.NotEmpty(t, c.SerialNumber)
			assert.Equal(t, "steward-test-01", c.StewardID)
			assert.True(t, c.IsValid)
		}
	}
	assert.True(t, found, "issued certificate must appear in list response")
}

// TestHandleListCertificates_NilCertManager_Returns503 verifies that the handler
// returns 503 when no cert manager is configured.
func TestHandleListCertificates_NilCertManager_Returns503(t *testing.T) {
	server := setupTestServer(t) // no cert manager
	apiKey := NewTestKey(t, server, []string{"certificate:list"})

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "SERVICE_UNAVAILABLE", errResp.Error.Code)
}

// TestHandleListCertificates_EmptyStore_ReturnsEmptyList verifies that a newly
// created cert manager with only a CA cert returns an empty list (CA certs are excluded).
func TestHandleListCertificates_EmptyStore_ReturnsEmptyList(t *testing.T) {
	server, _ := setupCertTestServer(t)
	apiKey := NewTestKey(t, server, []string{"certificate:list"})

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

// TestHandleListCertificates_WithStewardFilter_ReturnsStewardCert verifies the
// ?steward_id= filter returns only certs matching that common name.
func TestHandleListCertificates_WithStewardFilter_ReturnsStewardCert(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	apiKey := NewTestKey(t, server, []string{"certificate:list"})

	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-alpha",
		Organization: "Test CFGMS",
		ClientID:     "steward-alpha",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	_, err = certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-beta",
		Organization: "Test CFGMS",
		ClientID:     "steward-beta",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1/certificates?steward_id=steward-alpha", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "steward-alpha", resp.Data[0].CommonName)
	assert.Equal(t, "steward-alpha", resp.Data[0].StewardID)
}

// TestHandleListCertificates_WithStewardFilter_NoMatch_ReturnsEmpty verifies that
// filtering by a non-existent steward ID returns an empty list (not an error).
func TestHandleListCertificates_WithStewardFilter_NoMatch_ReturnsEmpty(t *testing.T) {
	server, _ := setupCertTestServer(t)
	apiKey := NewTestKey(t, server, []string{"certificate:list"})

	req := httptest.NewRequest("GET", "/api/v1/certificates?steward_id=does-not-exist", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

// TestHandleListCertificates_MultipleCerts_AllReturned verifies that all issued
// non-CA certificates appear in the list response.
func TestHandleListCertificates_MultipleCerts_AllReturned(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	apiKey := NewTestKey(t, server, []string{"certificate:list"})

	stewards := []string{"steward-one", "steward-two", "steward-three"}
	for _, id := range stewards {
		_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
			CommonName:   id,
			Organization: "Test CFGMS",
			ClientID:     id,
			ValidityDays: 365,
		})
		require.NoError(t, err)
	}

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, len(stewards))
}

// TestHandleListCertificates_RequiresAuth verifies the endpoint rejects unauthenticated requests.
func TestHandleListCertificates_RequiresAuth(t *testing.T) {
	server, _ := setupCertTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleListCertificates_RequiresCorrectPermission verifies that an API key
// without certificate:list permission is denied.
func TestHandleListCertificates_RequiresCorrectPermission(t *testing.T) {
	server, _ := setupCertTestServer(t)
	wrongKey := NewTestKey(t, server, []string{"steward:list"})

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", wrongKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// setupCertTestServerWithStewardStore creates a server wired with a real cert
// manager AND a real steward store for tenant-scope filtering tests.
func setupCertTestServerWithStewardStore(t *testing.T) (*Server, *cert.Manager, business.StewardStore) {
	t.Helper()
	server, certMgr, stewardStore, _ := setupCertTestServerWithStewardStoreRoot(t)
	return server, certMgr, stewardStore
}

// setupCertTestServerWithStewardStoreRoot is setupCertTestServerWithStewardStore with
// the flat-file storage root returned as well, so a test can inject a genuine durable-store
// fault by corrupting an on-disk steward record instead of substituting a fake store.
func setupCertTestServerWithStewardStoreRoot(t *testing.T) (*Server, *cert.Manager, business.StewardStore, string) {
	t.Helper()
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	logger := logging.NewNoopLogger()

	// Real OSS composite storage (flatfile steward records + in-memory SQLite business
	// data), created here rather than via pkgtesting.SetupTestStorage so the test owns
	// the flat-file root path.
	flatfileRoot := t.TempDir()
	storageManager, err := storageinterfaces.CreateOSSStorageManager(
		flatfileRoot,
		"file:cfgms-certtest-"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory",
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		if closeErr := storageManager.Close(); closeErr != nil {
			t.Errorf("storageManager.Close: %v", closeErr)
		}
	})

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

	certMgr := newTestCertManager(t)

	server, err := New(
		cfg, logger, controllerService, configService,
		nil, rbacService, certMgr, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr,
		nil, // No command publisher
		nil, // No push store
		nil, // No blob store
	)
	require.NoError(t, err)

	stewardStore := storageManager.GetStewardStore()
	server.SetStewardStore(stewardStore)

	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Close(closeCtx); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	})

	return server, certMgr, stewardStore, flatfileRoot
}

// TestHandleListCertificates_TenantScope_ExcludesSiblingTenant verifies that a
// caller scoped to client-1 never sees a certificate belonging to a steward in
// sibling tenant client-2.
func TestHandleListCertificates_TenantScope_ExcludesSiblingTenant(t *testing.T) {
	server, certMgr, stewardStore := setupCertTestServerWithStewardStore(t)

	// Register two stewards in sibling tenants.
	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-client1",
		TenantID: "client-1",
		Hostname: "host1",
		Platform: "linux",
		Arch:     "amd64",
	}))
	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-client2",
		TenantID: "client-2",
		Hostname: "host2",
		Platform: "linux",
		Arch:     "amd64",
	}))

	// Issue mTLS client certs for both stewards.
	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-client1",
		Organization: "Test CFGMS",
		ClientID:     "steward-client1",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	_, err = certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-client2",
		Organization: "Test CFGMS",
		ClientID:     "steward-client2",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Caller scoped to client-1.
	apiKey := NewEphemeralTestKey(t, server, []string{"certificate:list"}, "client-1", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// client-1's cert must be present.
	foundClient1 := false
	for _, c := range resp.Data {
		if c.StewardID == "steward-client1" {
			foundClient1 = true
		}
		// client-2's cert must never appear.
		assert.NotEqual(t, "steward-client2", c.StewardID,
			"client-2 certificate must be excluded from client-1 caller's response")
	}
	assert.True(t, foundClient1, "client-1 certificate must be included in the response")
}

// TestHandleListCertificates_StewardFilter_TenantScope_ExcludesSiblingTenantByCommonName
// covers the ?steward_id= branch under a tenant-scoped caller. The filter matches on
// COMMON NAME, which is independent of the owning steward (provisioning accepts an
// explicit common_name while ClientID stays the steward ID). A client-1 caller asking
// for the sibling tenant's certificate by its common name must receive nothing: the
// scope decision has to resolve the certificate's recorded owner, not the caller's
// query param.
func TestHandleListCertificates_StewardFilter_TenantScope_ExcludesSiblingTenantByCommonName(t *testing.T) {
	server, certMgr, stewardStore := setupCertTestServerWithStewardStore(t)

	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-client2",
		TenantID: "client-2",
		Hostname: "host2",
		Platform: "linux",
		Arch:     "amd64",
	}))

	// Issued the way the provisioning service does it: common name diverges from
	// the steward ID recorded as ClientID.
	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-client2.example.com",
		Organization: "Test CFGMS",
		ClientID:     "steward-client2",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	apiKey := NewEphemeralTestKey(t, server, []string{"certificate:list"}, "client-1", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/certificates?steward_id=steward-client2.example.com", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	body := rec.Body.String()
	assert.NotContains(t, body, "steward-client2",
		"a client-1 caller must not learn anything about client-2's certificate via its common name")

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(strings.NewReader(body)).Decode(&resp))
	assert.Empty(t, resp.Data,
		"sibling-tenant certificate must be filtered out of the steward_id-filtered response")
}

// TestHandleListCertificates_StewardFilter_TenantScope_IncludesOwnTenantByCommonName
// is the positive counterpart: the ?steward_id= branch must still return the caller's
// own certificate when the common name diverges from the owning steward ID, and must
// label it with the authoritative owner (ClientID) rather than the query param.
func TestHandleListCertificates_StewardFilter_TenantScope_IncludesOwnTenantByCommonName(t *testing.T) {
	server, certMgr, stewardStore := setupCertTestServerWithStewardStore(t)

	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-client1",
		TenantID: "client-1",
		Hostname: "host1",
		Platform: "linux",
		Arch:     "amd64",
	}))

	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-client1.example.com",
		Organization: "Test CFGMS",
		ClientID:     "steward-client1",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	apiKey := NewEphemeralTestKey(t, server, []string{"certificate:list"}, "client-1", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/certificates?steward_id=steward-client1.example.com", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "steward-client1.example.com", resp.Data[0].CommonName)
	assert.Equal(t, "steward-client1", resp.Data[0].StewardID,
		"the response must report the certificate's recorded owner, not the query param")
}

// TestHandleListCertificates_StewardFilter_TenantScope_DivergentCNNotOwnerLabelled
// pins the labelling rule that the scope decision depends on: even for an unscoped
// admin, a certificate returned by the common-name filter carries its recorded
// ClientID as StewardID. Without this, filterCertsByTenantScope would evaluate a
// caller-supplied string.
func TestHandleListCertificates_StewardFilter_TenantScope_DivergentCNNotOwnerLabelled(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	apiKey := NewTestKey(t, server, []string{"certificate:list"})

	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-gamma.example.com",
		Organization: "Test CFGMS",
		ClientID:     "steward-gamma",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1/certificates?steward_id=steward-gamma.example.com", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "steward-gamma", resp.Data[0].StewardID)
}

// TestHandleListCertificates_TenantScope_InternalCertVisibleToAll verifies that a
// controller-internal certificate with no ClientID still appears in every caller's
// list regardless of tenant scope.
func TestHandleListCertificates_TenantScope_InternalCertVisibleToAll(t *testing.T) {
	server, certMgr, stewardStore := setupCertTestServerWithStewardStore(t)

	// Generate a signing cert (no ClientID — controller-internal).
	require.NoError(t, certMgr.EnsureSigningCertificate(nil))

	// Register a steward in a different tenant and issue a cert for it.
	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-other",
		TenantID: "other-tenant",
		Hostname: "other-host",
		Platform: "linux",
		Arch:     "amd64",
	}))
	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-other",
		Organization: "Test CFGMS",
		ClientID:     "steward-other",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Caller scoped to client-1 (different from other-tenant).
	apiKey := NewEphemeralTestKey(t, server, []string{"certificate:list"}, "client-1", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// The signing cert (no StewardID) must be present.
	foundInternal := false
	for _, c := range resp.Data {
		if c.StewardID == "" {
			foundInternal = true
		}
		// other-tenant cert must be absent.
		assert.NotEqual(t, "steward-other", c.StewardID,
			"other-tenant certificate must not appear in client-1 caller's response")
	}
	assert.True(t, foundInternal, "controller-internal cert (no ClientID) must appear regardless of tenant scope")
}

// TestHandleListCertificates_TenantScope_StewardNotInStore_CertKept verifies the
// story AC for unattributable certificates: a cert whose ClientID has no steward
// record in the durable store has no tenant owner to check against, so it remains
// visible to a tenant-scoped caller (same as a controller-internal cert with no
// ClientID at all).
func TestHandleListCertificates_TenantScope_StewardNotInStore_CertKept(t *testing.T) {
	server, certMgr, _ := setupCertTestServerWithStewardStore(t)

	// Issue a cert for a steward that is NOT registered in the stewardStore.
	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "unregistered-steward",
		Organization: "Test CFGMS",
		ClientID:     "unregistered-steward",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	apiKey := NewEphemeralTestKey(t, server, []string{"certificate:list"}, "client-1", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	found := false
	for _, c := range resp.Data {
		if c.StewardID == "unregistered-steward" {
			found = true
		}
	}
	assert.True(t, found, "cert whose owning steward has no durable record must remain visible to a tenant-scoped caller")
}

// TestHandleListCertificates_TenantScope_StewardNotInStore_VisibleToUnscopedAdmin
// verifies that unattributable certs also remain visible to an unscoped admin
// (mTLS admin cert → TenantID ""), which never filters at all.
func TestHandleListCertificates_TenantScope_StewardNotInStore_VisibleToUnscopedAdmin(t *testing.T) {
	server, certMgr, _ := setupCertTestServerWithStewardStore(t)

	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "unregistered-steward",
		Organization: "Test CFGMS",
		ClientID:     "unregistered-steward",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	adminCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(adminCert.CertificatePEM)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	found := false
	for _, c := range resp.Data {
		if c.StewardID == "unregistered-steward" {
			found = true
		}
	}
	assert.True(t, found, "unscoped admin must still see certs with no durable steward record")
}

// TestHandleListCertificates_TenantScope_StoreFault_Returns500 verifies that a genuine
// durable-store fault (a corrupted steward record, distinct from not-found) fails the
// request instead of degrading to no filtering at all. During a store outage the
// endpoint must never fall back to returning every tenant's certificates.
func TestHandleListCertificates_TenantScope_StoreFault_Returns500(t *testing.T) {
	server, certMgr, stewardStore, flatfileRoot := setupCertTestServerWithStewardStoreRoot(t)

	// steward-client1 is in the caller's tenant; steward-client2 is in a sibling tenant.
	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-client1",
		TenantID: "client-1",
		Hostname: "host1",
		Platform: "linux",
		Arch:     "amd64",
	}))
	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-client2",
		TenantID: "client-2",
		Hostname: "host2",
		Platform: "linux",
		Arch:     "amd64",
	}))

	for _, id := range []string{"steward-client1", "steward-client2"} {
		_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
			CommonName:   id,
			Organization: "Test CFGMS",
			ClientID:     id,
			ValidityDays: 365,
		})
		require.NoError(t, err)
	}

	// Corrupt the durable record for steward-client2 so GetSteward returns an
	// unmarshal error rather than business.ErrStewardNotFound.
	recordPath := filepath.Join(flatfileRoot, "stewards", "steward-client2.json")
	require.FileExists(t, recordPath)
	require.NoError(t, os.WriteFile(recordPath, []byte("{ not json"), 0o600))
	_, lookupErr := stewardStore.GetSteward(context.Background(), "steward-client2")
	require.Error(t, lookupErr, "corrupted record must produce a store error")
	require.NotErrorIs(t, lookupErr, business.ErrStewardNotFound,
		"the injected fault must be a genuine store error, not not-found")

	apiKey := NewEphemeralTestKey(t, server, []string{"certificate:list"}, "client-1", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"store fault during tenant-scope filtering must fail the request")
	body := rec.Body.String()
	assert.NotContains(t, body, "steward-client2",
		"failed scope evaluation must not leak the other tenant's certificate")
	assert.NotContains(t, body, "steward-client1",
		"failed scope evaluation must not return partial certificate data")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(strings.NewReader(body)).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
}

// TestHandleListCertificates_TenantScope_NilStewardStore_Returns503 verifies the
// endpoint fails CLOSED when the controller was composed without a steward store.
// Without that store, subtree membership cannot be evaluated for a tenant-scoped
// caller, so returning the list at all would disclose every tenant's serials,
// common names and expiry dates. The composition is reachable: server.go wires the
// store only when the storage provider supplies one, and a provider answering
// CreateStewardStore with business.ErrNotSupported leaves it nil.
func TestHandleListCertificates_TenantScope_NilStewardStore_Returns503(t *testing.T) {
	server, certMgr, stewardStore := setupCertTestServerWithStewardStore(t)

	// Two stewards in sibling tenants, both with issued certs.
	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-client1",
		TenantID: "client-1",
		Hostname: "host1",
		Platform: "linux",
		Arch:     "amd64",
	}))
	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "steward-client2",
		TenantID: "client-2",
		Hostname: "host2",
		Platform: "linux",
		Arch:     "amd64",
	}))
	for _, id := range []string{"steward-client1", "steward-client2"} {
		_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
			CommonName:   id,
			Organization: "Test CFGMS",
			ClientID:     id,
			ValidityDays: 365,
		})
		require.NoError(t, err)
	}

	// Reproduce the unwired composition: no steward store on the server.
	server.SetStewardStore(nil)

	apiKey := NewEphemeralTestKey(t, server, []string{"certificate:list"}, "client-1", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"a tenant-scoped caller must never receive an unfiltered certificate list")

	body := rec.Body.String()
	assert.NotContains(t, body, "steward-client2",
		"unevaluable scope must not leak the sibling tenant's certificate")
	assert.NotContains(t, body, "steward-client1",
		"unevaluable scope must not return partial certificate data")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(strings.NewReader(body)).Decode(&errResp))
	assert.Equal(t, "SERVICE_UNAVAILABLE", errResp.Error.Code)
}

// TestHandleListCertificates_TenantScope_NilStewardStore_UnscopedAdminStillListed
// verifies the fail-closed guard is scoped to tenant-scoped callers only: an
// unscoped admin (mTLS admin cert → TenantID "") has no subtree to restrict to and
// still receives the full list when no steward store is wired.
func TestHandleListCertificates_TenantScope_NilStewardStore_UnscopedAdminStillListed(t *testing.T) {
	server, certMgr, _ := setupCertTestServerWithStewardStore(t)

	_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-client1",
		Organization: "Test CFGMS",
		ClientID:     "steward-client1",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	adminCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(adminCert.CertificatePEM)
	require.NoError(t, err)

	server.SetStewardStore(nil)

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"unscoped admin must not be blocked by the tenant-scope store requirement")

	var resp struct {
		Data []CertificateInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	found := false
	for _, c := range resp.Data {
		if c.StewardID == "steward-client1" {
			found = true
		}
	}
	assert.True(t, found, "unscoped admin must still receive the full certificate list")
}

// setupRotationTestServer creates a server wired with a real cert manager and
// signing rotation service for rotate-endpoint tests.
func setupRotationTestServer(t *testing.T) (*Server, *cert.Manager, *service.SigningRotationService) {
	t.Helper()
	setTestSecretsEnv(t)

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	logger := logging.NewNoopLogger()
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

	certMgr := newTestCertManager(t)
	require.NoError(t, certMgr.EnsureSigningCertificate(nil))

	rotationSvc := service.NewSigningRotationService(certMgr, logger)
	rotationSvc.SetControllerService(controllerService)

	server, err := New(
		cfg, logger, controllerService, configService,
		nil, rbacService, certMgr, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr, nil, nil, nil,
	)
	require.NoError(t, err)
	server.SetSigningRotationService(rotationSvc)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Close(closeCtx); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	})

	return server, certMgr, rotationSvc
}

// TestHandleRotateSigningCertRequiresAdminCert verifies that the rotate endpoint
// returns 403 for any sub-Strong-assurance principal, even when rbacService is nil.
//
// (a) API-key principal → 403 (AssuranceMachine, does not meet AssuranceStrong bar).
// (b) rbacService == nil + non-Strong-assurance cert → 503 (fail closed).
// The defense-in-depth Assurance < AssuranceStrong guard must block both before any
// rotation logic runs, mirroring the certificate:rotate permissionAssurance entry.
func TestHandleRotateSigningCertRequiresAdminCert(t *testing.T) {
	server, _, _ := setupRotationTestServer(t)

	t.Run("api_key_principal_rejected", func(t *testing.T) {
		apiKey := NewTestKey(t, server, []string{"certificate:rotate"})
		req := httptest.NewRequest("POST", "/api/v1/certificates/signing/rotate", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		var errResp ErrorResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
		// Assurance gate (requirePermission) fires before the handler's own Assurance check:
		// Machine-assurance API keys get INSUFFICIENT_PERMISSIONS, not MTLS_REQUIRED (Issue #2780).
		assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errResp.Error.Code)
	})

	t.Run("nil_rbac_non_admin_principal_rejected", func(t *testing.T) {
		// Build a server with rbacService == nil to verify authorization fails closed.
		setTestSecretsEnv(t)
		cfg := config.DefaultConfig()
		cfg.Certificate.EnableCertManagement = false
		logger := logging.NewNoopLogger()
		storageManager := pkgtesting.SetupTestStorage(t)
		controllerService := service.NewControllerService(logger)
		configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
		auditMgr2, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
		require.NoError(t, err)
		t.Cleanup(func() { _ = auditMgr2.Stop(context.Background()) })
		nilRBACServer, err := New(
			cfg, logger, controllerService, configService,
			nil, nil /* rbacService == nil */, nil, nil, nil,
			nil, nil, nil, "", nil, auditMgr2, nil, nil, nil,
		)
		require.NoError(t, err)
		nilRBACServer.SetSigningRotationService(service.NewSigningRotationService(nil, logger))
		t.Cleanup(func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if closeErr := nilRBACServer.Close(closeCtx); closeErr != nil {
				t.Errorf("nilRBACServer.Close: %v", closeErr)
			}
		})

		// A valid credential cannot compensate for a missing authorization service.
		apiKey := NewTestKey(t, nilRBACServer, []string{"certificate:rotate"})
		req := httptest.NewRequest("POST", "/api/v1/certificates/signing/rotate", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		nilRBACServer.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
}

// TestHandleRotateSigningCert_AdminSuccess verifies that a valid mTLS admin principal
// receives 200 with a RotationResult payload.
func TestHandleRotateSigningCert_AdminSuccess(t *testing.T) {
	server, certMgr, _ := setupRotationTestServer(t)

	issuedCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)

	x509Cert, err := cert.ParseCertificateFromPEM(issuedCert.CertificatePEM)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/certificates/signing/rotate", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data RotateSigningCertResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Data.NewSerial)
	assert.NotEmpty(t, resp.Data.OldSerial, "old_serial must be populated from the active signing cert when no rotation cursor exists yet")
	assert.NotEqual(t, resp.Data.OldSerial, resp.Data.NewSerial, "old_serial and new_serial must differ after rotation")
	assert.Equal(t, 7, resp.Data.OverlapDays)
	assert.NotEmpty(t, resp.Data.OverlapExpiresAt, "overlap_expires_at must be populated when overlap_days > 0")
	if _, parseErr := time.Parse(time.RFC3339, resp.Data.OverlapExpiresAt); parseErr != nil {
		t.Errorf("overlap_expires_at must be RFC3339 timestamp, got %q: %v", resp.Data.OverlapExpiresAt, parseErr)
	}
}

// TestHandleRotateSigningCert_ZeroOverlapPreserved verifies that an explicit
// overlap_days=0 in the request body is preserved (not defaulted to 7) and that
// overlap_expires_at is empty for zero-day rotations.
func TestHandleRotateSigningCert_ZeroOverlapPreserved(t *testing.T) {
	server, certMgr, _ := setupRotationTestServer(t)

	issuedCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(issuedCert.CertificatePEM)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/certificates/signing/rotate",
		strings.NewReader(`{"overlap_days":0}`))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data RotateSigningCertResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 0, resp.Data.OverlapDays, "explicit overlap_days=0 must be preserved, not replaced by the default")
	assert.Empty(t, resp.Data.OverlapExpiresAt, "overlap_expires_at must be empty when overlap_days == 0")
}

// TestHandleRotateSigningCert_ForceBypassesInProgress verifies that force=true
// in the request body allows a rotation to succeed even when the previous
// rotation's overlap window has not yet expired. The first rotation only
// establishes a CurrentSerial in the cursor (no rotating serial); the second
// shifts the first's serial into RotatingSerial; the third without force is
// then blocked by the in-progress guard; the fourth with force succeeds.
func TestHandleRotateSigningCert_ForceBypassesInProgress(t *testing.T) {
	server, certMgr, _ := setupRotationTestServer(t)

	issuedCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(issuedCert.CertificatePEM)
	require.NoError(t, err)

	do := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/certificates/signing/rotate",
			strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		return rec
	}

	// Prime the cursor: first rotation seeds CurrentSerial; second shifts it
	// into RotatingSerial with a 30-day overlap window.
	require.Equal(t, http.StatusOK, do(`{"overlap_days":30}`).Code, "first prime rotation must succeed")
	require.Equal(t, http.StatusOK, do(`{"overlap_days":30}`).Code, "second prime rotation must succeed")

	// Third rotation without force MUST fail with "in progress" because the
	// previous 30-day overlap is still active. The in-progress guard is a
	// client-recoverable conflict, surfaced as 409 (not 500) so callers can
	// retry with force=true (Issue #1816).
	rec3 := do(`{"overlap_days":30}`)
	require.Equal(t, http.StatusConflict, rec3.Code,
		"non-force rotation during active overlap must be rejected with 409, got body: %s", rec3.Body.String())

	// Fourth rotation with force MUST succeed despite the active in-progress state.
	rec4 := do(`{"overlap_days":30,"force":true}`)
	require.Equal(t, http.StatusOK, rec4.Code,
		"force rotation must succeed despite active overlap, got body: %s", rec4.Body.String())

	var resp struct {
		Data RotateSigningCertResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec4.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Data.NewSerial)
}

// TestHandleRotateSigningCert_NegativeOverlapRejected verifies that a negative
// overlap_days value is rejected with a 400.
func TestHandleRotateSigningCert_NegativeOverlapRejected(t *testing.T) {
	server, certMgr, _ := setupRotationTestServer(t)

	issuedCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(issuedCert.CertificatePEM)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/certificates/signing/rotate",
		strings.NewReader(`{"overlap_days":-1}`))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// setupProvisionTestServer creates a server wired with a real cert manager and a real
// certificate provisioning service. The cert manager's storage path is returned so a
// test can inject a storage fault (the provisioning service writes every issued cert
// through the cert store).
func setupProvisionTestServer(t *testing.T) (*Server, *cert.Manager, string) {
	t.Helper()
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	logger := logging.NewNoopLogger()
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

	// Cert manager with a test-owned storage path (newTestCertManager hides its
	// t.TempDir()), so the storage-fault test can make the cert store unwritable.
	certStoragePath := filepath.Join(t.TempDir(), "certs")
	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certStoragePath,
		CAConfig: &cert.CAConfig{
			Organization: "Test CFGMS",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	provisioningSvc := service.NewCertificateProvisioningService(certMgr, logger)

	server, err := New(
		cfg, logger, controllerService, configService,
		provisioningSvc, rbacService, certMgr, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr, nil, nil, nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := server.Close(closeCtx); closeErr != nil {
			t.Errorf("server.Close: %v", closeErr)
		}
	})

	return server, certMgr, certStoragePath
}

// newAdminPeerCert issues an mTLS admin certificate from certMgr and returns it parsed,
// ready to attach to a request as a TLS peer certificate. certificate:provision requires
// AssuranceStrong (assurance.go), so only an admin-marked client cert reaches the handler.
func newAdminPeerCert(t *testing.T, certMgr *cert.Manager) *x509.Certificate {
	t.Helper()
	issued, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	parsed, err := cert.ParseCertificateFromPEM(issued.CertificatePEM)
	require.NoError(t, err)
	return parsed
}

// postProvision sends POST /api/v1/certificates/provision authenticated with the given
// admin peer certificate and returns the recorder.
func postProvision(server *Server, peer *x509.Certificate, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/v1/certificates/provision", strings.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

// TestHandleProvisionCertificate_NilService_Returns503 verifies the handler reports the
// provisioning service as unavailable rather than panicking when it is not wired.
func TestHandleProvisionCertificate_NilService_Returns503(t *testing.T) {
	server, certMgr := setupCertTestServer(t) // certProvisioningService == nil
	peer := newAdminPeerCert(t, certMgr)

	rec := postProvision(server, peer, `{"steward_id":"steward-001"}`)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "SERVICE_UNAVAILABLE", errResp.Error.Code)
}

// TestHandleProvisionCertificate_InvalidJSON_Returns400 verifies a malformed body is
// rejected before any certificate is issued.
func TestHandleProvisionCertificate_InvalidJSON_Returns400(t *testing.T) {
	server, certMgr, _ := setupProvisionTestServer(t)
	peer := newAdminPeerCert(t, certMgr)

	before, err := certMgr.ListCertificates()
	require.NoError(t, err)

	rec := postProvision(server, peer, `{"steward_id":`)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_JSON", errResp.Error.Code)

	after, err := certMgr.ListCertificates()
	require.NoError(t, err)
	assert.Len(t, after, len(before), "no certificate may be issued for a malformed request")
}

// TestHandleProvisionCertificate_MissingStewardID_Returns400 verifies the required-field
// check: a syntactically valid body with no steward_id is rejected with MISSING_STEWARD_ID.
func TestHandleProvisionCertificate_MissingStewardID_Returns400(t *testing.T) {
	server, certMgr, _ := setupProvisionTestServer(t)
	peer := newAdminPeerCert(t, certMgr)

	rec := postProvision(server, peer, `{"common_name":"steward-001.example.com"}`)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "MISSING_STEWARD_ID", errResp.Error.Code)
}

// TestHandleProvisionCertificate_Success_Returns201 verifies the success path: 201 with a
// usable certificate/key/CA triple, and the issued cert recorded in the cert manager.
// common_name is omitted so the steward_id default is exercised.
func TestHandleProvisionCertificate_Success_Returns201(t *testing.T) {
	server, certMgr, _ := setupProvisionTestServer(t)
	peer := newAdminPeerCert(t, certMgr)

	rec := postProvision(server, peer, `{"steward_id":"steward-prov-01","validity_days":30}`)

	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	var resp struct {
		Data CertificateProvisionResult `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	result := resp.Data
	assert.NotEmpty(t, result.SerialNumber)

	issued, err := cert.ParseCertificateFromPEM([]byte(result.CertificatePEM))
	require.NoError(t, err, "certificate_pem must be a parseable certificate")
	assert.Equal(t, "steward-prov-01", issued.Subject.CommonName,
		"common_name must default to steward_id when omitted")
	assert.WithinDuration(t, time.Now().AddDate(0, 0, 30), issued.NotAfter, 24*time.Hour,
		"validity_days from the request must be honoured")
	assert.Equal(t, result.SerialNumber, issued.SerialNumber.String())
	assert.False(t, result.ExpiresAt.IsZero(), "expires_at must be populated")

	// The private key and CA cert must both be usable material, not placeholders.
	keyPair, err := tls.X509KeyPair([]byte(result.CertificatePEM), []byte(result.PrivateKeyPEM))
	require.NoError(t, err, "certificate_pem and private_key_pem must form a usable key pair")
	assert.NotNil(t, keyPair.PrivateKey)
	_, err = cert.ParseCertificateFromPEM([]byte(result.CACertificatePEM))
	require.NoError(t, err, "ca_certificate_pem must be a parseable certificate")

	// The issued cert must be recorded in the cert manager under the steward's ID.
	stored, err := certMgr.GetCertificateByCommonName("steward-prov-01")
	require.NoError(t, err)
	require.Len(t, stored, 1)
	assert.Equal(t, result.SerialNumber, stored[0].SerialNumber)
	assert.Equal(t, "steward-prov-01", stored[0].ClientID)
}

// TestHandleProvisionCertificate_ExplicitCommonName_Returns201 verifies an explicit
// common_name is used instead of the steward_id default.
func TestHandleProvisionCertificate_ExplicitCommonName_Returns201(t *testing.T) {
	server, certMgr, _ := setupProvisionTestServer(t)
	peer := newAdminPeerCert(t, certMgr)

	rec := postProvision(server, peer,
		`{"steward_id":"steward-prov-02","common_name":"steward-prov-02.example.com","organization":"Example Org"}`)

	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	var resp struct {
		Data CertificateProvisionResult `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	issued, err := cert.ParseCertificateFromPEM([]byte(resp.Data.CertificatePEM))
	require.NoError(t, err)
	assert.Equal(t, "steward-prov-02.example.com", issued.Subject.CommonName)
	assert.Contains(t, issued.Subject.Organization, "Example Org")
}

// TestHandleProvisionCertificate_ProvisioningFailure_Returns500 verifies that a real
// failure inside the provisioning service surfaces as 500 with no internal detail in the
// response body. The fault is injected by replacing the cert store's storage directory
// with a regular file, so persisting the issued certificate fails (ENOTDIR) — the CA
// itself is already loaded in memory and still signs successfully.
func TestHandleProvisionCertificate_ProvisioningFailure_Returns500(t *testing.T) {
	server, certMgr, certStoragePath := setupProvisionTestServer(t)
	peer := newAdminPeerCert(t, certMgr)

	require.NoError(t, os.RemoveAll(certStoragePath))
	require.NoError(t, os.WriteFile(certStoragePath, []byte("not a directory"), 0o600))

	rec := postProvision(server, peer, `{"steward_id":"steward-prov-03"}`)

	require.Equal(t, http.StatusInternalServerError, rec.Code, "body: %s", rec.Body.String())

	body := rec.Body.String()
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(strings.NewReader(body)).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
	assert.Equal(t, "Failed to provision certificate", errResp.Error.Message)
	assert.NotContains(t, body, certStoragePath,
		"the error response must not disclose internal filesystem paths")
	assert.NotContains(t, body, "BEGIN",
		"no certificate material may be returned on the failure path")
}
