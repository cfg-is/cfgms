// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// setupCertTestServer creates a server wired with a real cert manager for certificate handler tests.
func setupCertTestServer(t *testing.T) (*Server, *cert.Manager) {
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

	certMgr := newTestCertManager(t)

	server, err := New(
		cfg, logger, controllerService, configService,
		nil, rbacService, certMgr, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr,
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
