// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3578: tests for mTLS admin certificate binding handlers.
package api

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// setupCertBindingServer creates a server wired with a real cert manager for the
// cert-binding handler tests. Uses the same composition as setupCertTestServer.
func setupCertBindingServer(t *testing.T) (*Server, *cert.Manager) {
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
		nil, nil, nil, "", nil, auditMgr, nil, nil, nil,
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

// strongPrincipal returns a Principal with AssuranceStrong for mutating operations.
func strongPrincipal() *Principal {
	return &Principal{
		ID:        "test-mtls-strong",
		Name:      "mtls-admin:strong",
		Assurance: session.AssuranceStrong,
	}
}

// bindCertReq sends a POST .../certs/bind request and returns the recorder.
func bindCertReq(t *testing.T, server *Server, principal *Principal, username string, body BindCertRequest) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/accounts/"+username+"/certs/bind", bytes.NewReader(payload))
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username})
	rec := httptest.NewRecorder()
	server.handleBindCert(rec, req)
	return rec
}

// listCertsReq sends a GET .../certs request and returns the recorder.
func listCertsReq(t *testing.T, server *Server, principal *Principal, username string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts/"+username+"/certs", nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username})
	rec := httptest.NewRecorder()
	server.handleListCertBindings(rec, req)
	return rec
}

// revokeCertBindingReq sends a POST .../certs/revoke/{serial} request.
func revokeCertBindingReq(t *testing.T, server *Server, principal *Principal, username, serial string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/accounts/"+username+"/certs/revoke/"+serial, nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username, "serial": serial})
	rec := httptest.NewRecorder()
	server.handleRevokeCertBinding(rec, req)
	return rec
}

// provisionTestClientCert issues a real client certificate via certMgr and returns its serial.
func provisionTestClientCert(t *testing.T, certMgr *cert.Manager, commonName string) string {
	t.Helper()
	clientCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		ClientID:   commonName,
		CommonName: commonName,
	})
	require.NoError(t, err)
	return clientCert.SerialNumber
}

// createTestAccount creates a web-admin account and asserts 201 Created.
func createTestAccount(t *testing.T, server *Server, username string) {
	t.Helper()
	rec := postAccount(t, server, strongPrincipal(), AccountRequest{
		Username: username,
		TenantID: "default",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "create account %s: %s", username, rec.Body.String())
}

// TestHandleCertBinding_BindSuccess verifies the happy path: bind a certificate serial
// to an account returns 201 Created with the binding metadata.
func TestHandleCertBinding_BindSuccess(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	serial := provisionTestClientCert(t, certMgr, "alice-laptop")

	rec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial:      serial,
		Fingerprint: "sha256:abc123",
		Label:       "alice laptop",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "bind: %s", rec.Body.String())

	var resp struct {
		Data CertBindingInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, serial, resp.Data.Serial)
	assert.Equal(t, "sha256:abc123", resp.Data.Fingerprint)
	assert.Equal(t, "alice laptop", resp.Data.Label)
	assert.False(t, resp.Data.BoundAt.IsZero())
}

// TestHandleCertBinding_ListSuccess verifies that bound certificates appear in the list response.
func TestHandleCertBinding_ListSuccess(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	serial := provisionTestClientCert(t, certMgr, "alice-laptop")

	rec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial:      serial,
		Fingerprint: "sha256:abc123",
		Label:       "alice laptop",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	listRec := listCertsReq(t, server, testAdminPrincipal(), "alice")
	require.Equal(t, http.StatusOK, listRec.Code, "list: %s", listRec.Body.String())

	var resp struct {
		Data []CertBindingInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(listRec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, serial, resp.Data[0].Serial)
	assert.Equal(t, "alice laptop", resp.Data[0].Label)
}

// TestHandleCertBinding_ListEmpty verifies that the list endpoint returns an empty slice
// (not nil/null) when no certificates are bound.
func TestHandleCertBinding_ListEmpty(t *testing.T) {
	server, _ := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	rec := listCertsReq(t, server, testAdminPrincipal(), "alice")
	require.Equal(t, http.StatusOK, rec.Code, "list: %s", rec.Body.String())

	var resp struct {
		Data []CertBindingInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

// TestHandleCertBinding_RevokeActuallyRevokes verifies that handleRevokeCertBinding removes
// the binding AND calls certManager.Revoke — asserting IsRevoked(serial) is true afterward.
func TestHandleCertBinding_RevokeActuallyRevokes(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	serial := provisionTestClientCert(t, certMgr, "alice-laptop")

	// Bind the certificate first.
	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial:      serial,
		Fingerprint: "sha256:abc123",
		Label:       "alice laptop",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code)
	assert.False(t, certMgr.IsRevoked(serial), "cert must not be revoked before revoke call")

	// Revoke the binding.
	revokeRec := revokeCertBindingReq(t, server, strongPrincipal(), "alice", serial)
	require.Equal(t, http.StatusOK, revokeRec.Code, "revoke: %s", revokeRec.Body.String())

	// Assert the certificate is actually revoked via the cert manager.
	assert.True(t, certMgr.IsRevoked(serial), "cert must be revoked via certManager after handleRevokeCertBinding")

	// Assert the binding is gone from the list.
	listRec := listCertsReq(t, server, testAdminPrincipal(), "alice")
	require.Equal(t, http.StatusOK, listRec.Code)
	var listResp struct {
		Data []CertBindingInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(listRec.Body).Decode(&listResp))
	assert.Empty(t, listResp.Data, "binding must be removed from the account after revoke")
}

// TestHandleCertBinding_CrossAccountConflict verifies that binding a serial that is already
// bound to account A to account B returns 409 CONFLICT.
func TestHandleCertBinding_CrossAccountConflict(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	createTestAccount(t, server, "bob")
	serial := provisionTestClientCert(t, certMgr, "shared-serial")

	// Bind serial to alice.
	rec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial: serial,
		Label:  "alice copy",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "alice bind: %s", rec.Body.String())

	// Try to bind the same serial to bob → 409.
	rec2 := bindCertReq(t, server, strongPrincipal(), "bob", BindCertRequest{
		Serial: serial,
		Label:  "bob copy",
	})
	assert.Equal(t, http.StatusConflict, rec2.Code, "cross-account bind must return 409: %s", rec2.Body.String())
}

// TestHandleCertBinding_RevokeNonexistent verifies that revoking a serial that is not bound
// to the account returns 404 NOT FOUND.
func TestHandleCertBinding_RevokeNonexistent(t *testing.T) {
	server, _ := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	rec := revokeCertBindingReq(t, server, strongPrincipal(), "alice", "not-bound-serial")
	assert.Equal(t, http.StatusNotFound, rec.Code, "revoke nonexistent: %s", rec.Body.String())
}

// TestHandleCertBinding_DuplicateSerialOnSameAccount verifies that binding the same serial
// to the same account twice returns 409.
func TestHandleCertBinding_DuplicateSerialOnSameAccount(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	serial := provisionTestClientCert(t, certMgr, "alice-laptop")

	rec1 := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: serial})
	require.Equal(t, http.StatusCreated, rec1.Code)

	rec2 := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: serial})
	assert.Equal(t, http.StatusConflict, rec2.Code, "duplicate bind on same account: %s", rec2.Body.String())
}

// TestHandleCertBinding_ConcurrentBindSameSerial verifies the race condition is closed:
// two concurrent handleBindCert calls for the same serial on two different accounts must
// result in exactly one success (201) and one conflict (409). No interleaving should leave
// the serial bound to both accounts simultaneously.
func TestHandleCertBinding_ConcurrentBindSameSerial(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	createTestAccount(t, server, "bob")
	serial := provisionTestClientCert(t, certMgr, "contested-cert")

	// Pre-load both accounts into the in-memory cache so the concurrent scan hits cached entries.
	_, err := server.getAccount(context.Background(), "alice")
	require.NoError(t, err)
	_, err = server.getAccount(context.Background(), "bob")
	require.NoError(t, err)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses []int
	)
	for _, username := range []string{"alice", "bob"} {
		username := username
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := bindCertReq(t, server, strongPrincipal(), username, BindCertRequest{
				Serial: serial,
				Label:  username + " cert",
			})
			mu.Lock()
			statuses = append(statuses, rec.Code)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Exactly one must have succeeded (201) and one must have conflicted (409).
	require.Len(t, statuses, 2)
	created := 0
	conflict := 0
	for _, s := range statuses {
		switch s {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflict++
		}
	}
	assert.Equal(t, 1, created, "exactly one goroutine must have created the binding; statuses=%v", statuses)
	assert.Equal(t, 1, conflict, "exactly one goroutine must have received 409; statuses=%v", statuses)

	// Verify the serial appears in exactly one account's binding list.
	aliceBindings := getCertBindings(t, server, "alice")
	bobBindings := getCertBindings(t, server, "bob")
	aliceHas := containsSerial(aliceBindings, serial)
	bobHas := containsSerial(bobBindings, serial)
	assert.True(t, aliceHas != bobHas, "serial must be bound to exactly one account; alice=%v bob=%v", aliceHas, bobHas)
}

// getCertBindings lists bindings for username and returns the parsed slice.
func getCertBindings(t *testing.T, server *Server, username string) []CertBindingInfo {
	t.Helper()
	rec := listCertsReq(t, server, testAdminPrincipal(), username)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []CertBindingInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	return resp.Data
}

// containsSerial reports whether any binding in bindings has the given serial.
func containsSerial(bindings []CertBindingInfo, serial string) bool {
	for _, b := range bindings {
		if b.Serial == serial {
			return true
		}
	}
	return false
}

// TestHandleCertBinding_AccountNotFound verifies that operating on a nonexistent account
// returns 404 for all three endpoints.
func TestHandleCertBinding_AccountNotFound(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	serial := provisionTestClientCert(t, certMgr, "ghost-cert")

	bindRec := bindCertReq(t, server, strongPrincipal(), "ghost", BindCertRequest{Serial: serial})
	assert.Equal(t, http.StatusNotFound, bindRec.Code, "bind on nonexistent account: %s", bindRec.Body.String())

	listRec := listCertsReq(t, server, testAdminPrincipal(), "ghost")
	assert.Equal(t, http.StatusNotFound, listRec.Code, "list on nonexistent account: %s", listRec.Body.String())

	revokeRec := revokeCertBindingReq(t, server, strongPrincipal(), "ghost", serial)
	assert.Equal(t, http.StatusNotFound, revokeRec.Code, "revoke on nonexistent account: %s", revokeRec.Body.String())
}

// TestHandleCertBinding_LabelSanitized verifies that CR/LF characters in Label are stripped
// (go/log-injection CWE-117 defence) and the sanitized value is persisted.
func TestHandleCertBinding_LabelSanitized(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	serial := provisionTestClientCert(t, certMgr, "alice-laptop2")

	rec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial: serial,
		Label:  "alice\r\nlaptop",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	var resp struct {
		Data CertBindingInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "alicelaptop", resp.Data.Label, "CR/LF must be stripped from label")
}

// TestHandleCertBinding_BindMissingSerial verifies that a request with no serial is rejected 400.
func TestHandleCertBinding_BindMissingSerial(t *testing.T) {
	server, _ := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	rec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Label: "no serial"})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "missing serial must return 400: %s", rec.Body.String())
}

// TestHandleCertBinding_InvalidSerialRejected verifies that path-traversal payloads in the
// serial field are rejected at ingress (go/path-injection defence, Issue #3578 security review).
func TestHandleCertBinding_InvalidSerialRejected(t *testing.T) {
	server, _ := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	badSerials := []string{
		"../../etc/passwd",
		"../secret",
		"serial with spaces",
		strings.Repeat("A", 41), // exceeds 40-char cap
	}
	for _, bad := range badSerials {
		rec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: bad})
		assert.Equal(t, http.StatusBadRequest, rec.Code,
			"serial %q must be rejected: %s", bad, rec.Body.String())
	}
}

// TestHandleCertBinding_BindCapEnforced verifies that binding more than
// maxCertBindingsPerAccount certificates to a single account is rejected.
func TestHandleCertBinding_BindCapEnforced(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	for i := range maxCertBindingsPerAccount {
		serial := provisionTestClientCert(t, certMgr, "alice-cap-cert")
		rec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: serial})
		require.Equal(t, http.StatusCreated, rec.Code, "bind %d: %s", i, rec.Body.String())
	}

	// One more should be rejected.
	extra := provisionTestClientCert(t, certMgr, "alice-cap-extra")
	rec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: extra})
	assert.Equal(t, http.StatusConflict, rec.Code,
		"binding beyond cap must return 409: %s", rec.Body.String())
}

// TestHandleCertBinding_TenantIsolation verifies that handlers deny access to accounts
// outside the caller's tenant subtree.
func TestHandleCertBinding_TenantIsolation(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)

	// Create an account in the "default" tenant (done by createTestAccount).
	createTestAccount(t, server, "alice")
	serial := provisionTestClientCert(t, certMgr, "alice-tenant-test")

	// Bind alice's cert first using an admin principal (no tenant restriction).
	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: serial})
	require.Equal(t, http.StatusCreated, bindRec.Code)

	// A principal scoped to a sibling tenant must be denied access.
	siblingTenantPrincipal := &Principal{
		ID:        "sibling-user",
		Name:      "api-key:sibling",
		Assurance: session.AssuranceStrong,
		TenantID:  "sibling-tenant",
	}

	withTenant := func(r *http.Request, p *Principal) *http.Request {
		// Inject the caller TenantID into the context the way authenticationMiddleware does.
		ctx := context.WithValue(r.Context(), ctxkeys.TenantID, p.TenantID)
		return r.WithContext(ctx)
	}

	// Bind endpoint.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/accounts/alice/certs/bind",
		bytes.NewReader([]byte(`{"serial":"newserial"}`)))
	req = withPrincipal(req, siblingTenantPrincipal)
	req = withTenant(req, siblingTenantPrincipal)
	req = withVars(req, map[string]string{"username": "alice"})
	rec := httptest.NewRecorder()
	server.handleBindCert(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "cross-tenant bind must return 403")

	// List endpoint.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/accounts/alice/certs", nil)
	req = withPrincipal(req, siblingTenantPrincipal)
	req = withTenant(req, siblingTenantPrincipal)
	req = withVars(req, map[string]string{"username": "alice"})
	rec = httptest.NewRecorder()
	server.handleListCertBindings(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "cross-tenant list must return 403")

	// Revoke endpoint.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/accounts/alice/certs/revoke/"+serial, nil)
	req = withPrincipal(req, siblingTenantPrincipal)
	req = withTenant(req, siblingTenantPrincipal)
	req = withVars(req, map[string]string{"username": "alice", "serial": serial})
	rec = httptest.NewRecorder()
	server.handleRevokeCertBinding(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "cross-tenant revoke must return 403")
}

// TestHandleCertBinding_PersistedAcrossReload verifies that a bound certificate survives
// a cache flush and store reload (the binding is durably persisted via persistAccount).
func TestHandleCertBinding_PersistedAcrossReload(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	serial := provisionTestClientCert(t, certMgr, "alice-persist")

	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial:      serial,
		Fingerprint: "sha256:persist",
		Label:       "persistent cert",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code)

	// Flush the cache and reload from store.
	dropAccountCache(server)

	listRec := listCertsReq(t, server, testAdminPrincipal(), "alice")
	require.Equal(t, http.StatusOK, listRec.Code)
	var resp struct {
		Data []CertBindingInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(listRec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, serial, resp.Data[0].Serial)
	assert.Equal(t, "persistent cert", resp.Data[0].Label)
}

// TestHandleCertBinding_RevokeRefusedWithoutCertManager verifies that removing a binding is
// refused with 503 when no certificate manager is configured.
//
// Removing the binding while the certificate stays valid is not a partial success: the
// unbound certificate resolves through extractAdminPrincipal's bootstrap fallback as
// unscoped root, so an unrevokable unbind would widen a tenant-scoped administrator's
// certificate rather than retire it.
func TestHandleCertBinding_RevokeRefusedWithoutCertManager(t *testing.T) {
	server := setupTestServer(t)
	require.Nil(t, server.certManager, "this test requires a server with no cert manager")

	createTestAccount(t, server, "alice")
	const serial = "aabb1122ccdd"

	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial: serial,
		Label:  "no-cert-manager cert",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code, "bind: %s", bindRec.Body.String())

	revokeRec := revokeCertBindingReq(t, server, strongPrincipal(), "alice", serial)
	require.Equal(t, http.StatusServiceUnavailable, revokeRec.Code,
		"unbind must be refused when the cert cannot be revoked: %s", revokeRec.Body.String())
	assert.Contains(t, revokeRec.Body.String(), "CERT_MANAGER_UNAVAILABLE")

	// The binding must be intact — the certificate still resolves through its account.
	listRec := listCertsReq(t, server, testAdminPrincipal(), "alice")
	require.Equal(t, http.StatusOK, listRec.Code)
	var resp struct {
		Data []CertBindingInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(listRec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1, "the binding must survive a refused revoke")
	assert.Equal(t, serial, resp.Data[0].Serial)
}
