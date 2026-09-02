// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Tests for handleUpdateStewardConfig validation-vs-storage error routing (Issue #2482).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	storageifaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// storeWriteFailingConfigStore is a real ConfigStore whose StoreConfig always
// fails, simulating a durable-storage write error without touching read paths.
// All other operations delegate to the embedded real store.
type storeWriteFailingConfigStore struct {
	cfgconfig.ConfigStore
}

func (f *storeWriteFailingConfigStore) StoreConfig(context.Context, *cfgconfig.ConfigEntry) error {
	return errors.New("storage backend unavailable")
}

// useStorageWriteFailingConfigService replaces the server's config service with one
// backed by a store that fails only on StoreConfig writes. This lets tests exercise
// the 500 STORAGE_ERROR branch in handleUpdateStewardConfig without mocking.
func useStorageWriteFailingConfigService(t *testing.T, server *Server) {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	composite := storageifaces.NewStorageManagerFromStores(
		&storeWriteFailingConfigStore{ConfigStore: sm.GetConfigStore()},
		sm.GetAuditStore(),
		sm.GetRBACStore(),
		sm.GetTenantStore(),
		sm.GetClientTenantStore(),
		sm.GetRegistrationTokenStore(),
		sm.GetSessionStore(),
		sm.GetStewardStore(),
		sm.GetCommandStore(),
		sm.GetTriggerStore(),
		sm.GetPushStore(),
	)
	logger := logging.NewNoopLogger()
	server.configService = service.NewConfigurationServiceV2(logger, composite, service.NewControllerService(logger))
}

// TestHandleUpdateStewardConfig_InvalidResourceName_Returns400 verifies that a config
// upload with an invalid resource name (dot in name, e.g. "docker.io") returns HTTP 400
// with code VALIDATION_ERROR and the specific failed-field detail in the message, not
// 500 STORAGE_ERROR (Issue #2482).
func TestHandleUpdateStewardConfig_InvalidResourceName_Returns400(t *testing.T) {
	server := setupTestServer(t)

	body := []byte(`
steward:
  id: test-steward-invalid-rsrc
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: docker.io
    module: file
    config:
      path: /tmp/test
      content: x
`)

	req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-invalid-rsrc/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"validation failure must return 400, not 5xx; body: %s", rec.Body.String())
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "VALIDATION_ERROR", resp.Error.Code,
		"code must be VALIDATION_ERROR, not STORAGE_ERROR")
	assert.Contains(t, resp.Error.Message, "docker.io",
		"message must name the invalid resource so the client can diagnose without server logs")
}

// TestHandleUpdateStewardConfig_ServiceValidationFailure_Returns400 verifies the
// errors.As(err, &ve) routing branch: a config whose resource names all pass the
// handler-level identifierRegex but which fails a service-layer validator (two
// resources sharing the same name -> DUPLICATE_RESOURCE_NAME) makes SetConfiguration
// itself return a *service.ValidationFailedError. The handler must translate that
// into HTTP 400 VALIDATION_ERROR, not 500 STORAGE_ERROR (Issue #2482).
func TestHandleUpdateStewardConfig_ServiceValidationFailure_Returns400(t *testing.T) {
	server := setupTestServer(t)

	// Both resource names are individually valid (pass the handler regex) but
	// collide, which only the service-layer validator detects.
	body := []byte(`
steward:
  id: test-steward-dup-rsrc
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: duplicated-name
    module: file
    config:
      path: /tmp/a
      content: a
  - name: duplicated-name
    module: file
    config:
      path: /tmp/b
      content: b
`)

	req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-dup-rsrc/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"service-layer validation failure must return 400, not 5xx; body: %s", rec.Body.String())
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "VALIDATION_ERROR", resp.Error.Code,
		"code must be VALIDATION_ERROR, not STORAGE_ERROR")
	assert.Contains(t, resp.Error.Message, "validation failed",
		"message must carry the service-layer validation summary")
}

// TestHandleUpdateStewardConfig_ValidConfig_Returns200 verifies that a well-formed
// config upload succeeds (Issue #2482 — regression guard that the fix does not
// accidentally block valid uploads).
func TestHandleUpdateStewardConfig_ValidConfig_Returns200(t *testing.T) {
	server := setupTestServer(t)

	body := []byte(`
steward:
  id: test-steward-valid
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: my-managed-file
    module: file
    config:
      path: /tmp/managed
      content: hello
`)

	req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-valid/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"valid config must be accepted; body: %s", rec.Body.String())
}

// TestProductionBuildRejectsTestConfigOverwrite is the regression guard for the
// unauthenticated base-router overwrite reproduced during the public-beta audit.
// Test administration routes must be absent from a normal controller build even
// when the historical runtime opt-in environment variable is set.
func TestProductionBuildRejectsTestConfigOverwrite(t *testing.T) {
	server := setupTestServer(t)
	t.Setenv("CFGMS_ENABLE_TEST_ENDPOINTS", "true")
	const stewardID = "security-audit-steward"
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, "test-tenant", "addr", "active"))

	readKey := NewEphemeralTestKey(t, server, []string{"steward:read-config"}, "test-tenant", 5*time.Minute)

	configBody := func(content string) []byte {
		return []byte(`
steward:
  id: security-audit-steward
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: audit-canary
    module: file
    config:
      path: /tmp/audit-canary
      content: ` + content + "\n")
	}

	seedReq := makeAdminRequest(t, http.MethodPut, "/api/v1/stewards/"+stewardID+"/config", bytes.NewReader(configBody("authorized-original")))
	seedReq.Header.Set("Content-Type", "application/yaml")
	seedRec := httptest.NewRecorder()
	server.router.ServeHTTP(seedRec, seedReq)
	require.Equal(t, http.StatusOK, seedRec.Code, "authorized seed write failed: %s", seedRec.Body.String())

	overwriteReq := httptest.NewRequest(http.MethodPut, "/api/v1/test/stewards/"+stewardID+"/config", bytes.NewReader(configBody("unauthenticated-overwrite")))
	overwriteReq.Header.Set("Content-Type", "application/yaml")
	overwriteRec := httptest.NewRecorder()
	server.router.ServeHTTP(overwriteRec, overwriteReq)
	require.Equal(t, http.StatusNotFound, overwriteRec.Code,
		"production builds must not register test routes, regardless of environment: %s", overwriteRec.Body.String())

	readReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+stewardID+"/config", nil)
	readReq.Header.Set("X-API-Key", readKey)
	readRec := httptest.NewRecorder()
	server.router.ServeHTTP(readRec, readReq)
	require.Equal(t, http.StatusOK, readRec.Code, "authenticated readback failed: %s", readRec.Body.String())
	assert.Contains(t, readRec.Body.String(), "authorized-original",
		"rejected request must leave the authorized configuration intact")
	assert.NotContains(t, readRec.Body.String(), "unauthenticated-overwrite",
		"rejected request must not mutate durable configuration")
}

// TestHandleUpdateStewardConfig_StorageError_Returns500 verifies that a genuine
// storage-layer failure (not a validation failure) still returns HTTP 500 with
// code STORAGE_ERROR after the Issue #2482 fix — i.e. the fix does not convert
// real storage errors into 400s (AC1 regression guard, [REQUIRED TEST]).
func TestHandleUpdateStewardConfig_StorageError_Returns500(t *testing.T) {
	server := setupTestServer(t)
	useStorageWriteFailingConfigService(t, server)

	// Submit a config that passes all validation (valid resource name, valid YAML,
	// required fields present) so the only failure is the underlying StoreConfig call.
	body := []byte(`
steward:
  id: test-steward-storage-err
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: valid-resource
    module: file
    config:
      path: /tmp/test
      content: hello
`)

	req := httptest.NewRequest("PUT", "/api/v1/stewards/test-steward-storage-err/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceStrong, TenantID: "test-tenant", Permissions: []string{"steward:write-config"}})
	req = withVars(req, map[string]string{"id": "test-steward-storage-err"})
	rec := httptest.NewRecorder()
	server.handleUpdateStewardConfig(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"storage failure must return 500, not 400; body: %s", rec.Body.String())
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "STORAGE_ERROR", resp.Error.Code,
		"storage failure must report STORAGE_ERROR, not VALIDATION_ERROR")
}

// TestHandleUpdateStewardConfig_WithCommandStore_ReferencesDeliveryRecord
// verifies Issue #3757 (ADR-031 Decision 2): "status: stored responses that
// imply more than storage are replaced by responses that reference the
// trackable delivery record." When a commandStore is configured, a successful
// config update must return a command_id (and delivery_status) instead of a
// bare "status": "stored", and the referenced record must actually exist and
// be readable back through the store.
func TestHandleUpdateStewardConfig_WithCommandStore_ReferencesDeliveryRecord(t *testing.T) {
	server := setupTestServer(t)
	storageManager := pkgtesting.SetupTestStorage(t)
	commandStore := storageManager.GetCommandStore()
	require.NotNil(t, commandStore)
	server.SetCommandStore(commandStore)

	body := []byte(`
steward:
  id: test-steward-delivery-record
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: my-managed-file
    module: file
    config:
      path: /tmp/managed
      content: hello
`)

	req := httptest.NewRequest("PUT", "/api/v1/stewards/test-steward-delivery-record/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceStrong, TenantID: "test-tenant", Permissions: []string{"steward:write-config"}})
	req = withVars(req, map[string]string{"id": "test-steward-delivery-record"})
	rec := httptest.NewRecorder()
	server.handleUpdateStewardConfig(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var envelope APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&envelope))
	resp, ok := envelope.Data.(map[string]any)
	require.True(t, ok, "response data must be a JSON object")
	_, hasBareStatus := resp["status"]
	assert.False(t, hasBareStatus,
		"response must not fall back to a bare status: stored when a commandStore is configured")
	commandID, _ := resp["command_id"].(string)
	require.NotEmpty(t, commandID, "response must reference a trackable delivery record")
	assert.NotEmpty(t, resp["delivery_status"])

	got, err := commandStore.GetCommandRecord(context.Background(), commandID)
	require.NoError(t, err, "the referenced command_id must be a real, readable record")
	assert.Equal(t, "test-steward-delivery-record", got.StewardID)
	assert.Equal(t, "test-tenant", got.TenantID)
}

// TestHandleUpdateStewardConfig_NoCommandStore_FallsBackToBareStatus is the
// backward-compatibility regression guard: deployments without a commandStore
// configured keep the original bare "status": "stored" response shape rather
// than claiming a trackable record that does not exist.
func TestHandleUpdateStewardConfig_NoCommandStore_FallsBackToBareStatus(t *testing.T) {
	server := setupTestServer(t) // commandStore is nil here

	body := []byte(`
steward:
  id: test-steward-no-command-store
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: my-managed-file
    module: file
    config:
      path: /tmp/managed
      content: hello
`)

	req := httptest.NewRequest("PUT", "/api/v1/stewards/test-steward-no-command-store/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceStrong, TenantID: "test-tenant", Permissions: []string{"steward:write-config"}})
	req = withVars(req, map[string]string{"id": "test-steward-no-command-store"})
	rec := httptest.NewRecorder()
	server.handleUpdateStewardConfig(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var envelope APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&envelope))
	resp, ok := envelope.Data.(map[string]any)
	require.True(t, ok, "response data must be a JSON object")
	assert.Equal(t, "stored", resp["status"])
	_, hasCommandID := resp["command_id"]
	assert.False(t, hasCommandID, "no commandStore means no delivery record to reference")
}

// validCfgUploadBody returns a minimal valid YAML StewardConfig body for stewardID,
// reused across the tenant-scope tests below (Issue #3792).
func validCfgUploadBody(stewardID string) []byte {
	return []byte(`
steward:
  id: ` + stewardID + `
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: my-managed-file
    module: file
    config:
      path: /tmp/managed
      content: hello
`)
}

// TestHandleUpdateStewardConfig_CrossTenant_Returns404 is the [REQUIRED TEST] for
// Issue #3792: a caller scoped to tenant "tenant-a" must not be able to push config
// to a steward registered under a disjoint tenant "tenant-b" — rejected with 404
// (not 403, to avoid disclosing that the steward exists) and never applied.
func TestHandleUpdateStewardConfig_CrossTenant_Returns404(t *testing.T) {
	server := setupTestServer(t)
	const stewardID = "cross-tenant-steward"
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, "tenant-b", "addr", "active"))

	body := validCfgUploadBody(stewardID)
	req := httptest.NewRequest("PUT", "/api/v1/stewards/"+stewardID+"/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	req = withPrincipal(req, &Principal{ID: "scoped-admin", Assurance: session.AssuranceStrong, TenantID: "tenant-a", Permissions: []string{"steward:write-config"}})
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleUpdateStewardConfig(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code,
		"a caller scoped to tenant-a must not reach a steward in tenant-b; body: %s", rec.Body.String())
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "STEWARD_NOT_FOUND", resp.Error.Code)

	// The config must never have been applied: a same-tenant admin reading it back
	// must not see the cross-tenant write's content.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+stewardID+"/config", nil)
	getReq = withPrincipal(getReq, &Principal{ID: "admin", Assurance: session.AssuranceStrong, ImplicitAdmin: true})
	getReq = withVars(getReq, map[string]string{"id": stewardID})
	getRec := httptest.NewRecorder()
	server.handleGetStewardConfig(getRec, getReq)
	assert.NotEqual(t, http.StatusOK, getRec.Code,
		"rejected cross-tenant push must not have stored any configuration for the steward")
}

// TestHandleUpdateStewardConfig_SameTenantSubtree_Returns200 is the [REQUIRED TEST]
// for Issue #3792: a caller scoped to "tenant-a" can still push config to a steward
// registered in its own tenant subtree "tenant-a/child" (not just an exact match).
func TestHandleUpdateStewardConfig_SameTenantSubtree_Returns200(t *testing.T) {
	server := setupTestServer(t)
	const stewardID = "subtree-steward"
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, "tenant-a/child", "addr", "active"))

	body := validCfgUploadBody(stewardID)
	req := httptest.NewRequest("PUT", "/api/v1/stewards/"+stewardID+"/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	req = withPrincipal(req, &Principal{ID: "scoped-admin", Assurance: session.AssuranceStrong, TenantID: "tenant-a", Permissions: []string{"steward:write-config"}})
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleUpdateStewardConfig(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"a caller scoped to tenant-a must reach a steward in tenant-a/child; body: %s", rec.Body.String())
}

// TestHandleUpdateStewardConfig_APIKeyRefusedInsufficientAssurance is the
// [REQUIRED TEST] for Issue #3792: steward:write-config is root-equivalent on the
// target host, so an API-key principal (AssuranceMachine) holding the permission
// must still be refused — API keys can never satisfy AssuranceStrong (they cannot
// step up), so this must be a plain 403, not a step-up challenge.
func TestHandleUpdateStewardConfig_APIKeyRefusedInsufficientAssurance(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:write-config"}, "test-tenant", 5*time.Minute)

	body := validCfgUploadBody("api-key-refused-steward")
	req := httptest.NewRequest("PUT", "/api/v1/stewards/api-key-refused-steward/config", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code,
		"an API-key principal must be refused steward:write-config regardless of permission grant; body: %s", rec.Body.String())
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "INSUFFICIENT_PERMISSIONS", resp.Error.Code)
}
