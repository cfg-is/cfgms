// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
)

// newFSBlobStore creates a temporary filesystem BlobStore for tests.
// The filesystem provider is registered by providers_test.go (blank import).
func newFSBlobStore(t *testing.T) blob.BlobStore {
	t.Helper()
	store, err := blob.CreateBlobStoreFromConfig("filesystem", map[string]interface{}{"root": t.TempDir()})
	require.NoError(t, err)
	return store
}

// setupTestServerWithBlobStore creates a test server wired with a real filesystem BlobStore.
// setupTestServer (called internally) already isolates CFGMS_SECRETS_REPO_PATH per test.
func setupTestServerWithBlobStore(t *testing.T) (*Server, blob.BlobStore) {
	t.Helper()
	store := newFSBlobStore(t)
	server := setupTestServer(t)
	server.blobStore = store
	return server, store
}

// withTenant returns a copy of r with tenantID injected into the context.
func withTenant(r *http.Request, tenantID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxkeys.TenantID, tenantID))
}

// withVars returns a copy of r with gorilla/mux route variables injected.
// Use this when calling handlers directly (not via the router).
func withVars(r *http.Request, vars map[string]string) *http.Request {
	return mux.SetURLVars(r, vars)
}

// --- Upload ---

// TestHandleUploadInstallerArtifact_ValidInput verifies a PUT with valid platform/arch
// stores the artifact and returns 200 with platform, arch, size, and checksum.
func TestHandleUploadInstallerArtifact_ValidInput(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	body := bytes.NewBufferString("fake-installer-content")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/installer/artifacts/linux/amd64", body)
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"platform": "linux", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleUploadInstallerArtifact(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "expected object in Data")
	assert.Equal(t, "linux", data["platform"])
	assert.Equal(t, "amd64", data["arch"])
	assert.NotEmpty(t, data["checksum"], "checksum must be populated by the provider")
	size, _ := data["size"].(float64)
	assert.Greater(t, size, float64(0), "size must be non-zero")
}

// TestHandleUploadInstallerArtifact_InvalidPlatform verifies that an unknown platform returns 400.
func TestHandleUploadInstallerArtifact_InvalidPlatform(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/installer/artifacts/solaris/amd64",
		bytes.NewBufferString("content"))
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"platform": "solaris", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleUploadInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleUploadInstallerArtifact_InvalidArch verifies that an unknown arch returns 400.
func TestHandleUploadInstallerArtifact_InvalidArch(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/installer/artifacts/linux/mips",
		bytes.NewBufferString("content"))
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"platform": "linux", "arch": "mips"})
	rec := httptest.NewRecorder()

	server.handleUploadInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleUploadInstallerArtifact_NoAuth verifies that a missing tenant ID returns 401.
func TestHandleUploadInstallerArtifact_NoAuth(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/installer/artifacts/linux/amd64",
		bytes.NewBufferString("content"))
	req = withVars(req, map[string]string{"platform": "linux", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleUploadInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- List ---

// TestHandleListInstallerArtifacts_Empty verifies the list endpoint returns an empty array
// when no artifacts have been uploaded.
func TestHandleListInstallerArtifacts_Empty(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/artifacts", nil)
	req = withTenant(req, "test-tenant")
	rec := httptest.NewRecorder()

	server.handleListInstallerArtifacts(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	items, ok := resp.Data.([]interface{})
	require.True(t, ok, "expected array in Data")
	assert.Empty(t, items)
}

// TestHandleListInstallerArtifacts_NoAuth verifies the list endpoint returns 401 without auth.
func TestHandleListInstallerArtifacts_NoAuth(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/artifacts", nil)
	rec := httptest.NewRecorder()

	server.handleListInstallerArtifacts(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- Get single ---

// TestHandleGetInstallerArtifact_NotFound verifies the single-artifact endpoint returns 404
// when the artifact does not exist.
func TestHandleGetInstallerArtifact_NotFound(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/artifacts/windows/amd64", nil)
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"platform": "windows", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleGetInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleGetInstallerArtifact_InvalidPlatform verifies that an unknown platform returns 400.
func TestHandleGetInstallerArtifact_InvalidPlatform(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/artifacts/bsd/amd64", nil)
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"platform": "bsd", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleGetInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleGetInstallerArtifact_InvalidArch verifies that an unknown arch returns 400.
func TestHandleGetInstallerArtifact_InvalidArch(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/artifacts/linux/mips", nil)
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"platform": "linux", "arch": "mips"})
	rec := httptest.NewRecorder()

	server.handleGetInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleGetInstallerArtifact_NoAuth verifies that GET single without auth returns 401.
func TestHandleGetInstallerArtifact_NoAuth(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/artifacts/linux/amd64", nil)
	req = withVars(req, map[string]string{"platform": "linux", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleGetInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- Delete ---

// TestHandleDeleteInstallerArtifact_InvalidPlatform verifies that an unknown platform returns 400.
func TestHandleDeleteInstallerArtifact_InvalidPlatform(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/installer/artifacts/bsd/amd64", nil)
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"platform": "bsd", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleDeleteInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleDeleteInstallerArtifact_InvalidArch verifies that an unknown arch returns 400.
func TestHandleDeleteInstallerArtifact_InvalidArch(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/installer/artifacts/linux/mips", nil)
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"platform": "linux", "arch": "mips"})
	rec := httptest.NewRecorder()

	server.handleDeleteInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleDeleteInstallerArtifact_NoAuth verifies that DELETE without auth returns 401.
func TestHandleDeleteInstallerArtifact_NoAuth(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/installer/artifacts/linux/amd64", nil)
	req = withVars(req, map[string]string{"platform": "linux", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleDeleteInstallerArtifact(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- Round-trip ---

// TestInstallerArtifactRoundTrip is the REQUIRED round-trip test: upload → list → delete.
// Uses a real filesystem BlobStore to verify the full lifecycle with durable storage.
func TestInstallerArtifactRoundTrip(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	const tenantID = "round-trip-tenant"
	const platform = "darwin"
	const arch = "arm64"
	artifactContent := []byte("fake-darwin-arm64-installer-binary")

	// Upload
	uploadReq := httptest.NewRequest(http.MethodPut,
		"/api/v1/installer/artifacts/"+platform+"/"+arch,
		bytes.NewBuffer(artifactContent))
	uploadReq = withTenant(uploadReq, tenantID)
	uploadReq = withVars(uploadReq, map[string]string{"platform": platform, "arch": arch})
	uploadRec := httptest.NewRecorder()

	server.handleUploadInstallerArtifact(uploadRec, uploadReq)
	require.Equal(t, http.StatusOK, uploadRec.Code, "upload should succeed")

	var uploadResp APIResponse
	require.NoError(t, json.Unmarshal(uploadRec.Body.Bytes(), &uploadResp))
	uploadData, ok := uploadResp.Data.(map[string]interface{})
	require.True(t, ok, "upload response should be an object")
	assert.Equal(t, platform, uploadData["platform"])
	assert.Equal(t, arch, uploadData["arch"])
	uploadChecksum, _ := uploadData["checksum"].(string)
	require.NotEmpty(t, uploadChecksum, "checksum must be populated")

	// List
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/installer/artifacts", nil)
	listReq = withTenant(listReq, tenantID)
	listRec := httptest.NewRecorder()

	server.handleListInstallerArtifacts(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code, "list should succeed")

	var listResp APIResponse
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &listResp))
	items, ok := listResp.Data.([]interface{})
	require.True(t, ok, "list response should be an array")
	require.Len(t, items, 1, "expected exactly one artifact after upload")

	item, ok := items[0].(map[string]interface{})
	require.True(t, ok, "expected list element to be an object")
	assert.Equal(t, platform, item["platform"])
	assert.Equal(t, arch, item["arch"])
	assert.Equal(t, uploadChecksum, item["checksum"])

	// Get single
	getReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/installer/artifacts/"+platform+"/"+arch, nil)
	getReq = withTenant(getReq, tenantID)
	getReq = withVars(getReq, map[string]string{"platform": platform, "arch": arch})
	getRec := httptest.NewRecorder()

	server.handleGetInstallerArtifact(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code, "get single should succeed")

	var getResp APIResponse
	require.NoError(t, json.Unmarshal(getRec.Body.Bytes(), &getResp))
	getItem, ok := getResp.Data.(map[string]interface{})
	require.True(t, ok, "get single response should be an object")
	assert.Equal(t, platform, getItem["platform"])
	assert.Equal(t, arch, getItem["arch"])
	assert.Equal(t, uploadChecksum, getItem["checksum"])

	// Delete
	delReq := httptest.NewRequest(http.MethodDelete,
		"/api/v1/installer/artifacts/"+platform+"/"+arch, nil)
	delReq = withTenant(delReq, tenantID)
	delReq = withVars(delReq, map[string]string{"platform": platform, "arch": arch})
	delRec := httptest.NewRecorder()

	server.handleDeleteInstallerArtifact(delRec, delReq)
	require.Equal(t, http.StatusNoContent, delRec.Code, "delete should return 204")

	// Verify list is empty after delete
	listAfterReq := httptest.NewRequest(http.MethodGet, "/api/v1/installer/artifacts", nil)
	listAfterReq = withTenant(listAfterReq, tenantID)
	listAfterRec := httptest.NewRecorder()

	server.handleListInstallerArtifacts(listAfterRec, listAfterReq)
	require.Equal(t, http.StatusOK, listAfterRec.Code)

	var listAfterResp APIResponse
	require.NoError(t, json.Unmarshal(listAfterRec.Body.Bytes(), &listAfterResp))
	afterItems, ok := listAfterResp.Data.([]interface{})
	require.True(t, ok)
	assert.Empty(t, afterItems, "list should be empty after delete")

	// Get after delete should return 404
	getAfterReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/installer/artifacts/"+platform+"/"+arch, nil)
	getAfterReq = withTenant(getAfterReq, tenantID)
	getAfterReq = withVars(getAfterReq, map[string]string{"platform": platform, "arch": arch})
	getAfterRec := httptest.NewRecorder()

	server.handleGetInstallerArtifact(getAfterRec, getAfterReq)
	assert.Equal(t, http.StatusNotFound, getAfterRec.Code, "get after delete should return 404")
}

// TestInstallerArtifactTenantIsolation verifies that tenants cannot see each other's artifacts.
func TestInstallerArtifactTenantIsolation(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	// Upload for tenant-a
	uploadReq := httptest.NewRequest(http.MethodPut,
		"/api/v1/installer/artifacts/linux/amd64",
		bytes.NewBufferString("tenant-a-content"))
	uploadReq = withTenant(uploadReq, "tenant-a")
	uploadReq = withVars(uploadReq, map[string]string{"platform": "linux", "arch": "amd64"})
	uploadRec := httptest.NewRecorder()
	server.handleUploadInstallerArtifact(uploadRec, uploadReq)
	require.Equal(t, http.StatusOK, uploadRec.Code)

	// List as tenant-b — should see nothing
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/installer/artifacts", nil)
	listReq = withTenant(listReq, "tenant-b")
	listRec := httptest.NewRecorder()
	server.handleListInstallerArtifacts(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &resp))
	items, ok := resp.Data.([]interface{})
	require.True(t, ok, "expected array in Data")
	assert.Empty(t, items, "tenant-b must not see tenant-a's artifacts")
}

// TestInstallerArtifactRouterPermissions verifies that the installer routes enforce permissions
// via the full router + auth middleware.
func TestInstallerArtifactRouterPermissions(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	// Generate a key with installer:upload permission.
	uploadKey := NewEphemeralTestKey(t, server, []string{"installer:upload"}, "test-tenant", 5*time.Minute)

	body := bytes.NewBufferString("test content")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/installer/artifacts/linux/amd64", body)
	req.Header.Set("X-API-Key", uploadKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code,
		"installer:upload key should be allowed to PUT an artifact")
}

// TestInstallerArtifactRouterForbiddenWithoutPermission verifies that a key without
// installer:upload cannot upload an artifact.
func TestInstallerArtifactRouterForbiddenWithoutPermission(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	// Generate a key with read-only permission — no installer:upload.
	readKey := NewEphemeralTestKey(t, server, []string{"installer:read"}, "test-tenant", 5*time.Minute)

	body := bytes.NewBufferString("test content")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/installer/artifacts/linux/amd64", body)
	req.Header.Set("X-API-Key", readKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"installer:read key must not be allowed to PUT an artifact")
}

// TestInstallerArtifactRouterDeletePermission verifies that DELETE enforces installer:delete
// via the full router + auth middleware stack.
func TestInstallerArtifactRouterDeletePermission(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	// A key with only installer:read must not be allowed to DELETE.
	readKey := NewEphemeralTestKey(t, server, []string{"installer:read"}, "test-tenant", 5*time.Minute)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/installer/artifacts/linux/amd64", nil)
	req.Header.Set("X-API-Key", readKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"installer:read key must not be allowed to DELETE an artifact")

	// A key with installer:delete must be allowed to DELETE (returns 204 — artifact absent is fine).
	deleteKey := NewEphemeralTestKey(t, server, []string{"installer:delete"}, "test-tenant", 5*time.Minute)
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/installer/artifacts/linux/amd64", nil)
	req2.Header.Set("X-API-Key", deleteKey)
	rec2 := httptest.NewRecorder()
	server.router.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusNoContent, rec2.Code,
		"installer:delete key must be allowed to DELETE an artifact")
}
