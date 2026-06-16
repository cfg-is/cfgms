// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/pkg/cert"
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

// --- Download ---

// extractTarGz parses a tar.gz byte slice and returns a map of path → content.
func extractTarGz(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err, "response must be valid gzip")
	defer func() {
		if cerr := gzr.Close(); cerr != nil {
			t.Logf("failed to close gzip reader: %v", cerr)
		}
	}()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "tar read error")
		content, err := io.ReadAll(tr)
		require.NoError(t, err, "tar entry read error")
		files[header.Name] = content
	}
	return files
}

// setupTestCertManager creates a cert.Manager backed by a self-signed CA for tests.
// It also writes an init marker with the computed CA fingerprint to caPath.
func setupTestCertManager(t *testing.T, caPath string) (*cert.Manager, string) {
	t.Helper()
	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cert.CAConfig{
			Organization: "Test CFGMS",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	caCertPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)

	block, _ := pem.Decode(caCertPEM)
	require.NotNil(t, block, "CA cert PEM must be decodable")
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	hash := sha256.Sum256(caCert.Raw)
	fingerprint := fmt.Sprintf("%x", hash)

	marker := &initialization.InitMarker{
		Version:           1,
		InitializedAt:     time.Now().UTC(),
		ControllerVersion: "test",
		StorageProvider:   "test",
		CAFingerprint:     fingerprint,
	}
	require.NoError(t, initialization.WriteInitMarker(caPath, marker))

	return certMgr, fingerprint
}

// TestHandleDownloadInstallPackage_WithCA is the [REQUIRED TEST]:
// a Server with a filesystem BlobStore containing a dummy artifact and a cert.Manager
// with a self-signed CA; the archive must contain ca.crt and ca.fingerprint with
// correct content.
func TestHandleDownloadInstallPackage_WithCA(t *testing.T) {
	server, store := setupTestServerWithBlobStore(t)

	// Wire a self-signed cert manager and write an init marker.
	caPath := t.TempDir()
	certMgr, expectedFingerprint := setupTestCertManager(t, caPath)
	server.certManager = certMgr
	server.cfg.Certificate = &config.CertificateConfig{CAPath: caPath}

	// Get the CA cert PEM to verify the archive content later.
	expectedCACertPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)

	// Upload a dummy artifact under the root tenant.
	artifactContent := []byte("fake-linux-amd64-installer-binary")
	require.NoError(t, store.PutBlob(
		context.Background(),
		blob.BlobKey{TenantID: downloadTenantID, Namespace: "installers", Name: "linux-amd64"},
		bytes.NewReader(artifactContent),
		blob.BlobMeta{ContentType: "application/octet-stream"},
	))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/download/linux/amd64", nil)
	req = withVars(req, map[string]string{"platform": "linux", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleDownloadInstallPackage(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/gzip", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "cfgms-steward-linux-amd64.tar.gz")

	files := extractTarGz(t, rec.Body.Bytes())

	// Installer artifact must be present with the correct content.
	require.Contains(t, files, "installer/linux-amd64/cfgms-steward-amd64", "artifact must be in archive")
	assert.Equal(t, artifactContent, files["installer/linux-amd64/cfgms-steward-amd64"])

	// CA files must be present and correct (private CA).
	require.Contains(t, files, "installer/ca.crt", "ca.crt must be in archive for private CA")
	assert.Equal(t, expectedCACertPEM, files["installer/ca.crt"])

	require.Contains(t, files, "installer/ca.fingerprint", "ca.fingerprint must be in archive for private CA")
	assert.Equal(t, expectedFingerprint, string(files["installer/ca.fingerprint"]))

	// README must be present.
	assert.Contains(t, files, "installer/README.txt")
}

// TestHandleDownloadInstallPackage_WithoutCA is the [REQUIRED TEST]:
// same setup but certManager is nil so caIsPrivate() returns false; ca.crt must be absent.
func TestHandleDownloadInstallPackage_WithoutCA(t *testing.T) {
	server, store := setupTestServerWithBlobStore(t)
	// certManager remains nil → caIsPrivate() returns false, no CA bundle included.

	artifactContent := []byte("fake-windows-amd64-installer-binary")
	require.NoError(t, store.PutBlob(
		context.Background(),
		blob.BlobKey{TenantID: downloadTenantID, Namespace: "installers", Name: "windows-amd64"},
		bytes.NewReader(artifactContent),
		blob.BlobMeta{ContentType: "application/octet-stream"},
	))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/download/windows/amd64", nil)
	req = withVars(req, map[string]string{"platform": "windows", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleDownloadInstallPackage(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/gzip", rec.Header().Get("Content-Type"))

	files := extractTarGz(t, rec.Body.Bytes())

	// Installer artifact must be present (Windows uses .exe extension).
	require.Contains(t, files, "installer/windows-amd64/cfgms-steward-amd64.exe", "artifact must be in archive")
	assert.Equal(t, artifactContent, files["installer/windows-amd64/cfgms-steward-amd64.exe"])

	// CA files must NOT be present (public/nil CA).
	assert.NotContains(t, files, "installer/ca.crt", "ca.crt must not be in archive when CA is not private")
	assert.NotContains(t, files, "installer/ca.fingerprint", "ca.fingerprint must not be in archive when CA is not private")

	// README must still be present.
	assert.Contains(t, files, "installer/README.txt")
}

// TestHandleDownloadInstallPackage_NotFound verifies that a missing artifact returns
// 404 with the writeErrorResponse JSON shape (not a raw http.Error string).
func TestHandleDownloadInstallPackage_NotFound(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/download/linux/amd64", nil)
	req = withVars(req, map[string]string{"platform": "linux", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleDownloadInstallPackage(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Response must be JSON-shaped (writeErrorResponse), not a raw string.
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp), "404 must use JSON error shape")
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "ARTIFACT_NOT_FOUND", errResp.Error.Code)
}

// TestHandleDownloadInstallPackage_InvalidPlatform verifies that an unknown platform
// returns 400 with the JSON error shape.
func TestHandleDownloadInstallPackage_InvalidPlatform(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/download/solaris/amd64", nil)
	req = withVars(req, map[string]string{"platform": "solaris", "arch": "amd64"})
	rec := httptest.NewRecorder()

	server.handleDownloadInstallPackage(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
	assert.Equal(t, "INVALID_PLATFORM", errResp.Error.Code)
}

// TestHandleDownloadInstallPackage_InvalidArch verifies that an unknown arch
// returns 400 with the JSON error shape.
func TestHandleDownloadInstallPackage_InvalidArch(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/download/linux/mips", nil)
	req = withVars(req, map[string]string{"platform": "linux", "arch": "mips"})
	rec := httptest.NewRecorder()

	server.handleDownloadInstallPackage(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
	assert.Equal(t, "INVALID_ARCH", errResp.Error.Code)
}

// TestHandleDownloadInstallPackage_RouterNoAuth verifies that the download route is
// accessible without an API key (no auth required).
func TestHandleDownloadInstallPackage_RouterNoAuth(t *testing.T) {
	server, store := setupTestServerWithBlobStore(t)

	require.NoError(t, store.PutBlob(
		context.Background(),
		blob.BlobKey{TenantID: downloadTenantID, Namespace: "installers", Name: "linux-amd64"},
		bytes.NewReader([]byte("dummy")),
		blob.BlobMeta{ContentType: "application/octet-stream"},
	))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/download/linux/amd64", nil)
	// Deliberately no X-API-Key header.
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Must succeed — the download route is public.
	assert.Equal(t, http.StatusOK, rec.Code, "download endpoint must be accessible without auth")
	assert.Equal(t, "application/gzip", rec.Header().Get("Content-Type"))
}
