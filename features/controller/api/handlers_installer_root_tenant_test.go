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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func installerRequestAs(t *testing.T, method, path string, caller *Principal, body []byte, platform, arch string) *http.Request {
	t.Helper()
	req := requestAsPrincipal(t, method, path, "", caller, body)
	if platform != "" {
		req = withVars(req, map[string]string{"platform": platform, "arch": arch})
	}
	return req
}

// getInstallerBlob reads key's metadata and closes the content reader (an open
// reader pins the file on Windows and fails t.TempDir cleanup).
func getInstallerBlob(t *testing.T, store blob.BlobStore, key blob.BlobKey) error {
	t.Helper()
	rc, _, err := store.GetBlob(context.Background(), key)
	if err == nil {
		_ = rc.Close()
	}
	return err
}

func installerArtifactNames(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []installerArtifactInfo `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	names := make([]string, 0, len(resp.Data))
	for _, a := range resp.Data {
		names = append(names, a.Platform+"-"+a.Arch)
	}
	return names
}

// TestInstallerArtifacts_RootScoped_UsesRootTenant guards Issue #4634: a root-scoped
// admin's upload, list, get and delete work against the root tenant. Before the
// fix each answered 401, which the web console reads as an expired session — the
// Installer page's endless re-login loop.
func TestInstallerArtifacts_RootScoped_UsesRootTenant(t *testing.T) {
	server, store := setupTestServerWithBlobStore(t)
	caller := rootScopedPrincipal("root-operator-inst")

	rec := httptest.NewRecorder()
	server.handleUploadInstallerArtifact(rec, installerRequestAs(t, http.MethodPut,
		"/api/v1/installer/artifacts/linux/amd64", caller, []byte("root-linux-binary"), "linux", "amd64"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	err := getInstallerBlob(t, store, blob.BlobKey{TenantID: testRootTenantID, Namespace: "installers", Name: "linux-amd64"})
	require.NoError(t, err, "the artifact must be stored under the root tenant")

	rec = httptest.NewRecorder()
	server.handleListInstallerArtifacts(rec, installerRequestAs(t, http.MethodGet, "/api/v1/installer/artifacts", caller, nil, "", ""))
	assert.Equal(t, []string{"linux-amd64"}, installerArtifactNames(t, rec))

	rec = httptest.NewRecorder()
	server.handleGetInstallerArtifact(rec, installerRequestAs(t, http.MethodGet,
		"/api/v1/installer/artifacts/linux/amd64", caller, nil, "linux", "amd64"))
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = httptest.NewRecorder()
	server.handleDeleteInstallerArtifact(rec, installerRequestAs(t, http.MethodDelete,
		"/api/v1/installer/artifacts/linux/amd64", caller, nil, "linux", "amd64"))
	assert.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())

	rec = httptest.NewRecorder()
	server.handleListInstallerArtifacts(rec, installerRequestAs(t, http.MethodGet, "/api/v1/installer/artifacts", caller, nil, "", ""))
	assert.Empty(t, installerArtifactNames(t, rec))
}

// TestInstallerArtifacts_RootScopedClientTenant_RequiresCrossing guards Issue #4634:
// a root-scoped admin selecting a client tenant with ?tenant= is challenged without
// a crossing and nothing is stored; with one the upload lands in that tenant.
func TestInstallerArtifacts_RootScopedClientTenant_RequiresCrossing(t *testing.T) {
	server, store := setupTestServerWithBlobStore(t)
	prepareSelectedTenantServer(t, server)
	caller := rootScopedPrincipal("root-operator-inst")
	clientKey := blob.BlobKey{TenantID: "msp-sel", Namespace: "installers", Name: "linux-amd64"}

	upload := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleUploadInstallerArtifact(rec, installerRequestAs(t, http.MethodPut,
			"/api/v1/installer/artifacts/linux/amd64?tenant=msp-sel", caller, []byte("client-binary"), "linux", "amd64"))
		return rec
	}

	rec := upload()
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
	err := getInstallerBlob(t, store, clientKey)
	assert.ErrorIs(t, err, blob.ErrBlobNotFound, "a challenged upload must store nothing")

	rec = httptest.NewRecorder()
	server.handleListInstallerArtifacts(rec, installerRequestAs(t, http.MethodGet, "/api/v1/installer/artifacts?tenant=no-such-tenant", caller, nil, "", ""))
	assert.Equal(t, http.StatusNotFound, rec.Code, "an unknown tenant is not found, not challenged")

	grantSelectedTenantCrossing(t, server, caller.ID)
	rec = upload()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	err = getInstallerBlob(t, store, clientKey)
	require.NoError(t, err, "with a crossing the artifact is stored under the selected tenant")

	rec = httptest.NewRecorder()
	server.handleListInstallerArtifacts(rec, installerRequestAs(t, http.MethodGet, "/api/v1/installer/artifacts", caller, nil, "", ""))
	assert.Empty(t, installerArtifactNames(t, rec), "without ?tenant= the root tenant's artifacts are listed")
}

// TestInstallerArtifacts_RootScoped_NoRootTenant_BadRequest guards Issue #4634: when
// no root tenant can be resolved the request is a 400, never a 401.
func TestInstallerArtifacts_RootScoped_NoRootTenant_BadRequest(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)
	server.tenantManager = nil // rootTenantID resolves "" without a tenant manager

	rec := httptest.NewRecorder()
	server.handleListInstallerArtifacts(rec, installerRequestAs(t, http.MethodGet, "/api/v1/installer/artifacts", rootScopedPrincipal("root-operator-inst"), nil, "", ""))
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

// TestInstallerDownload_ServesRootTenantResolvedByPosition guards Issue #4634: a
// deployment whose root tenant is not named "root" still serves the artifact its
// root admin uploaded on the public download path.
func TestInstallerDownload_ServesRootTenantResolvedByPosition(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)
	sm := pkgtesting.SetupTestStorage(t)
	server.tenantManager = tenant.NewManager(tenant.NewStorageAdapter(sm.GetTenantStore()), nil)
	_, err := server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: "acme-corp"})
	require.NoError(t, err)
	require.Equal(t, "acme-corp", server.rootTenantID(context.Background()))

	rec := httptest.NewRecorder()
	server.handleUploadInstallerArtifact(rec, installerRequestAs(t, http.MethodPut,
		"/api/v1/installer/artifacts/linux/amd64", rootScopedPrincipal("root-operator-inst"), []byte("acme-linux-binary"), "linux", "amd64"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	req := withVars(httptest.NewRequest(http.MethodGet, "/api/v1/installer/download/linux/amd64", nil),
		map[string]string{"platform": "linux", "arch": "amd64"})
	rec = httptest.NewRecorder()
	server.handleDownloadInstallPackage(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	files := extractTarGz(t, rec.Body.Bytes())
	require.Contains(t, files, "installer/linux-amd64/cfgms-steward-amd64")
	assert.True(t, bytes.Equal([]byte("acme-linux-binary"), files["installer/linux-amd64/cfgms-steward-amd64"]))
}
