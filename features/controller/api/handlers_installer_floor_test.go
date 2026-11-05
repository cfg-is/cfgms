// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
)

// uploadInstallerAt signs content at version and PUTs it as tenantID.
func uploadInstallerAt(t *testing.T, server *Server, tenantID, platform, arch, version string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut,
		signedInstallerPath(t, "/api/v1/installer/artifacts/"+platform+"/"+arch, content, version, platform, arch),
		bytes.NewReader(content))
	req = withTenant(req, tenantID)
	req = withVars(req, map[string]string{"platform": platform, "arch": arch})
	rec := httptest.NewRecorder()
	server.handleUploadInstallerArtifact(rec, req)
	return rec
}

func deleteInstaller(t *testing.T, server *Server, tenantID, platform, arch string) {
	t.Helper()
	req := withTenant(httptest.NewRequest(http.MethodDelete, "/api/v1/installer/artifacts/"+platform+"/"+arch, nil), tenantID)
	req = withVars(req, map[string]string{"platform": platform, "arch": arch})
	rec := httptest.NewRecorder()
	server.handleDeleteInstallerArtifact(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
}

func storedInstallerBytes(t *testing.T, store blob.BlobStore, tenantID, platform, arch string) []byte {
	t.Helper()
	rc, _, err := store.GetBlob(context.Background(), blob.BlobKey{TenantID: tenantID, Namespace: "installers", Name: platform + "-" + arch})
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	var buf bytes.Buffer
	_, err = buf.ReadFrom(rc)
	require.NoError(t, err)
	return buf.Bytes()
}

func requireNotNewer(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "INSTALLER_VERSION_NOT_NEWER")
	assert.NotContains(t, rec.Body.String(), "v2.0.0", "refusal must not reveal the floor")
}

func TestInstallerFloor_OlderVersionRefused(t *testing.T) {
	server, store := setupTestServerWithBlobStore(t)
	newer := []byte("installer-v2")
	require.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v2.0.0", newer).Code)

	requireNotNewer(t, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.9.9", []byte("installer-v1")))
	assert.Equal(t, newer, storedInstallerBytes(t, store, "t1", "linux", "amd64"), "stored artifact must be unchanged")
}

func TestInstallerFloor_SurvivesDelete(t *testing.T) {
	server, store := setupTestServerWithBlobStore(t)
	require.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v2.0.0", []byte("installer-v2")).Code)
	deleteInstaller(t, server, "t1", "linux", "amd64")

	requireNotNewer(t, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.0.0", []byte("installer-v1")))
	exists, err := store.BlobExists(context.Background(), blob.BlobKey{TenantID: "t1", Namespace: "installers", Name: "linux-amd64"})
	require.NoError(t, err)
	assert.False(t, exists, "refused upload must not store an artifact")

	require.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v2.0.1", []byte("installer-v2.0.1")).Code)
}

func TestInstallerFloor_EqualVersion(t *testing.T) {
	server, store := setupTestServerWithBlobStore(t)
	content := []byte("installer-v1")
	require.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.0.0", content).Code)
	assert.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.0.0", content).Code, "identical retry is accepted")
	// 1.0.0 and v1.0.0 are the same coordinate.
	assert.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "1.0.0", content).Code)

	rec := uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.0.0", []byte("different-installer"))
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "INSTALLER_VERSION_NOT_NEWER")
	assert.Equal(t, content, storedInstallerBytes(t, store, "t1", "linux", "amd64"))
}

func TestInstallerFloor_HigherVersionBecomesFloor(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)
	require.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.0.0", []byte("a")).Code)
	require.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.1.0", []byte("b")).Code)
	requireNotNewer(t, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.0.0", []byte("a")))
}

func TestInstallerFloor_PreReleaseBelowRelease(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)
	require.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.0.0", []byte("release")).Code)
	requireNotNewer(t, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.0.0-rc.1", []byte("rc")))
}

func TestInstallerFloor_ScopedPerTenantPlatformArch(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)
	require.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "v2.0.0", []byte("a")).Code)

	assert.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "arm64", "v1.0.0", []byte("b")).Code, "other arch")
	assert.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "windows", "amd64", "v1.0.0", []byte("c")).Code, "other platform")
	assert.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t2", "linux", "amd64", "v1.0.0", []byte("d")).Code, "other tenant")
}

// TestInstallerFloor_ConcurrentDifferentInstallersSameVersion: two different
// installers racing for one new version cannot both pass; exactly one is accepted.
func TestInstallerFloor_ConcurrentDifferentInstallersSameVersion(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)
	codes := make([]int, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = uploadInstallerAt(t, server, "t1", "linux", "amd64", "v3.0.0", []byte{byte('a' + i)}).Code
		}(i)
	}
	close(start)
	wg.Wait()
	assert.ElementsMatch(t, []int{http.StatusOK, http.StatusConflict}, codes)
}

func TestInstallerUpload_VersionValidation(t *testing.T) {
	content := []byte("installer")
	cases := []struct{ name, version, code string }{
		{"missing", "", "VERSION_REQUIRED"},
		{"two components", "1.2", "INVALID_VERSION"},
		{"word", "latest", "INVALID_VERSION"},
		{"build metadata", "v1.2.3+build", "INVALID_VERSION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, store := setupTestServerWithBlobStore(t)
			path := "/api/v1/installer/artifacts/linux/amd64?signature=" + signInstallerContent(t, content, "v1.2.3", "linux", "amd64")
			if tc.version != "" {
				path += "&version=" + tc.version
			}
			req := withTenant(httptest.NewRequest(http.MethodPut, path, bytes.NewReader(content)), "t1")
			req = withVars(req, map[string]string{"platform": "linux", "arch": "amd64"})
			rec := httptest.NewRecorder()
			server.handleUploadInstallerArtifact(rec, req)

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.code)
			blobs, err := store.ListBlobs(context.Background(), blob.BlobKey{TenantID: "t1"})
			require.NoError(t, err)
			assert.Empty(t, blobs, "nothing may be stored")
		})
	}
}

func TestInstallerUpload_StoresCanonicalVersionLabel(t *testing.T) {
	server, store := setupTestServerWithBlobStore(t)
	require.Equal(t, http.StatusOK, uploadInstallerAt(t, server, "t1", "linux", "amd64", "1.4.0", []byte("x")).Code)
	rc, meta, err := store.GetBlob(context.Background(), blob.BlobKey{TenantID: "t1", Namespace: "installers", Name: "linux-amd64"})
	require.NoError(t, err)
	_ = rc.Close()
	assert.Equal(t, "v1.4.0", meta.Labels["version"])
}

func TestHandleDownloadInstallPackage_RefusesAlteredVersionLabel(t *testing.T) {
	content := []byte("signed-at-v1")
	for _, tc := range []struct {
		name   string
		labels func(l map[string]string)
	}{
		{"altered", func(l map[string]string) { l["version"] = "v9.9.9" }},
		{"missing", func(l map[string]string) { delete(l, "version") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, store := serverWithRootTenant(t, "acme-root")
			meta := signedInstallerMeta(t, content, testInstallerVersion, "linux", "amd64")
			tc.labels(meta.Labels)
			require.NoError(t, store.PutBlob(context.Background(),
				blob.BlobKey{TenantID: "acme-root", Namespace: "installers", Name: "linux-amd64"},
				bytes.NewReader(content), meta))
			rec := downloadInstaller(server, "linux", "amd64")
			assert.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		})
	}
}

// listFailStore wraps a real BlobStore and fails ListBlobs, to prove the floor fails closed.
type listFailStore struct{ blob.BlobStore }

func (listFailStore) ListBlobs(context.Context, blob.BlobKey) ([]blob.BlobInfo, error) {
	return nil, errors.New("list unavailable")
}

func TestInstallerFloor_StoreFailureFailsClosed(t *testing.T) {
	server, real := setupTestServerWithBlobStore(t)
	server.blobStore = listFailStore{real}

	rec := uploadInstallerAt(t, server, "t1", "linux", "amd64", "v1.0.0", []byte("x"))
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "STORE_ERROR")
	exists, err := real.BlobExists(context.Background(), blob.BlobKey{TenantID: "t1", Namespace: "installers", Name: "linux-amd64"})
	require.NoError(t, err)
	assert.False(t, exists)
}
