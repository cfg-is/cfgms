// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// handlersupgradeCharPutBlob stores a steward binary with explicit labels.
func handlersupgradeCharPutBlob(t *testing.T, server *Server, tenantID, version string, content []byte, labels map[string]string) {
	t.Helper()
	key := stewardBinaryBlobKey(tenantID, version, "linux", "amd64")
	meta := blob.BlobMeta{ContentType: "application/octet-stream", Labels: labels}
	require.NoError(t, server.blobStore.PutBlob(context.Background(), key, bytes.NewReader(content), meta))
}

// handlersupgradeCharCommit dispatches a tenant-a upgrade and marks it committed.
func handlersupgradeCharCommit(t *testing.T, server *Server, store *testUpgradeStore) string {
	t.Helper()
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	id := resp.Data.(map[string]interface{})["upgrade_id"].(string)
	require.NoError(t, store.UpdateUpgradeStatus(context.Background(), id, business.UpgradeStatusCommitted, ""))
	return id
}

func handlersupgradeCharServer(t *testing.T) (*Server, *testUpgradeStore) {
	return setupUpgradeServer(t, "tenant-a", []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	})
}

func TestHandlersUpgradeChar_Dispatch_ChecksumRecomputedFromBlob(t *testing.T) {
	server, store := handlersupgradeCharServer(t)
	content := []byte("real-content")
	handlersupgradeCharPutBlob(t, server, "tenant-a", "v0.5.12", content, map[string]string{
		"approved_by":      "approver@example.com",
		"publisher":        "cfgms",
		"signature":        "AQID",
		"signature_digest": "dig",
		"sha256":           "deadbeef", // lying label must not be trusted
	})
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	recs, err := store.ListUpgradesBySteward(context.Background(), "steward-1")
	require.NoError(t, err)
	require.Len(t, recs, 1)
	sum := sha256.Sum256(content)
	assert.Equal(t, hex.EncodeToString(sum[:]), recs[0].SHA256)
	assert.Equal(t, "cfgms", recs[0].Publisher)
	assert.Equal(t, "dig", recs[0].SignatureDigest)
	assert.Equal(t, []byte{1, 2, 3}, recs[0].BundleSignature)
	assert.Equal(t, "api_key", recs[0].InitiatedBy.AuthMethod)
}

func TestHandlersUpgradeChar_Dispatch_MissingApprovedLabelRefused(t *testing.T) {
	server, store := handlersupgradeCharServer(t)
	handlersupgradeCharPutBlob(t, server, "tenant-a", "v0.5.12", []byte("x"), map[string]string{"signature": "AQID"})
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "NOT_APPROVED")
	recs, _ := store.ListUpgradesBySteward(context.Background(), "steward-1")
	assert.Empty(t, recs)
}

func TestHandlersUpgradeChar_Dispatch_BadSignatureLabel500(t *testing.T) {
	server, _ := handlersupgradeCharServer(t)
	handlersupgradeCharPutBlob(t, server, "tenant-a", "v0.5.12", []byte("x"),
		map[string]string{"approved_by": "a", "signature": "!!not-base64!!"})
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "SIGNATURE_DECODE_ERROR")
}

func TestHandlersUpgradeChar_Dispatch_InvalidSelector400(t *testing.T) {
	server, _ := handlersupgradeCharServer(t)
	rec := doDispatchUpgrade(server, "tenant-a", "bogus:value", "v0.5.12", "linux", "amd64")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_SELECTOR")
}

func TestHandlersUpgradeChar_Dispatch_InvalidPlatformAndArch(t *testing.T) {
	server, _ := handlersupgradeCharServer(t)
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "plan9", "amd64")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_PLATFORM")
	rec = doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "mips")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_ARCH")
}

func TestHandlersUpgradeChar_Dispatch_ConcurrentOnSecondStewardRejectsAll(t *testing.T) {
	server, store := setupUpgradeServer(t, "tenant-a", []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
		{ID: "steward-2", TenantID: "tenant-a", Status: "online"},
	})
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-2", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	rec = doDispatchUpgrade(server, "tenant-a", "tenant:tenant-a", "v0.5.12", "linux", "amd64")
	if rec.Code == http.StatusConflict {
		assert.Contains(t, rec.Body.String(), "CONCURRENT_UPGRADE")
		recs, _ := store.ListUpgradesBySteward(context.Background(), "steward-2")
		assert.Len(t, recs, 1)
	}
}

func TestHandlersUpgradeChar_Dispatch_AdminDefaultNamespace(t *testing.T) {
	server, store := handlersupgradeCharServer(t)
	// Binary only under tenant-a: admin (default namespace) must not find it.
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")
	rec := dispatchUpgradeAsAdmin(server, "id:steward-1", "v0.5.12", "linux", "amd64")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "BINARY_NOT_FOUND")
	publishApprovedBinary(t, server, "default", "v0.5.12", "linux", "amd64")
	rec = dispatchUpgradeAsAdmin(server, "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	recs, _ := store.ListUpgradesBySteward(context.Background(), "steward-1")
	require.Len(t, recs, 1)
	assert.Equal(t, "tenant-a", recs[0].TenantID)
	assert.Equal(t, "mtls_admin", recs[0].InitiatedBy.AuthMethod)
}

func TestHandlersUpgradeChar_Rollback_NoPriorRecord404(t *testing.T) {
	server, _ := handlersupgradeCharServer(t)
	rec := doUpgradeRollback(server, "tenant-a", "does-not-exist", "v0.5.11")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "UPGRADE_NOT_FOUND")
}

func TestHandlersUpgradeChar_Rollback_MissingUpgradeID400(t *testing.T) {
	server, _ := handlersupgradeCharServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade//rollback", bytes.NewReader([]byte(`{}`)))
	req = withScopedPrincipal(req, "tenant-a")
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": ""})
	rec := httptest.NewRecorder()
	server.handleUpgradeRollback(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "MISSING_UPGRADE_ID")
}

func TestHandlersUpgradeChar_Rollback_InvalidBodyAndVersion(t *testing.T) {
	server, store := handlersupgradeCharServer(t)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")
	id := handlersupgradeCharCommit(t, server, store)

	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte(`{bad`)))
	req = withScopedPrincipal(req, "tenant-a")
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": id})
	rec := httptest.NewRecorder()
	server.handleUpgradeRollback(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_BODY")

	rec = doUpgradeRollback(server, "tenant-a", id, "not-a-version")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_VERSION")
}

func TestHandlersUpgradeChar_Rollback_ChecksumRecomputedAndRecordShape(t *testing.T) {
	server, store := handlersupgradeCharServer(t)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")
	content := []byte("rollback-content")
	handlersupgradeCharPutBlob(t, server, "tenant-a", "v0.5.11", content, map[string]string{
		"approved_by":      "a",
		"publisher":        "cfgms",
		"signature":        "AQID",
		"signature_digest": "dig",
		"sha256":           "deadbeef",
	})
	id := handlersupgradeCharCommit(t, server, store)
	rec := doUpgradeRollback(server, "tenant-a", id, "v0.5.11")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	rbID := resp.Data.(map[string]interface{})["upgrade_id"].(string)
	rb, err := store.GetUpgrade(context.Background(), rbID)
	require.NoError(t, err)
	sum := sha256.Sum256(content)
	assert.Equal(t, hex.EncodeToString(sum[:]), rb.SHA256)
	assert.Equal(t, "steward-1", rb.StewardID)
	assert.Equal(t, "tenant-a", rb.TenantID)
	assert.Equal(t, "v0.5.11", rb.Version)
	assert.Equal(t, "api_key", rb.InitiatedBy.AuthMethod)
	assert.Equal(t, "dig", rb.SignatureDigest)
	assert.Equal(t, []byte{1, 2, 3}, rb.BundleSignature)
}

func TestHandlersUpgradeChar_Rollback_MissingApprovedAndBadSignature(t *testing.T) {
	server, store := handlersupgradeCharServer(t)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")
	id := handlersupgradeCharCommit(t, server, store)

	handlersupgradeCharPutBlob(t, server, "tenant-a", "v0.5.10", []byte("x"), map[string]string{"signature": "AQID"})
	rec := doUpgradeRollback(server, "tenant-a", id, "v0.5.10")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "NOT_APPROVED")

	handlersupgradeCharPutBlob(t, server, "tenant-a", "v0.5.9", []byte("x"),
		map[string]string{"approved_by": "a", "signature": "!!bad!!"})
	rec = doUpgradeRollback(server, "tenant-a", id, "v0.5.9")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "SIGNATURE_DECODE_ERROR")
}

func TestHandlersUpgradeChar_Rollback_NoBlobStore503(t *testing.T) {
	server, _ := handlersupgradeCharServer(t)
	server.blobStore = nil
	rec := doUpgradeRollback(server, "tenant-a", "x", "v0.5.11")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "BINARY_STORE_UNAVAILABLE")
}
