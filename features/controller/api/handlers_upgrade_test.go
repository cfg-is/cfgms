// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// --- Test-only in-memory UpgradeStore ---

type testUpgradeStore struct {
	mu      sync.RWMutex
	records map[string]*business.UpgradeRecord
}

func newTestUpgradeStore() *testUpgradeStore {
	return &testUpgradeStore{records: make(map[string]*business.UpgradeRecord)}
}

func (s *testUpgradeStore) CreateUpgrade(_ context.Context, record *business.UpgradeRecord) error {
	if len(record.BundleSignature) == 0 {
		return fmt.Errorf("bundle signature is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.ID]; exists {
		return fmt.Errorf("duplicate upgrade ID: %s", record.ID)
	}
	cp := *record
	s.records[record.ID] = &cp
	return nil
}

func (s *testUpgradeStore) UpdateUpgradeStatus(_ context.Context, id string, status business.UpgradeStatus, errorMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return business.ErrUpgradeNotFound
	}
	r.Status = status
	r.ErrorMessage = errorMsg
	if status == business.UpgradeStatusCommitted ||
		status == business.UpgradeStatusRolledBack ||
		status == business.UpgradeStatusFailed {
		now := time.Now().UTC()
		r.CompletedAt = &now
	}
	return nil
}

func (s *testUpgradeStore) GetUpgrade(_ context.Context, id string) (*business.UpgradeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return nil, business.ErrUpgradeNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *testUpgradeStore) ListUpgradesBySteward(_ context.Context, stewardID string) ([]*business.UpgradeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.UpgradeRecord
	for _, r := range s.records {
		if r.StewardID == stewardID {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *testUpgradeStore) ListUpgradesByTenant(_ context.Context, tenantID string) ([]*business.UpgradeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.UpgradeRecord
	for _, r := range s.records {
		if r.TenantID == tenantID {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *testUpgradeStore) HealthCheck(_ context.Context) error { return nil }
func (s *testUpgradeStore) Initialize(_ context.Context) error  { return nil }
func (s *testUpgradeStore) Close() error                        { return nil }

var _ business.UpgradeStore = (*testUpgradeStore)(nil)

// --- Upgrade test helpers ---

// setupUpgradeServer creates a test server with a blob store, upgrade store, and fleet query.
func setupUpgradeServer(t *testing.T, tenantID string, stewards []fleet.StewardData) (*Server, *testUpgradeStore) {
	t.Helper()
	server, _ := setupTestServerWithBlobStore(t)
	store := newTestUpgradeStore()
	server.upgradeStore = store
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: stewards})
	return server, store
}

// publishApprovedBinary puts a steward binary blob with approved_by label set.
// This simulates a binary that has been published AND approved for dispatch.
func publishApprovedBinary(t *testing.T, server *Server, tenantID, version, platform, arch string) []byte {
	t.Helper()
	content := []byte(fmt.Sprintf("cfgms-steward-binary-%s-%s-%s", version, platform, arch))
	sum := sha256.Sum256(content)

	// Create a fake 64-byte signature
	fakeSig := make([]byte, 64)
	for i := range fakeSig {
		fakeSig[i] = byte(i)
	}
	sigDigest := sha256.Sum256(fakeSig)

	key := stewardBinaryBlobKey(tenantID, version, platform, arch)
	meta := blob.BlobMeta{
		ContentType: "application/octet-stream",
		Labels: map[string]string{
			"version":          version,
			"platform":         platform,
			"arch":             arch,
			"publisher":        "cfgms",
			"published_by":     "publisher@example.com",
			"publisher_tenant": tenantID,
			"signature":        base64.RawURLEncoding.EncodeToString(fakeSig),
			"signature_digest": hex.EncodeToString(sigDigest[:]),
			"sha256":           hex.EncodeToString(sum[:]),
			"approved_by":      "approver@example.com",
		},
	}
	err := server.blobStore.PutBlob(context.Background(), key, bytes.NewReader(content), meta)
	require.NoError(t, err, "publishApprovedBinary: PutBlob must not fail")
	return content
}

// publishUnapprovedBinary puts a steward binary blob WITHOUT approved_by label.
func publishUnapprovedBinary(t *testing.T, server *Server, tenantID, version, platform, arch string) {
	t.Helper()
	content := []byte(fmt.Sprintf("cfgms-steward-binary-%s-%s-%s-unapproved", version, platform, arch))
	fakeSig := make([]byte, 64)
	sigDigest := sha256.Sum256(fakeSig)

	key := stewardBinaryBlobKey(tenantID, version, platform, arch)
	meta := blob.BlobMeta{
		ContentType: "application/octet-stream",
		Labels: map[string]string{
			"version":          version,
			"platform":         platform,
			"arch":             arch,
			"publisher":        "cfgms",
			"published_by":     "publisher@example.com",
			"publisher_tenant": tenantID,
			"signature":        base64.RawURLEncoding.EncodeToString(fakeSig),
			"signature_digest": hex.EncodeToString(sigDigest[:]),
			// approved_by intentionally absent
		},
	}
	err := server.blobStore.PutBlob(context.Background(), key, bytes.NewReader(content), meta)
	require.NoError(t, err, "publishUnapprovedBinary: PutBlob must not fail")
}

// doDispatchUpgrade calls handleDispatchUpgrade with the given params.
func doDispatchUpgrade(server *Server, tenantID, selector, version, platform, arch string) *httptest.ResponseRecorder {
	body := dispatchUpgradeRequest{
		Selector: selector,
		Version:  version,
		Platform: platform,
		Arch:     arch,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade", bytes.NewReader(b))
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, tenantID))
	rec := httptest.NewRecorder()
	server.handleDispatchUpgrade(rec, req)
	return rec
}

// doUpgradeStatus calls handleUpgradeStatus for the given upgrade_id.
func doUpgradeStatus(server *Server, tenantID, upgradeID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/upgrade/"+upgradeID, nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, tenantID))
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": upgradeID})
	rec := httptest.NewRecorder()
	server.handleUpgradeStatus(rec, req)
	return rec
}

// doUpgradeRollback calls handleUpgradeRollback for the given upgrade_id and target version.
func doUpgradeRollback(server *Server, tenantID, upgradeID, targetVersion string) *httptest.ResponseRecorder {
	body := rollbackRequest{Version: targetVersion}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade/"+upgradeID+"/rollback", bytes.NewReader(b))
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, tenantID))
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": upgradeID})
	rec := httptest.NewRecorder()
	server.handleUpgradeRollback(rec, req)
	return rec
}

// --- Required tests (AC) ---

// TestDispatch_RequiresDurableStore verifies that dispatch returns 503 when no
// durable UpgradeStore is configured (no in-memory fallback).
func TestDispatch_RequiresDurableStore(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)
	// upgradeStore is nil — not configured.

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "UPGRADE_STORE_UNAVAILABLE")
}

// TestDispatch_RejectsCrossTenantSelector verifies that dispatching with stewards
// from a different tenant returns 403.
func TestDispatch_RejectsCrossTenantSelector(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-other-tenant", TenantID: "tenant-b", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	// Caller is tenant-a, but the steward resolved by id: belongs to tenant-b.
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-other-tenant", "v0.5.12", "linux", "amd64")

	assert.Equal(t, http.StatusForbidden, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "CROSS_TENANT")
}

// TestDispatch_RejectsUnapprovedBlob verifies that a blob in published state
// (approved_by label absent) returns 403.
func TestDispatch_RejectsUnapprovedBlob(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)
	publishUnapprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")

	assert.Equal(t, http.StatusForbidden, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "NOT_APPROVED")
}

// TestDispatch_RejectsConcurrentUpgrade verifies that a second dispatch to the
// same steward with an active (non-terminal) upgrade record returns 409 Conflict.
func TestDispatch_RejectsConcurrentUpgrade(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	// First dispatch must succeed.
	rec1 := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec1.Code, "first dispatch must succeed: %s", rec1.Body.String())

	// Verify that a non-terminal record now exists.
	records, err := upgradeStore.ListUpgradesBySteward(context.Background(), "steward-1")
	require.NoError(t, err)
	require.NotEmpty(t, records, "first dispatch must have created an upgrade record")
	assert.Equal(t, business.UpgradeStatusDispatched, records[0].Status)

	// Second dispatch to the same steward must return 409.
	rec2 := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	assert.Equal(t, http.StatusConflict, rec2.Code)
	body := rec2.Body.String()
	assert.Contains(t, body, "CONCURRENT_UPGRADE")
}

// --- Happy path tests ---

// TestDispatch_Returns202WithUpgradeID verifies that a valid dispatch request
// returns 202 Accepted with a non-empty upgrade_id and steward_count=1.
func TestDispatch_Returns202WithUpgradeID(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code, "response body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "expected Data to be a JSON object")
	assert.NotEmpty(t, data["upgrade_id"])
	count, _ := data["steward_count"].(float64)
	assert.Equal(t, float64(1), count)
	assert.Equal(t, "accepted", data["status"])

	// Verify an UpgradeRecord was created in the durable store.
	upgradeID, _ := data["upgrade_id"].(string)
	record, err := upgradeStore.GetUpgrade(context.Background(), upgradeID)
	require.NoError(t, err, "upgrade record must be retrievable by upgrade_id")
	assert.Equal(t, "steward-1", record.StewardID)
	assert.Equal(t, "tenant-a", record.TenantID)
	assert.Equal(t, business.UpgradeStatusDispatched, record.Status)
	assert.Equal(t, "cfgms", record.Publisher)
	assert.NotEmpty(t, record.BundleSignature)
	assert.NotEmpty(t, record.OperationNonce)
	assert.NotEmpty(t, record.SHA256)
}

// TestDispatch_CreatesRecordWithCorrectProvenance verifies that UpgradeRecord
// fields are set from blob labels (Publisher, BundleSignature, SignatureDigest).
func TestDispatch_CreatesRecordWithCorrectProvenance(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-prov", TenantID: "tenant-prov", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-prov", stewards)
	content := publishApprovedBinary(t, server, "tenant-prov", "v1.0.0", "linux", "amd64")

	rec := doDispatchUpgrade(server, "tenant-prov", "id:steward-prov", "v1.0.0", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data := resp.Data.(map[string]interface{})
	upgradeID := data["upgrade_id"].(string)

	record, err := upgradeStore.GetUpgrade(context.Background(), upgradeID)
	require.NoError(t, err)

	// Publisher must come from blob label.
	assert.Equal(t, "cfgms", record.Publisher)
	// BundleSignature must be non-empty (decoded from blob label).
	assert.NotEmpty(t, record.BundleSignature)
	// SHA-256 must be recomputed from blob content.
	sum := sha256.Sum256(content)
	assert.Equal(t, hex.EncodeToString(sum[:]), record.SHA256)
}

// TestDispatch_NoBlobStore verifies 503 when blob store is not configured.
func TestDispatch_NoBlobStore(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server := setupTestServer(t)
	server.upgradeStore = newTestUpgradeStore()
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: stewards})
	// blobStore is nil.

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "BINARY_STORE_UNAVAILABLE")
}

// TestDispatch_EmptySelectorReturns400 verifies that an empty selector returns 400.
func TestDispatch_EmptySelectorReturns400(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)

	rec := doDispatchUpgrade(server, "tenant-a", "", "v0.5.12", "linux", "amd64")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestDispatch_NoMatchingStewardsReturns403 verifies 403 when selector matches
// no stewards in the caller's tenant.
func TestDispatch_NoMatchingStewardsReturns403(t *testing.T) {
	server, _ := setupUpgradeServer(t, "tenant-a", nil /* no stewards */)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	rec := doDispatchUpgrade(server, "tenant-a", "id:nonexistent-steward", "v0.5.12", "linux", "amd64")

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "CROSS_TENANT")
}

// TestDispatch_BlobNotFoundReturns404 verifies 404 when blob does not exist.
func TestDispatch_BlobNotFoundReturns404(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)
	// No binary published.

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v9.9.9", "linux", "amd64")

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestDispatch_InvalidVersionReturns400 verifies 400 for invalid version format.
func TestDispatch_InvalidVersionReturns400(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "1.0.0", "linux", "amd64")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_VERSION")
}

// TestDispatch_AllowsTerminalRecordReplacement verifies that a second dispatch
// succeeds when the prior upgrade record is in a terminal state (failed/committed/rolled_back).
func TestDispatch_AllowsTerminalRecordReplacement(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	// First dispatch.
	rec1 := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec1.Code)

	// Advance the record to a terminal state (failed).
	var resp1 APIResponse
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &resp1))
	data1 := resp1.Data.(map[string]interface{})
	upgradeID := data1["upgrade_id"].(string)
	require.NoError(t, upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID, business.UpgradeStatusFailed, "disk full"))

	// Second dispatch should now succeed (prior record is terminal).
	rec2 := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	assert.Equal(t, http.StatusAccepted, rec2.Code)
}

// TestUpgradeStatus_Returns200WithRecord verifies that GET /stewards/upgrade/{id}
// returns the upgrade record after a successful dispatch.
func TestUpgradeStatus_Returns200WithRecord(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code)

	var dispatchResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &dispatchResp))
	data := dispatchResp.Data.(map[string]interface{})
	upgradeID := data["upgrade_id"].(string)

	// Query status.
	statusRec := doUpgradeStatus(server, "tenant-a", upgradeID)
	assert.Equal(t, http.StatusOK, statusRec.Code)

	var statusResp APIResponse
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &statusResp))
	statusData, ok := statusResp.Data.(map[string]interface{})
	require.True(t, ok)
	// UpgradeRecord has no JSON tags so fields serialize with their Go field names.
	assert.Equal(t, upgradeID, statusData["ID"])
	assert.Equal(t, "dispatched", statusData["Status"])
}

// TestUpgradeStatus_CrossTenantReturns403 verifies that a tenant cannot query
// another tenant's upgrade record.
func TestUpgradeStatus_CrossTenantReturns403(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code)

	var dispatchResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &dispatchResp))
	data := dispatchResp.Data.(map[string]interface{})
	upgradeID := data["upgrade_id"].(string)

	// tenant-b must not see tenant-a's record.
	statusRec := doUpgradeStatus(server, "tenant-b", upgradeID)
	assert.Equal(t, http.StatusForbidden, statusRec.Code)
}

// TestUpgradeStatus_NotFoundReturns404 verifies 404 for unknown upgrade_id.
func TestUpgradeStatus_NotFoundReturns404(t *testing.T) {
	server, _ := setupUpgradeServer(t, "tenant-a", nil)

	statusRec := doUpgradeStatus(server, "tenant-a", "no-such-upgrade")
	assert.Equal(t, http.StatusNotFound, statusRec.Code)
}

// TestUpgradeStatus_NoDurableStoreReturns503 verifies 503 when upgradeStore is nil.
func TestUpgradeStatus_NoDurableStoreReturns503(t *testing.T) {
	server := setupTestServer(t)
	// upgradeStore is nil.

	statusRec := doUpgradeStatus(server, "tenant-a", "some-id")
	assert.Equal(t, http.StatusServiceUnavailable, statusRec.Code)
}

// TestUpgradeRollback_Returns202 verifies that a rollback dispatch returns 202
// given an approved binary at the target version.
func TestUpgradeRollback_Returns202(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")
	publishApprovedBinary(t, server, "tenant-a", "v0.5.11", "linux", "amd64")

	// Create an initial upgrade record so rollback has something to reference.
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code)

	var dispatchResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &dispatchResp))
	data := dispatchResp.Data.(map[string]interface{})
	upgradeID := data["upgrade_id"].(string)

	// Mark original upgrade as committed so rollback doesn't conflict.
	require.NoError(t, upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID, business.UpgradeStatusCommitted, ""))

	// Rollback to v0.5.11.
	rollbackRec := doUpgradeRollback(server, "tenant-a", upgradeID, "v0.5.11")
	assert.Equal(t, http.StatusAccepted, rollbackRec.Code, "body: %s", rollbackRec.Body.String())
}

// TestUpgradeRollback_NoDurableStoreReturns503 verifies 503 when upgradeStore is nil.
func TestUpgradeRollback_NoDurableStoreReturns503(t *testing.T) {
	server, _ := setupTestServerWithBlobStore(t)
	// upgradeStore is nil.

	rollbackRec := doUpgradeRollback(server, "tenant-a", "some-id", "v0.5.11")
	assert.Equal(t, http.StatusServiceUnavailable, rollbackRec.Code)
}

// TestUpgradeRollback_MissingVersionReturns400 verifies 400 when target version
// is omitted from rollback body.
func TestUpgradeRollback_MissingVersionReturns400(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)

	// Create a record manually so the rollback has something to look up.
	fakeSig := make([]byte, 64)
	record := &business.UpgradeRecord{
		ID:              "upgrade-for-rollback",
		StewardID:       "steward-1",
		TenantID:        "tenant-a",
		Version:         "v0.5.12",
		Platform:        "linux",
		Arch:            "amd64",
		Status:          business.UpgradeStatusCommitted,
		Publisher:       "cfgms",
		BundleSignature: fakeSig,
		CreatedAt:       time.Now().UTC(),
		OperationNonce:  make([]byte, 32),
	}
	require.NoError(t, upgradeStore.CreateUpgrade(context.Background(), record))

	rollbackRec := doUpgradeRollback(server, "tenant-a", "upgrade-for-rollback", "" /* empty version */)
	assert.Equal(t, http.StatusBadRequest, rollbackRec.Code)
}

// TestUpgradeStatus_MissingTenantReturns401 verifies 401 when caller has no tenant.
func TestUpgradeStatus_MissingTenantReturns401(t *testing.T) {
	server, _ := setupUpgradeServer(t, "tenant-a", nil)
	server.upgradeStore = newTestUpgradeStore()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/upgrade/some-id", nil)
	// No TenantID in context.
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": "some-id"})
	rec := httptest.NewRecorder()
	server.handleUpgradeStatus(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestUpgradeRollback_MissingTenantReturns401 verifies 401 when caller has no tenant.
func TestUpgradeRollback_MissingTenantReturns401(t *testing.T) {
	server, _ := setupUpgradeServer(t, "tenant-a", nil)
	server.upgradeStore = newTestUpgradeStore()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade/some-id/rollback",
		bytes.NewReader([]byte(`{"version":"v0.5.11"}`)))
	// No TenantID in context.
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": "some-id"})
	rec := httptest.NewRecorder()
	server.handleUpgradeRollback(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestUpgradeRollback_CrossTenantReturns403 verifies that a tenant cannot roll
// back another tenant's upgrade record.
func TestUpgradeRollback_CrossTenantReturns403(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)

	// Create an upgrade record owned by tenant-a.
	fakeSig := make([]byte, 64)
	record := &business.UpgradeRecord{
		ID:              "upgrade-tenant-a",
		StewardID:       "steward-1",
		TenantID:        "tenant-a",
		Version:         "v0.5.12",
		Platform:        "linux",
		Arch:            "amd64",
		Status:          business.UpgradeStatusCommitted,
		Publisher:       "cfgms",
		BundleSignature: fakeSig,
		CreatedAt:       time.Now().UTC(),
		OperationNonce:  make([]byte, 32),
	}
	require.NoError(t, upgradeStore.CreateUpgrade(context.Background(), record))

	// tenant-b attempts rollback of tenant-a's record.
	rollbackRec := doUpgradeRollback(server, "tenant-b", "upgrade-tenant-a", "v0.5.11")
	assert.Equal(t, http.StatusForbidden, rollbackRec.Code)
}

// TestUpgradeRollback_BinaryNotFoundReturns404 verifies 404 when the rollback
// target binary is absent from the blob store.
func TestUpgradeRollback_BinaryNotFoundReturns404(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)
	// No rollback binary published for v0.5.11.

	fakeSig := make([]byte, 64)
	record := &business.UpgradeRecord{
		ID:              "upgrade-for-404-rollback",
		StewardID:       "steward-1",
		TenantID:        "tenant-a",
		Version:         "v0.5.12",
		Platform:        "linux",
		Arch:            "amd64",
		Status:          business.UpgradeStatusCommitted,
		Publisher:       "cfgms",
		BundleSignature: fakeSig,
		CreatedAt:       time.Now().UTC(),
		OperationNonce:  make([]byte, 32),
	}
	require.NoError(t, upgradeStore.CreateUpgrade(context.Background(), record))

	rollbackRec := doUpgradeRollback(server, "tenant-a", "upgrade-for-404-rollback", "v0.5.11")
	assert.Equal(t, http.StatusNotFound, rollbackRec.Code)
	assert.Contains(t, rollbackRec.Body.String(), "BINARY_NOT_FOUND")
}

// TestUpgradeRollback_UnapprovedBinaryReturns403 verifies 403 when the rollback
// target binary exists but has not been approved.
func TestUpgradeRollback_UnapprovedBinaryReturns403(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)
	publishUnapprovedBinary(t, server, "tenant-a", "v0.5.11", "linux", "amd64")

	fakeSig := make([]byte, 64)
	record := &business.UpgradeRecord{
		ID:              "upgrade-for-403-rollback",
		StewardID:       "steward-1",
		TenantID:        "tenant-a",
		Version:         "v0.5.12",
		Platform:        "linux",
		Arch:            "amd64",
		Status:          business.UpgradeStatusCommitted,
		Publisher:       "cfgms",
		BundleSignature: fakeSig,
		CreatedAt:       time.Now().UTC(),
		OperationNonce:  make([]byte, 32),
	}
	require.NoError(t, upgradeStore.CreateUpgrade(context.Background(), record))

	rollbackRec := doUpgradeRollback(server, "tenant-a", "upgrade-for-403-rollback", "v0.5.11")
	assert.Equal(t, http.StatusForbidden, rollbackRec.Code)
	assert.Contains(t, rollbackRec.Body.String(), "NOT_APPROVED")
}

// TestDispatch_InvalidBody verifies 400 for malformed JSON body.
func TestDispatch_InvalidBody(t *testing.T) {
	server, _ := setupUpgradeServer(t, "tenant-a", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade",
		bytes.NewReader([]byte("not-json")))
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
	rec := httptest.NewRecorder()
	server.handleDispatchUpgrade(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestDispatch_MissingTenantReturns401 verifies 401 when caller has no tenant.
func TestDispatch_MissingTenantReturns401(t *testing.T) {
	server, _ := setupUpgradeServer(t, "tenant-a", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade",
		bytes.NewReader([]byte(`{"selector":"id:s1","version":"v0.5.12","platform":"linux","arch":"amd64"}`)))
	// No TenantID in context.
	rec := httptest.NewRecorder()
	server.handleDispatchUpgrade(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestDispatch_UpgradeStoreRecordsCanBeReadByStatus verifies end-to-end: dispatch
// creates a record that the status endpoint can retrieve.
func TestDispatch_UpgradeStoreRecordsCanBeReadByStatus(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-e2e", TenantID: "tenant-e2e", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-e2e", stewards)
	publishApprovedBinary(t, server, "tenant-e2e", "v0.5.12", "linux", "amd64")

	rec := doDispatchUpgrade(server, "tenant-e2e", "id:steward-e2e", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code)

	var dispatchResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &dispatchResp))
	upgradeID := dispatchResp.Data.(map[string]interface{})["upgrade_id"].(string)

	statusRec := doUpgradeStatus(server, "tenant-e2e", upgradeID)
	require.Equal(t, http.StatusOK, statusRec.Code)

	var statusResp APIResponse
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &statusResp))
	statusData := statusResp.Data.(map[string]interface{})
	assert.Equal(t, "steward-e2e", statusData["StewardID"])
}
