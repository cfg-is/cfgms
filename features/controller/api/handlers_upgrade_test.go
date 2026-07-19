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

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/fleet"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
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
	// Tenant-scoped (non-admin) caller: principal + tenant injected as the middleware
	// would for an X-API-Key request (Issue #1999).
	req = withScopedPrincipal(req, tenantID)
	rec := httptest.NewRecorder()
	server.handleDispatchUpgrade(rec, req)
	return rec
}

// doUpgradeStatus calls handleUpgradeStatus for the given upgrade_id.
func doUpgradeStatus(server *Server, tenantID, upgradeID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/upgrade/"+upgradeID, nil)
	req = withScopedPrincipal(req, tenantID)
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
	req = withScopedPrincipal(req, tenantID)
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

// TestDispatch_ExplicitTenantPrefix_OutsideSubtreeRejected verifies that a
// non-admin caller whose selector carries an explicit tenant-path prefix outside
// their authorized subtree is rejected with 403 CROSS_TENANT by the early-return
// branch (handlers_upgrade.go:137-144), before the fleet query or approval gate.
// The existing TestDispatch_RejectsCrossTenantSelector uses a prefix-less selector
// and hits the len(stewards)==0 path instead, leaving this branch uncovered.
func TestDispatch_ExplicitTenantPrefix_OutsideSubtreeRejected(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	// Caller tenant-a, but the selector prefix targets tenant-b (outside subtree).
	rec := doDispatchUpgrade(server, "tenant-a", "tenant-b/id:steward-1", "v0.5.12", "linux", "amd64")

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "CROSS_TENANT")
}

// TestDispatch_ExplicitTenantPrefix_ScopesToSubtree verifies that a valid
// in-subtree tenant-path prefix drives filter.TenantSubtree = parsedTenantPath
// (handlers_upgrade.go:145): dispatch resolves only stewards at or below the
// prefixed sub-tenant, excluding sibling sub-tenants under the caller's tenant.
func TestDispatch_ExplicitTenantPrefix_ScopesToSubtree(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-c1", TenantID: "tenant-a/client-1", Status: "online"},
		{ID: "steward-c2", TenantID: "tenant-a/client-2", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	// Caller tenant-a targets only the client-1 subtree via an explicit prefix.
	rec := doDispatchUpgrade(server, "tenant-a", "tenant-a/client-1/all", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	count, _ := data["steward_count"].(float64)
	assert.Equal(t, float64(1), count,
		"explicit prefix must scope to tenant-a/client-1, excluding sibling client-2")

	// The in-subtree steward must have a record; the sibling must have none.
	c1records, err := upgradeStore.ListUpgradesBySteward(context.Background(), "steward-c1")
	require.NoError(t, err)
	assert.Len(t, c1records, 1, "in-subtree steward must receive an upgrade record")
	c2records, err := upgradeStore.ListUpgradesBySteward(context.Background(), "steward-c2")
	require.NoError(t, err)
	assert.Empty(t, c2records, "sibling-subtree steward must not receive an upgrade record")
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
	req = withScopedPrincipal(req, "tenant-a")
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

// --- Admin mTLS empty-tenant tests (Issue #1999) ---

// dispatchUpgradeAsAdmin calls handleDispatchUpgrade with an admin mTLS principal
// (IsAdmin=true, empty tenant) injected, exactly as the middleware does for an mTLS cert.
func dispatchUpgradeAsAdmin(server *Server, selector, version, platform, arch string) *httptest.ResponseRecorder {
	body := dispatchUpgradeRequest{Selector: selector, Version: version, Platform: platform, Arch: arch}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade", bytes.NewReader(b))
	req = withAdminPrincipal(req)
	rec := httptest.NewRecorder()
	server.handleDispatchUpgrade(rec, req)
	return rec
}

// statusUpgradeAsAdmin calls handleUpgradeStatus with an admin mTLS principal injected.
func statusUpgradeAsAdmin(server *Server, upgradeID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/upgrade/"+upgradeID, nil)
	req = withAdminPrincipal(req)
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": upgradeID})
	rec := httptest.NewRecorder()
	server.handleUpgradeStatus(rec, req)
	return rec
}

// rollbackUpgradeAsAdmin calls handleUpgradeRollback with an admin mTLS principal injected.
func rollbackUpgradeAsAdmin(server *Server, upgradeID, targetVersion string) *httptest.ResponseRecorder {
	body := rollbackRequest{Version: targetVersion}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade/"+upgradeID+"/rollback", bytes.NewReader(b))
	req = withAdminPrincipal(req)
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": upgradeID})
	rec := httptest.NewRecorder()
	server.handleUpgradeRollback(rec, req)
	return rec
}

// emptyScopedReq models a NON-admin caller with no tenant (genuine auth failure).
func emptyScopedReq(req *http.Request) *http.Request { return withScopedPrincipal(req, "") }

// TestDispatch_AdminEmptyTenant_NotUnauthorized verifies that an admin mTLS principal
// (empty tenant) is NOT rejected with 401 on dispatch; it acts on every matched steward
// regardless of tenant, using the global (empty-tenant) binary namespace (Issue #1999).
func TestDispatch_AdminEmptyTenant_NotUnauthorized(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-x", TenantID: "tenant-x", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-x", stewards)
	// Admins (empty tenant) read the binary from the "default" namespace — the blob store
	// requires a non-empty tenant, so admin writes/reads fall back to "default" (Issue #1999).
	publishApprovedBinary(t, server, "default", "v0.5.12", "linux", "amd64")

	rec := dispatchUpgradeAsAdmin(server, "id:steward-x", "v0.5.12", "linux", "amd64")

	require.NotEqual(t, http.StatusUnauthorized, rec.Code,
		"admin mTLS principal with empty tenant must not be rejected with 401: %s", rec.Body.String())
	require.Equal(t, http.StatusAccepted, rec.Code, "admin dispatch must be accepted: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data := resp.Data.(map[string]interface{})
	upgradeID := data["upgrade_id"].(string)
	record, err := upgradeStore.GetUpgrade(context.Background(), upgradeID)
	require.NoError(t, err)
	assert.Equal(t, "steward-x", record.StewardID)
	// Admin-dispatched records are attributed to the target steward's tenant.
	assert.Equal(t, "tenant-x", record.TenantID)
	assert.Equal(t, "mtls_admin", record.InitiatedBy.AuthMethod)
}

// TestDispatch_NonAdminEmptyTenant_Unauthorized verifies that a NON-admin principal with
// no tenant gets 401 from authRunAccess on dispatch, and — critically — that the auth gate
// PRECEDES the tenant-isolation loop. The only steward belongs to "tenant-a", so if the
// empty-tenant auth check were removed, execution would fall through to the isolation loop
// (callerTenantID="" matches no steward) and return 403 CROSS_TENANT instead. Asserting 401
// AUTHENTICATION_REQUIRED (not 403) pins the ordering: auth before isolation (Issue #1999, B3).
func TestDispatch_NonAdminEmptyTenant_Unauthorized(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	body := dispatchUpgradeRequest{Selector: "id:steward-1", Version: "v0.5.12", Platform: "linux", Arch: "amd64"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade", bytes.NewReader(b))
	req = emptyScopedReq(req)
	rec := httptest.NewRecorder()
	server.handleDispatchUpgrade(rec, req)

	// Must be 401 from the auth gate, NOT 403 from the isolation loop further down.
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"non-admin empty-tenant must be rejected by authRunAccess (401), before the isolation loop")
	assert.Contains(t, rec.Body.String(), "AUTHENTICATION_REQUIRED")
	assert.NotContains(t, rec.Body.String(), "CROSS_TENANT",
		"401 must precede the isolation loop; a CROSS_TENANT (403) here would mean auth ran after isolation")
}

// TestUpgradeStatus_AdminEmptyTenant_SeesAnyTenantRecord verifies that an admin mTLS
// principal can read a record owned by any tenant (no 401, no 403) — Issue #1999.
func TestUpgradeStatus_AdminEmptyTenant_SeesAnyTenantRecord(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	// A tenant-scoped caller creates the record (TenantID=tenant-a).
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	upgradeID := resp.Data.(map[string]interface{})["upgrade_id"].(string)

	// Admin (empty tenant) must be able to view tenant-a's record.
	statusRec := statusUpgradeAsAdmin(server, upgradeID)
	require.NotEqual(t, http.StatusUnauthorized, statusRec.Code,
		"admin mTLS principal with empty tenant must not be rejected with 401 on status")
	assert.Equal(t, http.StatusOK, statusRec.Code, "admin must see any tenant's record: %s", statusRec.Body.String())
}

// TestUpgradeStatus_NonAdminEmptyTenant_Unauthorized verifies that a NON-admin caller
// with no tenant still gets 401 on status (regression guard, Issue #1999).
func TestUpgradeStatus_NonAdminEmptyTenant_Unauthorized(t *testing.T) {
	server, _ := setupUpgradeServer(t, "tenant-a", nil)
	server.upgradeStore = newTestUpgradeStore()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/upgrade/some-id", nil)
	req = emptyScopedReq(req)
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": "some-id"})
	rec := httptest.NewRecorder()
	server.handleUpgradeStatus(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "AUTHENTICATION_REQUIRED")
}

// TestUpgradeStatus_NonAdminCrossTenant_StillForbidden verifies that the existing
// cross-tenant isolation is preserved for scoped (non-admin) callers (Issue #1999).
func TestUpgradeStatus_NonAdminCrossTenant_StillForbidden(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	upgradeID := resp.Data.(map[string]interface{})["upgrade_id"].(string)

	// tenant-b (scoped non-admin) must still be forbidden from viewing tenant-a's record.
	statusRec := doUpgradeStatus(server, "tenant-b", upgradeID)
	assert.Equal(t, http.StatusForbidden, statusRec.Code)
}

// TestUpgradeRollback_AdminEmptyTenant_NotUnauthorized verifies that an admin mTLS
// principal can roll back a record owned by any tenant (no 401, no 403). Two distinct
// namespaces are at play and must not be conflated (Issue #1999):
//   - The rollback BINARY is fetched from the admin's "default" blob namespace
//     (handlers_upgrade.go uses installerBlobTenant(callerTenantID), and an admin's caller
//     tenant is empty → "default"); it is NOT fetched from the original record's tenant.
//   - The rollback RECORD's TenantID inherits original.TenantID (effectiveTenantID) so
//     per-tenant status/listing isolation stays consistent.
func TestUpgradeRollback_AdminEmptyTenant_NotUnauthorized(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")
	// The admin rollback fetches the rollback binary from the admin "default" namespace.
	publishApprovedBinary(t, server, "default", "v0.5.11", "linux", "amd64")

	// Tenant-scoped caller creates and commits the original upgrade record.
	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	upgradeID := resp.Data.(map[string]interface{})["upgrade_id"].(string)
	require.NoError(t, upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID, business.UpgradeStatusCommitted, ""))

	// Admin (empty tenant) rolls back tenant-a's record.
	rollbackRec := rollbackUpgradeAsAdmin(server, upgradeID, "v0.5.11")
	require.NotEqual(t, http.StatusUnauthorized, rollbackRec.Code,
		"admin mTLS principal with empty tenant must not be rejected with 401 on rollback")
	assert.Equal(t, http.StatusAccepted, rollbackRec.Code, "admin rollback must be accepted: %s", rollbackRec.Body.String())

	// The rollback record must carry the original record's tenant (not empty).
	var rbResp APIResponse
	require.NoError(t, json.Unmarshal(rollbackRec.Body.Bytes(), &rbResp))
	rbID := rbResp.Data.(map[string]interface{})["upgrade_id"].(string)
	rbRecord, err := upgradeStore.GetUpgrade(context.Background(), rbID)
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", rbRecord.TenantID, "admin rollback record must inherit the original record's tenant")
}

// TestUpgradeRollback_AdminEmptyTenant_BinaryAbsentFromDefault404 pins the actual fetch
// namespace for an admin rollback: the binary is read from "default", NOT from the original
// record's tenant. The rollback target binary is published ONLY under the original record's
// tenant ("tenant-a") and is intentionally absent from "default", so the admin rollback must
// return 404 — proving the fetch resolves against "default" (Issue #1999).
func TestUpgradeRollback_AdminEmptyTenant_BinaryAbsentFromDefault404(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-1", TenantID: "tenant-a", Status: "online"},
	}
	server, upgradeStore := setupUpgradeServer(t, "tenant-a", stewards)
	publishApprovedBinary(t, server, "tenant-a", "v0.5.12", "linux", "amd64")
	// Rollback target published ONLY under tenant-a, NOT under "default".
	publishApprovedBinary(t, server, "tenant-a", "v0.5.11", "linux", "amd64")

	rec := doDispatchUpgrade(server, "tenant-a", "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	upgradeID := resp.Data.(map[string]interface{})["upgrade_id"].(string)
	require.NoError(t, upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID, business.UpgradeStatusCommitted, ""))

	// Admin rollback must look in "default" (where v0.5.11 is absent) and 404 — not find
	// the tenant-a copy. This is the negative proof of the actual fetch namespace.
	rollbackRec := rollbackUpgradeAsAdmin(server, upgradeID, "v0.5.11")
	require.NotEqual(t, http.StatusUnauthorized, rollbackRec.Code,
		"admin auth must pass; this asserts the blob namespace, not auth")
	assert.Equal(t, http.StatusNotFound, rollbackRec.Code,
		"admin rollback binary is fetched from \"default\", not the record tenant: %s", rollbackRec.Body.String())
	assert.Contains(t, rollbackRec.Body.String(), "BINARY_NOT_FOUND")
}

// TestUpgradeRollback_NonAdminEmptyTenant_Unauthorized verifies that a NON-admin caller
// with no tenant still gets 401 on rollback (regression guard, Issue #1999).
func TestUpgradeRollback_NonAdminEmptyTenant_Unauthorized(t *testing.T) {
	server, _ := setupUpgradeServer(t, "tenant-a", nil)
	server.upgradeStore = newTestUpgradeStore()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/upgrade/some-id/rollback",
		bytes.NewReader([]byte(`{"version":"v0.5.11"}`)))
	req = emptyScopedReq(req)
	req = mux.SetURLVars(req, map[string]string{"upgrade_id": "some-id"})
	rec := httptest.NewRecorder()
	server.handleUpgradeRollback(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "AUTHENTICATION_REQUIRED")
}

// --- B2: end-to-end admin delivery-path round-trip (Issue #1999) ---

// capturingControlPlane is a real controlplaneInterfaces.ControlPlaneProvider that records
// the SignedCommands dispatched through it (including their params). It is NOT a mock — it
// has no expectations and satisfies the full provider contract.
type capturingControlPlane struct {
	mu       sync.Mutex
	commands []*controlplaneTypes.SignedCommand
}

func (c *capturingControlPlane) Name() string      { return "capturing" }
func (c *capturingControlPlane) IsConnected() bool { return true }
func (c *capturingControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (c *capturingControlPlane) Start(_ context.Context) error { return nil }
func (c *capturingControlPlane) Stop(_ context.Context) error  { return nil }
func (c *capturingControlPlane) SendCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commands = append(c.commands, cmd)
	return nil
}
func (c *capturingControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.SignedCommand, _ []string) (*controlplaneTypes.FanOutResult, error) {
	return nil, fmt.Errorf("FanOutCommand must not be called in this test")
}
func (c *capturingControlPlane) SubscribeCommands(_ context.Context, _ string, _ controlplaneInterfaces.CommandHandler) error {
	return nil
}
func (c *capturingControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}
func (c *capturingControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, _ controlplaneInterfaces.EventHandler) error {
	return nil
}
func (c *capturingControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}
func (c *capturingControlPlane) SubscribeHeartbeats(_ context.Context, _ controlplaneInterfaces.HeartbeatHandler) error {
	return nil
}
func (c *capturingControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}
func (c *capturingControlPlane) Reconnect(_ context.Context) error { return nil }

// downloadURLs returns the download_url param from every captured PushStewardBinary command.
func (c *capturingControlPlane) downloadURLs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, cmd := range c.commands {
		if du, ok := cmd.Command.Params["download_url"].(string); ok {
			out = append(out, du)
		}
	}
	return out
}

// doGetStewardBinaryPublic calls handleGetStewardBinaryPublic with the given tenant query
// param (no auth — the public endpoint authenticates via the binary signature steward-side).
func doGetStewardBinaryPublic(server *Server, version, platform, arch, tenant string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/public/steward-binaries/"+version+"/"+platform+"/"+arch+"?tenant="+tenant, nil)
	req = mux.SetURLVars(req, map[string]string{"version": version, "platform": platform, "arch": arch})
	rec := httptest.NewRecorder()
	server.handleGetStewardBinaryPublic(rec, req)
	return rec
}

// TestAdminDispatch_EndToEndDeliveryPath_DefaultNamespace exercises the full admin delivery
// path: admin publish (lands in "default") → admin dispatch (download_url must carry
// tenant=default, not empty) → public download with ?tenant=default returns those exact bytes.
// This covers the publish-namespace ↔ dispatch-download-URL ↔ public-download contract that
// was previously untested (Issue #1999, B2).
func TestAdminDispatch_EndToEndDeliveryPath_DefaultNamespace(t *testing.T) {
	stewards := []fleet.StewardData{
		{ID: "steward-x", TenantID: "tenant-x", Status: "online"},
	}
	server, _ := setupUpgradeServer(t, "tenant-x", stewards)

	// Wire a real command publisher backed by a capturing control plane so the dispatch
	// fan-out goroutine records the download_url it would send to the steward.
	cp := &capturingControlPlane{}
	pub, err := commands.New(&commands.Config{
		ControlPlane: cp,
		Signer:       nil,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	server.commandPublisher = pub

	// 1. Admin publishes the steward binary via the publish handler (no manual blob seeding),
	//    proving the publish handler itself lands the blob in "default" for an admin.
	content := []byte("cfgms-steward-binary-e2e-admin")
	fix := newStewardBinaryFixture(t)
	server.stewardBinaryTrustStore = fix.store
	sigBase64 := fix.signContent(content)
	pubRec := publishWithPrincipal(server, withAdminPrincipal, "v0.5.12", "linux", "amd64", sigBase64, content)
	require.Equal(t, http.StatusOK, pubRec.Code, "admin publish must succeed: %s", pubRec.Body.String())

	// The publish path does not auto-approve; dispatch requires approved_by. Re-publish the
	// same content with the approved label into "default" so dispatch's approval gate passes.
	approvedContent := publishApprovedBinary(t, server, "default", "v0.5.12", "linux", "amd64")

	// 2. Admin dispatches the upgrade.
	rec := dispatchUpgradeAsAdmin(server, "id:steward-x", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, rec.Code, "admin dispatch must be accepted: %s", rec.Body.String())

	// The dispatch fan-out runs in a background goroutine; wait for the command to land.
	require.Eventually(t, func() bool {
		return len(cp.downloadURLs()) > 0
	}, 2*time.Second, 5*time.Millisecond, "dispatch must publish a PushStewardBinary command")

	// 2a. The download_url must carry tenant=default (not empty), pointing at the public path.
	urls := cp.downloadURLs()
	require.Len(t, urls, 1)
	assert.Contains(t, urls[0], "tenant=default",
		"admin dispatch download_url must reference the default namespace: %s", urls[0])
	assert.NotRegexp(t, `tenant=($|&)`, urls[0], "download_url tenant param must not be empty")
	assert.Contains(t, urls[0], "/api/v1/public/steward-binaries/v0.5.12/linux/amd64",
		"download_url must target the public download endpoint")

	// 2b. The public download endpoint with ?tenant=default returns the approved binary that
	//     was published under "default", closing the delivery loop.
	getRec := doGetStewardBinaryPublic(server, "v0.5.12", "linux", "amd64", "default")
	require.Equal(t, http.StatusOK, getRec.Code,
		"public download with tenant=default must return the published binary: %s", getRec.Body.String())
	assert.Equal(t, approvedContent, getRec.Body.Bytes(),
		"public download must return the exact bytes published under default")
}

// ── Tenant isolation regression test — Issue #2781 ───────────────────────────

// TestUpgradeStatus_AssuranceBoundary is a table-driven regression test
// confirming that the Assurance-based tenant-isolation gates in handlers_upgrade.go
// are byte-for-byte equivalent to the deleted IsAdmin-based checks:
//   - AssuranceBasic (admin) principal gets global read access regardless of the record's tenant.
//   - AssuranceMachine (API key) principal sees only same-tenant records (403 otherwise).
func TestUpgradeStatus_AssuranceBoundary(t *testing.T) {
	const recordTenant = "tenant-a"

	stewards := []fleet.StewardData{{ID: "steward-1", TenantID: recordTenant, Status: "online"}}
	server, _ := setupUpgradeServer(t, recordTenant, stewards)
	publishApprovedBinary(t, server, recordTenant, "v0.5.12", "linux", "amd64")

	// Create one upgrade record owned by tenant-a.
	dispRec := doDispatchUpgrade(server, recordTenant, "id:steward-1", "v0.5.12", "linux", "amd64")
	require.Equal(t, http.StatusAccepted, dispRec.Code)
	var dispResp APIResponse
	require.NoError(t, json.Unmarshal(dispRec.Body.Bytes(), &dispResp))
	upgradeID := dispResp.Data.(map[string]interface{})["upgrade_id"].(string)

	cases := []struct {
		name       string
		tenantID   string
		isAdmin    bool
		wantStatus int
	}{
		{
			name:       "AssuranceBasic_admin_any_tenant",
			tenantID:   "",
			isAdmin:    true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "AssuranceMachine_same_tenant",
			tenantID:   recordTenant,
			isAdmin:    false,
			wantStatus: http.StatusOK,
		},
		{
			name:       "AssuranceMachine_cross_tenant_403",
			tenantID:   "tenant-b",
			isAdmin:    false,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if tc.isAdmin {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/upgrade/"+upgradeID, nil)
				req = withAdminPrincipal(req)
				req = mux.SetURLVars(req, map[string]string{"upgrade_id": upgradeID})
				rec = httptest.NewRecorder()
				server.handleUpgradeStatus(rec, req)
			} else {
				rec = doUpgradeStatus(server, tc.tenantID, upgradeID)
			}
			assert.Equal(t, tc.wantStatus, rec.Code,
				"tenantID=%q isAdmin=%v accessing upgrade record in %q", tc.tenantID, tc.isAdmin, recordTenant)
		})
	}
}
