// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// setupCommandTestServer builds a real (non-mocked) server wired with a
// SQLite-backed CommandStore, for the GET /api/v1/commands/{id} and
// GET /api/v1/stewards/{id}/pending-deliveries tests.
func setupCommandTestServer(t *testing.T) (*Server, business.CommandStore) {
	t.Helper()
	server := setupTestServer(t)
	storageManager := pkgtesting.SetupTestStorage(t)
	commandStore := storageManager.GetCommandStore()
	require.NotNil(t, commandStore)
	server.SetCommandStore(commandStore)
	return server, commandStore
}

func newGetCommandRequest(t *testing.T, id string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/commands/"+id, nil)
	return mux.SetURLVars(req, map[string]string{"id": id})
}

func newPendingDeliveriesRequest(t *testing.T, stewardID string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+stewardID+"/pending-deliveries", nil)
	return mux.SetURLVars(req, map[string]string{"id": stewardID})
}

func createCommandRecord(t *testing.T, store business.CommandStore, id, stewardID, tenantID string) *business.CommandRecord {
	t.Helper()
	rec := &business.CommandRecord{
		ID:        id,
		Type:      "sync_config",
		StewardID: stewardID,
		TenantID:  tenantID,
		IssuedBy:  "test",
	}
	require.NoError(t, store.CreateCommandRecord(context.Background(), rec))
	return rec
}

// ---------------------------------------------------------------------------
// GET /api/v1/commands/{id}
// ---------------------------------------------------------------------------

func TestHandleGetCommandRecord_NilStoreSends503(t *testing.T) {
	server := setupTestServer(t) // commandStore is nil
	req := withScopedPrincipal(newGetCommandRequest(t, "cmd-does-not-matter"), "tenant-a")
	rec := httptest.NewRecorder()

	server.handleGetCommandRecord(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleGetCommandRecord_MissingPrincipal(t *testing.T) {
	server, _ := setupCommandTestServer(t)
	req := newGetCommandRequest(t, "cmd-1") // no principal injected
	rec := httptest.NewRecorder()

	server.handleGetCommandRecord(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleGetCommandRecord_UnknownID404(t *testing.T) {
	server, _ := setupCommandTestServer(t)
	req := withScopedPrincipal(newGetCommandRequest(t, "cmd-unknown"), "tenant-a")
	rec := httptest.NewRecorder()

	server.handleGetCommandRecord(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleGetCommandRecord_OwnTenantCanRead(t *testing.T) {
	server, store := setupCommandTestServer(t)
	rec := createCommandRecord(t, store, "cmd-own", "steward-a", "tenant-a")

	req := withScopedPrincipal(newGetCommandRequest(t, rec.ID), "tenant-a")
	w := httptest.NewRecorder()

	server.handleGetCommandRecord(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp CommandRecordResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "cmd-own", resp.ID)
	assert.Equal(t, "steward-a", resp.StewardID)
	assert.Equal(t, string(business.DeliveryStatusPending), resp.DeliveryStatus)
}

// TestHandleGetCommandRecord_CrossTenantReturn404 is the required cross-tenant
// isolation test for delivery-record reads by command ID (Issue #3757 AC: "a
// caller from tenant A cannot read a delivery record belonging to tenant B").
// 404, not 403, so the response cannot be used as an existence oracle for
// command IDs belonging to another tenant.
func TestHandleGetCommandRecord_CrossTenantReturn404(t *testing.T) {
	server, store := setupCommandTestServer(t)
	rec := createCommandRecord(t, store, "cmd-tenant-b", "steward-b", "tenant-b")

	req := withScopedPrincipal(newGetCommandRequest(t, rec.ID), "tenant-a")
	w := httptest.NewRecorder()

	server.handleGetCommandRecord(w, req)

	require.Equal(t, http.StatusNotFound, w.Code,
		"tenant-a caller must not be able to read tenant-b's delivery record")
}

func TestHandleGetCommandRecord_AdminCanReadAnyTenant(t *testing.T) {
	server, store := setupCommandTestServer(t)
	rec := createCommandRecord(t, store, "cmd-admin-read", "steward-c", "tenant-c")

	req := withAdminPrincipal(newGetCommandRequest(t, rec.ID))
	w := httptest.NewRecorder()

	server.handleGetCommandRecord(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandleGetCommandRecord_RouteRegistered(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/commands/some-id", nil)
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	// No API key supplied → 401, not 404. Route exists.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ---------------------------------------------------------------------------
// GET /api/v1/stewards/{id}/pending-deliveries
// ---------------------------------------------------------------------------

func TestHandleListPendingDeliveries_NilStoreSends503(t *testing.T) {
	server := setupTestServer(t)
	req := withScopedPrincipal(newPendingDeliveriesRequest(t, "steward-x"), "tenant-a")
	rec := httptest.NewRecorder()

	server.handleListPendingDeliveries(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleListPendingDeliveries_UnknownStewardReturns404(t *testing.T) {
	server, _ := setupCommandTestServer(t)
	req := withScopedPrincipal(newPendingDeliveriesRequest(t, "steward-unknown"), "tenant-a")
	rec := httptest.NewRecorder()

	server.handleListPendingDeliveries(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleListPendingDeliveries_OwnTenantCanRead(t *testing.T) {
	server, store := setupCommandTestServer(t)
	stewardID := registerActiveSteward(t, server.controllerService, "pending-dna-a", "tenant-a")
	createCommandRecord(t, store, "cmd-pd-1", stewardID, "tenant-a")
	createCommandRecord(t, store, "cmd-pd-2", stewardID, "tenant-a")

	req := withScopedPrincipal(newPendingDeliveriesRequest(t, stewardID), "tenant-a")
	w := httptest.NewRecorder()

	server.handleListPendingDeliveries(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp PendingDeliveriesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, stewardID, resp.StewardID)
	assert.Len(t, resp.Deliveries, 2)
}

// TestHandleListPendingDeliveries_CrossTenantReturn404 is the required
// cross-tenant isolation test for delivery-record reads by steward ID (Issue
// #3757 AC: "a caller from tenant A cannot read a delivery record belonging to
// tenant B ... by steward ID"). The steward belongs to tenant-b; a tenant-a
// caller must not be able to enumerate its pending deliveries.
func TestHandleListPendingDeliveries_CrossTenantReturn404(t *testing.T) {
	server, store := setupCommandTestServer(t)
	stewardID := registerActiveSteward(t, server.controllerService, "pending-dna-b", "tenant-b")
	createCommandRecord(t, store, "cmd-pd-cross", stewardID, "tenant-b")

	req := withScopedPrincipal(newPendingDeliveriesRequest(t, stewardID), "tenant-a")
	w := httptest.NewRecorder()

	server.handleListPendingDeliveries(w, req)

	require.Equal(t, http.StatusNotFound, w.Code,
		"tenant-a caller must not be able to list tenant-b steward's pending deliveries")
}

// TestHandleListPendingDeliveries_ExcludesRecordsFromPreviousTenant covers the
// gap the steward-move path opens (POST /api/v1/stewards/{id}/move, Issue
// #2341). Authorizing on the steward's CURRENT tenant is not enough: rows
// written while the steward lived in tenant-b keep tenant_id "tenant-b" but stay
// attached to the same steward_id, and CommandRecordResponse carries tenant_id
// and issued_by — so returning them would disclose the previous tenant's path
// and its operator across an MSP boundary.
func TestHandleListPendingDeliveries_ExcludesRecordsFromPreviousTenant(t *testing.T) {
	server, store := setupCommandTestServer(t)
	stewardID := registerActiveSteward(t, server.controllerService, "pending-dna-moved", "tenant-a")
	// Written before the move, under the steward's previous tenant.
	createCommandRecord(t, store, "cmd-pd-previous", stewardID, "tenant-b")
	// Written after the move, under the steward's current tenant.
	createCommandRecord(t, store, "cmd-pd-current", stewardID, "tenant-a")

	req := withScopedPrincipal(newPendingDeliveriesRequest(t, stewardID), "tenant-a")
	w := httptest.NewRecorder()

	server.handleListPendingDeliveries(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp PendingDeliveriesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Deliveries, 1,
		"a record stamped with the steward's previous tenant must not be returned")
	assert.Equal(t, "cmd-pd-current", resp.Deliveries[0].ID)
	assert.Equal(t, "tenant-a", resp.Deliveries[0].TenantID)
}

// TestHandleListPendingDeliveries_AdminSeesOnlyStewardTenantChain proves the
// tenant filter is anchored to the steward, not to the caller: an unscoped mTLS
// admin (callerTenant "") still does not get another tenant's record back just
// because it happens to share a steward_id.
func TestHandleListPendingDeliveries_AdminSeesOnlyStewardTenantChain(t *testing.T) {
	server, store := setupCommandTestServer(t)
	stewardID := registerActiveSteward(t, server.controllerService, "pending-dna-admin-scope", "tenant-a")
	createCommandRecord(t, store, "cmd-pd-admin-current", stewardID, "tenant-a")
	createCommandRecord(t, store, "cmd-pd-admin-foreign", stewardID, "tenant-b")

	req := withAdminPrincipal(newPendingDeliveriesRequest(t, stewardID))
	w := httptest.NewRecorder()

	server.handleListPendingDeliveries(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp PendingDeliveriesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Deliveries, 1)
	assert.Equal(t, "cmd-pd-admin-current", resp.Deliveries[0].ID)
}

// TestHandleListPendingDeliveries_IncludesAncestorTenantRecords proves the
// tenant filter does not break subtree fan-out: handleConfigPush stamps each
// delivery row with the config's tenant, which for a push aimed at a tenant
// subtree is an ancestor of the targeted steward's own tenant. Those rows are
// legitimately owed to the steward and must still drain.
func TestHandleListPendingDeliveries_IncludesAncestorTenantRecords(t *testing.T) {
	server, store := setupCommandTestServer(t)
	stewardID := registerActiveSteward(t, server.controllerService, "pending-dna-subtree", "root/msp-a/client-1")
	createCommandRecord(t, store, "cmd-pd-subtree-own", stewardID, "root/msp-a/client-1")
	createCommandRecord(t, store, "cmd-pd-subtree-parent", stewardID, "root/msp-a")
	createCommandRecord(t, store, "cmd-pd-subtree-sibling", stewardID, "root/msp-a/client-2")

	req := withScopedPrincipal(newPendingDeliveriesRequest(t, stewardID), "root/msp-a")
	w := httptest.NewRecorder()

	server.handleListPendingDeliveries(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp PendingDeliveriesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	ids := make([]string, 0, len(resp.Deliveries))
	for _, d := range resp.Deliveries {
		ids = append(ids, d.ID)
	}
	assert.ElementsMatch(t, []string{"cmd-pd-subtree-own", "cmd-pd-subtree-parent"}, ids,
		"own and ancestor tenants drain; a sibling tenant's row never does")
}

func TestHandleListPendingDeliveries_AdminCanReadAnyTenant(t *testing.T) {
	server, store := setupCommandTestServer(t)
	stewardID := registerActiveSteward(t, server.controllerService, "pending-dna-admin", "tenant-c")
	createCommandRecord(t, store, "cmd-pd-admin", stewardID, "tenant-c")

	req := withAdminPrincipal(newPendingDeliveriesRequest(t, stewardID))
	w := httptest.NewRecorder()

	server.handleListPendingDeliveries(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandleListPendingDeliveries_RouteRegistered(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/some-id/pending-deliveries", nil)
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	// No API key supplied → 401, not 404. Route exists.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
