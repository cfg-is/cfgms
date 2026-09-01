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
