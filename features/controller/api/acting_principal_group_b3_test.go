// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// Group B part 3 of the #6425 sweep: the steward config-update, decommission and
// visibility handlers and the tenant deletion request and approval handlers. Each
// records who acted (a command record's IssuedBy, an audit User, a pending deletion's
// RequestedBy, a deletion approver), so each refuses a request with no actor.

// b3Request builds a request to a handler with {id} bound, the given tenant scope
// ("" is a root caller) and p as the principal, or none when p is nil. The scope is
// set even without a principal, so the missing actor is the only reason to refuse.
func b3Request(method, path, body, id, scopeTenant string, p *Principal) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": id})
	ctx := withCallerTenant(req.Context(), scopeTenant)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, fixtureCallerTenant(scopeTenant))
	return req.WithContext(withActor(ctx, p))
}

// TestHandleUpdateStewardConfig_NoActor_Returns401 pins that a config update without
// an acting principal is refused before the configuration is stored or a delivery
// record is written (handlers_stewards.go recordConfigUpdateDelivery IssuedBy).
func TestHandleUpdateStewardConfig_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	commandStore := pkgtesting.SetupTestStorage(t).GetCommandStore()
	require.NotNil(t, commandStore)
	server.SetCommandStore(commandStore)
	const stewardID = "b3-cfg-steward"
	const tenantID = "test-tenant"
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, tenantID, "addr", "active"))

	put := func(p *Principal) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/stewards/"+stewardID+"/config",
			bytes.NewReader(validCfgUploadBody(stewardID)))
		req.Header.Set("Content-Type", "application/yaml")
		req = mux.SetURLVars(req, map[string]string{"id": stewardID})
		ctx := withCallerTenant(req.Context(), tenantID)
		rec := httptest.NewRecorder()
		server.handleUpdateStewardConfig(rec, req.WithContext(withActor(ctx, p)))
		return rec
	}
	stored := func() int {
		rec := httptest.NewRecorder()
		getReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+stewardID+"/config", nil)
		getReq = withPrincipal(getReq, &Principal{ID: "reader", Assurance: session.AssuranceStrong, TenantID: tenantID, ImplicitAdmin: true})
		getReq = withVars(getReq, map[string]string{"id": stewardID})
		server.handleGetStewardConfig(rec, getReq)
		return rec.Code
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, put(tc.principal))
			assert.NotEqual(t, http.StatusOK, stored(), "no configuration may be stored")
			records, err := commandStore.ListCommandRecords(context.Background(), &business.CommandFilter{StewardID: stewardID})
			require.NoError(t, err)
			assert.Empty(t, records, "no delivery record may be written")
		})
	}

	admin := &Principal{ID: "b3-admin", Assurance: session.AssuranceStrong, TenantID: tenantID, Permissions: []string{"steward:write-config"}}
	rec := put(admin)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	assert.Equal(t, http.StatusOK, stored(), "the configuration is stored")
	records, err := commandStore.ListCommandRecords(context.Background(), &business.CommandFilter{StewardID: stewardID})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, admin.ID, records[0].IssuedBy)
}

// TestHandleDecommissionSteward_NoActor_Returns401 pins that a decommission without an
// acting principal is refused with the steward left active and no audit entry
// (handlers_stewards.go emitDecommissionAudit User).
func TestHandleDecommissionSteward_NoActor_Returns401(t *testing.T) {
	server, st := setupDecommissionServer(t)
	const stewardID = "s-b3-decomm"
	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID: stewardID, TenantID: "test-tenant", Status: business.StewardStatusActive,
	}))
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, "test-tenant", "addr", "active"))

	decommission := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleDecommissionSteward(rec, b3Request(http.MethodDelete, "/api/v1/stewards/"+stewardID, "", stewardID, "", p))
		return rec
	}

	for _, tc := range noActorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, decommission(tc.principal))
			got, err := st.GetSteward(context.Background(), stewardID)
			require.NoError(t, err)
			assert.Equal(t, business.StewardStatusActive, got.Status, "the steward must not be tombstoned")
			assert.Empty(t, auditEntriesByAction(t, server, "steward.decommissioned"))
		})
	}

	admin := &Principal{ID: "b3-admin", Assurance: session.AssuranceBasic}
	rec := decommission(admin)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	got, err := st.GetSteward(context.Background(), stewardID)
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusDeregistered, got.Status)
	events := auditEntriesByAction(t, server, "steward.decommissioned")
	require.Len(t, events, 1)
	assert.Equal(t, admin.ID, events[0].UserID)
}

// TestHandleSetStewardVisibility_NoActor_Returns401 pins that a visibility change
// without an acting principal is refused with the steward still visible and no audit
// entry (handlers_stewards.go emitVisibilityAudit User).
func TestHandleSetStewardVisibility_NoActor_Returns401(t *testing.T) {
	server, st := setupVisibilityServer(t)
	const stewardID = "s-b3-vis"
	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID: stewardID, TenantID: "test-tenant", Status: business.StewardStatusActive,
	}))

	setHidden := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleSetStewardVisibility(rec, b3Request(http.MethodPatch,
			"/api/v1/stewards/"+stewardID+"/visibility", fmt.Sprintf(`{"hidden":%v}`, true), stewardID, "", p))
		return rec
	}

	for _, tc := range noActorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, setHidden(tc.principal))
			got, err := st.GetSteward(context.Background(), stewardID)
			require.NoError(t, err)
			assert.False(t, got.Hidden, "the steward must not be hidden")
			assert.Empty(t, auditEntriesByAction(t, server, "steward.visibility_changed"))
		})
	}

	admin := &Principal{ID: "b3-admin", Assurance: session.AssuranceBasic}
	rec := setHidden(admin)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	got, err := st.GetSteward(context.Background(), stewardID)
	require.NoError(t, err)
	assert.True(t, got.Hidden)
	events := auditEntriesByAction(t, server, "steward.visibility_changed")
	require.Len(t, events, 1)
	assert.Equal(t, admin.ID, events[0].UserID)
}

// TestHandleRequestTenantDeletion_NoActor_Returns401 pins that a deletion request
// without an acting principal is refused and no pending deletion is recorded
// (handlers_tenants.go RequestTenantDeletion requesterID).
func TestHandleRequestTenantDeletion_NoActor_Returns401(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	createSuspendedTenant(t, server, "b3-del-req")

	for _, tc := range noActorCases("b3-del-req") {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, requestDeletionAs(server, tc.principal, "b3-del-req"))
			_, err := server.tenantManager.GetPendingDeletion(context.Background(), "b3-del-req")
			assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound, "no pending deletion may be recorded")
		})
	}

	alice := &Principal{ID: "alice", TenantID: "b3-del-req"}
	rec := requestDeletionAs(server, alice, "b3-del-req")
	require.Equal(t, http.StatusAccepted, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	pending, err := server.tenantManager.GetPendingDeletion(context.Background(), "b3-del-req")
	require.NoError(t, err)
	assert.Equal(t, alice.ID, pending.RequestedBy)
}

// TestHandleApproveTenantDeletion_NoActor_Returns401 pins that an approval without an
// acting principal is refused with the tenant and its pending deletion intact
// (handlers_tenants.go ApproveTenantDeletion approverID). Dual control is off so the
// only reason the approval is refused is the missing actor.
func TestHandleApproveTenantDeletion_NoActor_Returns401(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	ctx := context.Background()
	setMinimalHold(t, server, false)
	createSuspendedTenant(t, server, "b3-del-approve")
	alice := &Principal{ID: "alice", TenantID: "b3-del-approve"}
	require.Equal(t, http.StatusAccepted, requestDeletionAs(server, alice, "b3-del-approve").Code)
	waitUntilHoldElapsed(t, server, "b3-del-approve")

	for _, tc := range noActorCases("b3-del-approve") {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, approveDeletionAs(server, tc.principal, "b3-del-approve"))
			_, err := server.tenantManager.GetTenant(ctx, "b3-del-approve")
			require.NoError(t, err, "the tenant must not be deleted")
			_, err = server.tenantManager.GetPendingDeletion(ctx, "b3-del-approve")
			require.NoError(t, err, "the pending deletion must stay")
		})
	}

	rec := approveDeletionAs(server, alice, "b3-del-approve")
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	_, err := server.tenantManager.GetTenant(ctx, "b3-del-approve")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
}
