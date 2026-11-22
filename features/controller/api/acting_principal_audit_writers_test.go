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

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// The audit writers below used to read the principal from the request context
// themselves and wrote whatever they found (nothing, for a request with no principal)
// into the audit entry's actor. Each now takes the actor its handler resolved with
// requireActingPrincipal. One handler per writer is exercised here: with no principal,
// or one with an empty ID, it answers 401 AUTHENTICATION_REQUIRED, changes nothing and
// audits nothing; the same request from a principal with an ID succeeds and is audited
// under that ID.

// noActorRequest builds a request that reaches handler directly (no permission
// middleware) carrying principal p, which may be nil or have an empty ID.
func noActorRequest(method, path string, vars map[string]string, body interface{}, p *Principal) *http.Request {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}
	ctx := context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
	return req.WithContext(withActor(ctx, p))
}

// callAs runs handler with noActorRequest.
func callAs(handler http.HandlerFunc, p *Principal, method, path string, vars map[string]string, body interface{}) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler(rec, noActorRequest(method, path, vars, body, p))
	return rec
}

// requireAuditedAs asserts exactly one audit entry carries action and names actorID.
func requireAuditedAs(t *testing.T, server *Server, action, actorID string) *business.AuditEntry {
	t.Helper()
	events := auditEntriesByAction(t, server, action)
	require.Len(t, events, 1, "the action must be audited once")
	assert.Equal(t, actorID, events[0].UserID)
	return events[0]
}

// emitHypervProfileAudit.
func TestHandleCreateHypervProfile_NoActor_Returns401(t *testing.T) {
	server := setupHypervProfileServer(t)
	ps := hyperv.NewConfigBackedProfileStore(server.hypervProfileConfigStore, "tenant-x")
	create := func(p *Principal) *httptest.ResponseRecorder {
		return callAs(server.handleCreateHypervProfile, p, http.MethodPost, "/api/v1/hyperv/profiles?tenant=tenant-x",
			nil, hypervProfileRequest{
				Name: "debian-12", OSFamily: "linux", AnswerFormat: "preseed", Template: "hostname={{ .VMName }}",
				Enroll: hypervProfileEnroll{RegistrationTokenSecretKey: "hyperv/enroll/regtoken", BundleURL: "https://controller.example/bundle"},
			})
	}

	for _, tc := range noActorCases("tenant-x") {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, create(tc.principal))
			names, err := ps.ListProfiles(context.Background())
			require.NoError(t, err)
			assert.Empty(t, names, "no profile may be stored")
			assert.Empty(t, auditEntriesByAction(t, server, "hyperv_profile.created"))
		})
	}

	rec := createHypervProfileReq(t, server, hypervProfileStrongPrincipal("admin-1", "tenant-x"), validHypervProfilePayload("debian-12"))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	requireAuditedAs(t, server, "hyperv_profile.created", "admin-1")
}

// emitIPTrustAudit.
func TestHandleAddIPTrust_NoActor_Returns401(t *testing.T) {
	server, ipStore := newIPTrustServer(t)
	add := func(p *Principal) *httptest.ResponseRecorder {
		return callAs(server.handleAddIPTrust, p, http.MethodPost, "/api/v1/registration/ip-trust", nil,
			map[string]interface{}{"tenant_id": "acme", "cidr": "10.0.0.0/8"})
	}

	for _, tc := range noActorCases("acme") {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, add(tc.principal))
			entries, err := ipStore.ListTrustedRanges(context.Background(), "acme")
			require.NoError(t, err)
			assert.Empty(t, entries, "no range may be trusted")
			assert.Empty(t, auditEntriesByAction(t, server, "ip_trust.added"))
		})
	}

	require.Equal(t, http.StatusNoContent, add(&Principal{ID: "operator-7"}).Code)
	requireAuditedAs(t, server, "ip_trust.added", "operator-7")
}

// emitModuleApprovalAudit.
func TestHandleApproveModuleBundle_NoActor_Returns401(t *testing.T) {
	server, mc, _ := setupModuleApprovalServer(t)
	addr := makePendingBundle(t, mc, "cfgms", "hyperv", "0.2.1")
	vars := map[string]string{"address": formatModuleAddress(addr)}

	for _, tc := range noActorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			rec := callAs(server.handleApproveModuleBundle, tc.principal, http.MethodPost, "/", vars, nil)
			assertAuthenticationRequired(t, rec)
			status, err := mc.GetApprovalStatus(addr)
			require.NoError(t, err)
			assert.Equal(t, cache.ApprovalStatusPending, status, "the bundle must stay pending")
			assert.Empty(t, auditEntriesByAction(t, server, "module.bundle.approved"))
		})
	}

	principal := moduleTestStrongPrincipal()
	req := makeApproveRequest(t, server, formatModuleAddress(addr), principal)
	rec := httptest.NewRecorder()
	server.requirePermission("module", "approve")(http.HandlerFunc(server.handleApproveModuleBundle)).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, err := mc.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status)
	requireAuditedAs(t, server, "module.bundle.approved", principal.ID)
}

// emitOsqueryAudit.
func TestHandleOsqueryQuery_NoActor_Returns401(t *testing.T) {
	disp := &stubOsqueryDispatcher{rows: []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": "h"}}}}
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithStewardIDs("steward-1")
	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}

	for _, tc := range noActorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			rec := callAs(server.handleOsqueryQuery, tc.principal, http.MethodPost, "/api/v1/osquery/query", nil, body)
			assertAuthenticationRequired(t, rec)
			assert.Empty(t, dispatchedStewardIDs(disp), "no steward may be queried")
			assert.Empty(t, auditEntriesByAction(t, server, "osquery.query.dispatch"))
		})
	}

	principal := osqueryStrongPrincipal()
	req := makeOsqueryRequest(t, server, body, principal)
	rec := httptest.NewRecorder()
	server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery)).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, dispatchedStewardIDs(disp)["steward-1"])
	requireAuditedAs(t, server, "osquery.query.dispatch", principal.ID)
}

// emitRegistrationManagementAudit.
func TestHandleDenyRegistration_NoActor_Returns401(t *testing.T) {
	server, ts, pendingStore := newRegistrationApprovalServer(t)
	defer ts.Close()
	now := time.Now().UTC()
	require.NoError(t, pendingStore.AddPending(context.Background(), &business.PendingRegistrationEntry{
		PendingID: "pending-deny-1", StewardID: "steward-deny-1", TenantID: "tenant-a", TokenStr: "tok-deny-1",
		SourceIP: "10.0.0.2", RegisteredAt: now, ExpiresAt: now.Add(time.Hour),
		Status: business.PendingRegistrationStatusPending,
	}))
	vars := map[string]string{"id": "pending-deny-1"}

	for _, tc := range noActorCases("tenant-a") {
		t.Run(tc.name, func(t *testing.T) {
			rec := callAs(server.handleDenyRegistration, tc.principal, http.MethodPost, "/", vars, nil)
			assertAuthenticationRequired(t, rec)
			got, err := pendingStore.GetPendingByID(context.Background(), "pending-deny-1")
			require.NoError(t, err)
			assert.Equal(t, business.PendingRegistrationStatusPending, got.Status, "the entry must stay pending")
			assert.Empty(t, auditEntriesByAction(t, server, "registration.denied"))
		})
	}

	rec := callAs(server.handleDenyRegistration, &Principal{ID: "operator-3"}, http.MethodPost, "/", vars, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	got, err := pendingStore.GetPendingByID(context.Background(), "pending-deny-1")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusDenied, got.Status)
	requireAuditedAs(t, server, "registration.denied", "operator-3")
}

// emitTokenManagementAudit.
func TestHandleCreateRegistrationToken_NoActor_Returns401(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	create := func(p *Principal) *httptest.ResponseRecorder {
		return callAs(server.handleCreateRegistrationToken, p, http.MethodPost, "/api/v1/registration/tokens", nil,
			registration.TokenCreateRequest{TenantID: "tenant-a", ControllerURL: "grpc://controller.example.com:7443"})
	}

	for _, tc := range noActorCases("tenant-a") {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, create(tc.principal))
			tokens, err := tokenStore.ListTokens(context.Background(), "tenant-a")
			require.NoError(t, err)
			assert.Empty(t, tokens, "no token may be minted")
			assert.Empty(t, auditEntriesByAction(t, server, "registration_token.created"))
		})
	}

	rec := create(&Principal{ID: "operator-4"})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	tokens, err := tokenStore.ListTokens(context.Background(), "tenant-a")
	require.NoError(t, err)
	assert.Len(t, tokens, 1)
	requireAuditedAs(t, server, "registration_token.created", "operator-4")
}

// m365Audit.
func TestHandlePutTenantM365Connection_NoActor_Returns401(t *testing.T) {
	env := newM365Env(t)
	put := func(p *Principal) *httptest.ResponseRecorder {
		return callAs(env.server.handlePutTenantM365Connection, p, http.MethodPut, "/api/v1/tenants/client-a1/m365-connection",
			map[string]string{"id": "client-a1"},
			map[string]interface{}{"app_id": "app-1", "m365_tenant_id": "dir-1", "client_secret": m365TestSecret})
	}

	for _, tc := range noActorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, put(tc.principal))
			cfg, err := m365GetConfig(env.cs, "client-a1")
			require.NoError(t, err)
			assert.Nil(t, cfg, "no connection may be stored")
			assert.Empty(t, auditEntriesByAction(t, env.server, m365ActionSet))
		})
	}

	rec := env.set(t, "client-a1", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	cfg, err := m365GetConfig(env.cs, "client-a1")
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	requireAuditedAs(t, env.server, m365ActionSet, m365AdminPrincipal().ID)
}

// emitIdentityOperatorAudit.
func TestHandleRotateCredentials_NoActor_Returns401(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-rot-na", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	serials := env.issueClientCerts(t, "steward-rot-na", 1)
	vars := map[string]string{"id": "steward-rot-na"}

	for _, tc := range noActorCases(cloneTenant) {
		t.Run(tc.name, func(t *testing.T) {
			rec := callAs(env.server.handleRotateCredentials, tc.principal, http.MethodPost, "/", vars, nil)
			assertAuthenticationRequired(t, rec)
			revoked, err := env.certMgr.IsRevoked(serials[0])
			require.NoError(t, err)
			assert.False(t, revoked, "no certificate may be revoked")
			got, err := env.steward.GetSteward(context.Background(), "steward-rot-na")
			require.NoError(t, err)
			assert.Equal(t, business.StewardStatusActive, got.Status)
			assert.Empty(t, env.auditActions(t, auditActionCredentialsRotated))
		})
	}

	rec := callClone(env.server.handleRotateCredentials, http.MethodPost, "/", vars, cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	events := env.auditActions(t, auditActionCredentialsRotated)
	require.Len(t, events, 1)
	assert.Equal(t, "operator", events[0].UserID)
}

// emitOperatorAuditResult: a refused restore is audited as denied, and still names an actor.
func TestHandleRestoreTamperedSteward_Refused_NoActor_Returns401(t *testing.T) {
	const code = types.ReasonCodeTamperDataDir
	env := newTamperEnv(t)
	env.addTampered(t, "s-na-fault", cloneTenant, cloneDeviceA, time.Minute, code)
	vars := map[string]string{"id": "s-na-fault"}

	for _, tc := range noActorCases(cloneTenant) {
		t.Run(tc.name, func(t *testing.T) {
			rec := callAs(env.server.handleRestoreTamperedSteward, tc.principal, http.MethodPost, "/", vars, nil)
			assertAuthenticationRequired(t, rec)
			assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-na-fault"))
			assert.Empty(t, env.auditActions(t, auditActionTamperRestoreRefused),
				"a refusal is not recorded under an empty actor")
		})
	}

	rec := env.post(env.server.handleRestoreTamperedSteward, "restore", "s-na-fault", cloneTenant, nil)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	refused := env.auditActions(t, auditActionTamperRestoreRefused)
	require.Len(t, refused, 1)
	assert.Equal(t, "operator", refused[0].UserID)
	assert.Equal(t, business.AuditResultDenied, refused[0].Result)
}

// handleBanTamperedSteward calls emitIdentityOperatorAudit after changing the status
// and revoking serials, so the 401 has to come first.
func TestHandleBanTamperedSteward_NoActor_Returns401(t *testing.T) {
	env := newTamperEnv(t)
	env.addTampered(t, "s-na-ban", cloneTenant, cloneDeviceA, time.Minute)
	vars := map[string]string{"id": "s-na-ban"}

	for _, tc := range noActorCases(cloneTenant) {
		t.Run(tc.name, func(t *testing.T) {
			rec := callAs(env.server.handleBanTamperedSteward, tc.principal, http.MethodPost, "/", vars, nil)
			assertAuthenticationRequired(t, rec)
			assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-na-ban"))
			assert.Empty(t, env.auditActions(t, auditActionTamperBanned))
		})
	}

	rec := env.post(env.server.handleBanTamperedSteward, "ban", "s-na-ban", cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	banned := env.auditActions(t, auditActionTamperBanned)
	require.Len(t, banned, 1)
	assert.Equal(t, "operator", banned[0].UserID)
}

// handleRepairTamperedSteward feeds ApprovedBy and two audit entries from the actor.
func TestHandleRepairTamperedSteward_NoActor_Returns401(t *testing.T) {
	env := newRepairEnv(t)
	env.addTampered(t, "s-na-repair", cloneTenant, cloneDeviceA, time.Second)
	vars := map[string]string{"id": "s-na-repair"}
	body := map[string]interface{}{"reason": "recovered", "approved_loss_codes": []string{}}

	for _, tc := range noActorCases(cloneTenant) {
		t.Run(tc.name, func(t *testing.T) {
			rec := callAs(env.server.handleRepairTamperedSteward, tc.principal, http.MethodPost, "/", vars, body)
			assertAuthenticationRequired(t, rec)
			assert.Empty(t, env.sender.requests("s-na-repair"), "nothing may be sent to the steward")
			assert.Empty(t, env.auditActions(t, auditActionTamperRepairRequested))
			assert.Empty(t, env.auditActions(t, auditActionTamperRepairCancelled))
		})
	}

	resp := env.requestRepair(t, "s-na-repair", nil)
	entries := env.auditActions(t, auditActionTamperRepairRequested)
	require.Len(t, entries, 1)
	assert.Equal(t, "operator", entries[0].UserID)

	raw, found, err := env.server.nonceStore.GetAndConsumeNonce(context.Background(), repairRequestKey("s-na-repair", resp.RepairID))
	require.NoError(t, err)
	require.True(t, found)
	var stored repairRequestEntry
	require.NoError(t, json.Unmarshal(raw, &stored))
	assert.Equal(t, "operator", stored.ApprovedBy, "the approver is the acting principal")
}
