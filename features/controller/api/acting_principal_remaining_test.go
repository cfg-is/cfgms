// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Handlers that record an actor (an ApprovedBy, CreatedBy, UpdatedBy or GrantedBy
// field) resolve it through requireActingPrincipal and refuse with 401
// AUTHENTICATION_REQUIRED, changing nothing, when the context holds no principal or one
// with an empty ID (group A of the #6425 sweep). Each test below drives one handler
// directly with every noActorCases shape against an otherwise complete request, checks
// that nothing was stored and nothing audited, and then sends the same request as a real
// principal to show that the actor was the only reason it was refused.

// actorRequest builds a direct-handler-call request carrying route variables, the tenant
// identity and scope authenticationMiddleware would set for a caller of scopeTenant ("":
// root), and p as the principal (none when p is nil).
func actorRequest(method, path string, body []byte, vars map[string]string, scopeTenant string, p *Principal) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, fixtureCallerTenant(scopeTenant))
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scopeForVerifiedAdminCert(scopeTenant))
	return req.WithContext(withActor(ctx, p))
}

// auditEntryCount returns how many audit entries the server holds, of any action.
func auditEntryCount(t *testing.T, server *Server) int {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{})
	require.NoError(t, err)
	return len(entries)
}

// ---- handleApproveCliLoginRequest ----------------------------------------------------

func TestHandleApproveCliLoginRequest_NoActor_Returns401(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	_, hash := newTestVerifier(t)
	lodged := decodeLodgeCliLoginResponse(t, lodgeCliLogin(t, server, hash))
	payload, err := json.Marshal(ApproveCliLoginRequestBody{UserCode: lodged.UserCode})
	require.NoError(t, err)

	for _, tc := range noActorCases("approver-tenant") {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			req := actorRequest(http.MethodPost, "/api/v1/cli-login/"+lodged.RequestID+"/approve", payload,
				map[string]string{"id": lodged.RequestID}, "approver-tenant", tc.principal)
			rec := httptest.NewRecorder()
			server.handleApproveCliLoginRequest(rec, req)

			assertAuthenticationRequired(t, rec)
			stored, err := server.getCliLoginRequestByID(context.Background(), lodged.RequestID)
			require.NoError(t, err)
			require.NotNil(t, stored)
			assert.Equal(t, cliLoginRequestStatusPending, stored.Status)
			assert.Empty(t, stored.ApprovedBy)
			assert.Empty(t, stored.SessionID, "no session may be minted")
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	approver := browserPrincipalAfterPasskeyLogin("browser-op-1", false)
	approver.TenantID = "approver-tenant"
	rec := approveCliLogin(t, server, approver, lodged.RequestID, ApproveCliLoginRequestBody{UserCode: lodged.UserCode})
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := server.getCliLoginRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.Equal(t, approver.ID, stored.ApprovedBy)
}

// ---- handleMintEnrolmentToken --------------------------------------------------------

// countEnrolmentTokens returns how many enrolment tokens the server's secret store holds.
func countEnrolmentTokens(t *testing.T, server *Server) int {
	t.Helper()
	metas, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Tags:           []string{"enrolment_token"},
		Metadata:       map[string]string{secretsif.MetadataKeySecretType: enrolmentTokenSecretType},
		IncludeExpired: true,
	})
	require.NoError(t, err)
	return len(metas)
}

func TestHandleMintEnrolmentToken_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	const tenantID = "mint-tenant"
	payload, err := json.Marshal(MintEnrolmentTokenRequest{TenantID: tenantID})
	require.NoError(t, err)
	mint := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleMintEnrolmentToken(rec, actorRequest(http.MethodPost, "/api/v1/enrolment-tokens", payload, nil, tenantID, p))
		return rec
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, mint(tc.principal))
			assert.Zero(t, countEnrolmentTokens(t, server), "no enrolment token may be stored")
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := mint(operator)
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	var resp struct {
		Data EnrolmentTokenResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	tok, err := server.getEnrolmentTokenByID(context.Background(), resp.Data.ID)
	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.Equal(t, operator.ID, tok.CreatedBy)
}

// ---- handleApproveCredentialRequest --------------------------------------------------

func TestHandleApproveCredentialRequest_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	const tenantID = "approve-tenant"
	lodged := lodgeTestCredentialRequest(t, server, tenantID)
	acct := createApprovalTestAccount(t, server, "device-owner", tenantID)
	payload, err := json.Marshal(ApproveCredentialRequestBody{Fingerprint: lodged.PublicKeyFingerprint, AccountID: acct.ID})
	require.NoError(t, err)
	approve := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleApproveCredentialRequest(rec, actorRequest(http.MethodPost,
			"/api/v1/credential-requests/"+lodged.RequestID+"/approve", payload,
			map[string]string{"id": lodged.RequestID}, tenantID, p))
		return rec
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, approve(tc.principal))
			stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
			require.NoError(t, err)
			require.NotNil(t, stored)
			assert.Equal(t, credentialRequestStatusPending, stored.Status)
			assert.Empty(t, stored.ApprovedBy)
			assert.Empty(t, stored.BoundAccountID)
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	approver := implicitAdminPrincipal("approver-1")
	approver.TenantID = tenantID
	rec := approve(approver)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.Equal(t, credentialRequestStatusApproved, stored.Status)
	assert.Equal(t, approver.ID, stored.ApprovedBy)
}

// ---- handlePutTenantRebootWindow / handlePutStewardRebootWindow ----------------------

func TestHandlePutTenantRebootWindow_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()
	const tenantID = "reboot-actor-tenant"
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: tenantID, Name: tenantID, ParentID: testRootTenantID})
	require.NoError(t, err)
	payload, err := json.Marshal(rebootWindowPutRequest{ScheduleYAML: sampleScheduleYAML})
	require.NoError(t, err)
	put := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handlePutTenantRebootWindow(rec, actorRequest(http.MethodPut, "/api/v1/tenants/"+tenantID+"/reboot-window",
			payload, map[string]string{"tenant_id": tenantID}, tenantID, p))
		return rec
	}
	configStore := server.rebootWindowConfigStore()
	require.NotNil(t, configStore, "test server must expose a config store")
	key, err := server.rebootWindowTenantConfigKey(ctx, tenantID)
	require.NoError(t, err)

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, put(tc.principal))
			_, getErr := configStore.GetConfig(ctx, key)
			assert.True(t, errors.Is(getErr, cfgconfig.ErrConfigNotFound), "no config doc may be stored, got %v", getErr)
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := put(operator)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := configStore.GetConfig(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, operator.ID, stored.CreatedBy)
	assert.Equal(t, operator.ID, stored.UpdatedBy)
}

func TestHandlePutStewardRebootWindow_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()
	const tenantID = "reboot-actor-steward-tenant"
	const stewardID = "reboot-actor-steward"
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: tenantID, Name: tenantID, ParentID: testRootTenantID})
	require.NoError(t, err)
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, tenantID, "localhost:7021", "online"))
	payload, err := json.Marshal(rebootWindowPutRequest{ScheduleYAML: sampleScheduleYAML})
	require.NoError(t, err)
	put := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handlePutStewardRebootWindow(rec, actorRequest(http.MethodPut, "/api/v1/stewards/"+stewardID+"/reboot-window",
			payload, map[string]string{"id": stewardID}, tenantID, p))
		return rec
	}
	configStore := server.rebootWindowConfigStore()
	require.NotNil(t, configStore, "test server must expose a config store")
	key := &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "stewards", Name: stewardID}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, put(tc.principal))
			_, getErr := configStore.GetConfig(ctx, key)
			assert.True(t, errors.Is(getErr, cfgconfig.ErrConfigNotFound), "no config doc may be stored, got %v", getErr)
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := put(operator)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := configStore.GetConfig(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, operator.ID, stored.CreatedBy)
	assert.Equal(t, operator.ID, stored.UpdatedBy)
}

// ---- handleCreateRoleConfig ----------------------------------------------------------

func TestHandleCreateRoleConfig_NoActor_Returns401(t *testing.T) {
	server := setupRoleConfigServer(t)
	ctx := context.Background()
	const tenantID = "role-actor-tenant"
	payload := validRolePayload("actor-role", "os:windows")
	create := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleCreateRoleConfig(rec, actorRequest(http.MethodPost, "/api/v1/roles", payload, nil, tenantID, p))
		return rec
	}
	key := &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "role-policies", Name: "actor-role"}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, create(tc.principal))
			_, getErr := server.roleConfigStore.GetConfig(ctx, key)
			assert.True(t, errors.Is(getErr, cfgconfig.ErrConfigNotFound), "no role config may be stored, got %v", getErr)
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := create(operator)
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := server.roleConfigStore.GetConfig(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, operator.ID, stored.CreatedBy)
	assert.Equal(t, operator.ID, stored.UpdatedBy)
}

// ---- tenant crossing handlers --------------------------------------------------------

// crossingActorRequest is a crossing-handler request whose route variables are tenantID
// ({id}) and, when crossingID is not empty, crossingID ({crossing_id}).
func crossingActorRequest(method, tenantID, crossingID string, body []byte, scopeTenant string, p *Principal) *http.Request {
	vars := map[string]string{"id": tenantID}
	if crossingID != "" {
		vars["crossing_id"] = crossingID
	}
	return actorRequest(method, "/api/v1/tenants/"+tenantID+"/crossing", body, vars, scopeTenant, p)
}

func TestHandleCreateTenantCrossingGrant_NoActor_Returns401(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]interface{}{"duration_minutes": 60})
	require.NoError(t, err)
	grant := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleCreateTenantCrossingGrant(rec, crossingActorRequest(http.MethodPost, "msp-a", "", payload, "msp-a", p))
		return rec
	}

	for _, tc := range noActorCases("msp-a") {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, grant(tc.principal))
			list, err := server.tenantCrossingStore.ListTenantCrossings(ctx, "msp-a")
			require.NoError(t, err)
			assert.Empty(t, list, "no crossing grant may be stored")
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	mspAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	rec := grant(mspAdmin)
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	list, err := server.tenantCrossingStore.ListTenantCrossings(ctx, "msp-a")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, mspAdmin.ID, list[0].GrantedBy)
}

func TestHandleTenantBreakGlass_NoActor_Returns401(t *testing.T) {
	server := breakGlassServer(t)
	ctx := context.Background()
	payload := breakGlassBody(t, "account_recovery", "Client lost all admin passkeys, INC-4821")
	invoke := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleTenantBreakGlass(rec, crossingActorRequest(http.MethodPost, "msp-a", "", payload, "", p))
		return rec
	}

	for _, tc := range noActorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, invoke(tc.principal))
			list, err := server.tenantCrossingStore.ListTenantCrossings(ctx, "msp-a")
			require.NoError(t, err)
			assert.Empty(t, list, "no break-glass crossing may be stored")
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	caller := rootScopedPrincipal("root-operator-1")
	rec := invoke(caller)
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	list, err := server.tenantCrossingStore.ListTenantCrossings(ctx, "msp-a")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, caller.ID, list[0].GrantedBy)
	assert.Equal(t, caller.ID, list[0].PrincipalID)
}

func TestHandleApproveTenantBreakGlass_NoActor_Returns401(t *testing.T) {
	server := secondApproverServer(t, true)
	ctx := context.Background()
	pending := invokePending(t, server)
	approve := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleApproveTenantBreakGlass(rec, crossingActorRequest(http.MethodPost, "msp-a", pending.ID, nil, "", p))
		return rec
	}

	for _, tc := range noActorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, approve(tc.principal))
			stored, err := server.tenantCrossingStore.GetTenantCrossing(ctx, pending.ID)
			require.NoError(t, err)
			assert.Equal(t, business.TenantCrossingApprovalPending, stored.ApprovalState)
			assert.Empty(t, stored.ApprovedBy)
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	approver := rootScopedPrincipal("root-operator-2")
	rec := approve(approver)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := server.tenantCrossingStore.GetTenantCrossing(ctx, pending.ID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantCrossingApprovalApproved, stored.ApprovalState)
	assert.Equal(t, approver.ID, stored.ApprovedBy)
}

func TestHandleEndTenantCrossing_NoActor_Returns401(t *testing.T) {
	server := setupEndCrossingServer(t)
	ctx := context.Background()
	seedCrossing(t, server, "grant-1", "msp-a", "", "msp-a-admin", business.TenantCrossingKindGrant)
	end := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleEndTenantCrossing(rec, crossingActorRequest(http.MethodDelete, "msp-a", "grant-1", nil, "msp-a", p))
		return rec
	}

	for _, tc := range noActorCases("msp-a") {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, end(tc.principal))
			stored, err := server.tenantCrossingStore.GetTenantCrossing(ctx, "grant-1")
			require.NoError(t, err)
			assert.Nil(t, stored.RevokedAt, "the crossing must stay in force")
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	mspAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	rec := end(mspAdmin)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := server.tenantCrossingStore.GetTenantCrossing(ctx, "grant-1")
	require.NoError(t, err)
	assert.NotNil(t, stored.RevokedAt)
}
