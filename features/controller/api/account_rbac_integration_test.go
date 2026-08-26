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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/session"
)

// setupRBACIntegrationServer extends setupCertBindingServer with a session manager.
// withDefaultEmbeddedSPA is called first so the SPA state is correct when New() runs
// inside setupCertBindingServer.
func setupRBACIntegrationServer(t *testing.T) (*Server, session.Manager) {
	t.Helper()
	withDefaultEmbeddedSPA(t)
	srv, _ := setupCertBindingServer(t)
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)
	srv.SetSessionManager(mgr)
	return srv, mgr
}

// createRoleCarryingPermissions creates a role that actually carries permission IDs.
//
// createRoleForTenant (handlers_rbac_test.go) builds a role with an empty PermissionIds
// slice; a role with no permissions cannot demonstrate anything about permission flow,
// so these tests must not use it.
func createRoleCarryingPermissions(t *testing.T, server *Server, tenantID, roleID, roleName string, permissionIDs []string) {
	t.Helper()
	// M-AUTH-2: CreateRole requires justification in context.
	ctx := rbac.WithSensitiveOperationJustification(context.Background(),
		"test: role setup for account/RBAC reconciliation test")
	_, err := server.rbacService.CreateRole(ctx, &controller.CreateRoleRequest{
		Role: &common.Role{
			Id:            roleID,
			Name:          roleName,
			Description:   "permission-carrying test role for " + tenantID,
			TenantId:      tenantID,
			PermissionIds: permissionIDs,
		},
	})
	require.NoError(t, err)
}

// requireSubjectHoldsPermission reads the subject's role assignments back through
// GET /api/v1/rbac/subjects/{id}/roles and requires that permissionID is present in
// the assigned roles. This proves the RBAC store genuinely holds the grant, so a later
// authorization denial cannot be explained away as a failed or empty assignment.
func requireSubjectHoldsPermission(t *testing.T, srv *Server, tenantID, subjectID, permissionID string) {
	t.Helper()
	rec := callHandleGetSubjectRoles(srv, tenantID, subjectID)
	require.Equal(t, http.StatusOK, rec.Code, "subject role read-back must succeed")

	var resp struct {
		Data []RoleInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	for _, role := range resp.Data {
		for _, perm := range role.Permissions {
			if perm == permissionID {
				return
			}
		}
	}
	t.Fatalf("subject %q does not hold permission %q through any assigned role: %+v",
		subjectID, permissionID, resp.Data)
}

// TestAccountRBAC_CertBoundSessionAuthorizesFromAccountRecord is a [REQUIRED TEST] for
// Issue #3583. It establishes two facts about a certificate-bound account on the CLI/API
// surface, both asserted against behaviour the test actually exercises:
//
//  1. Identity pin (Issue #3580): extractAdminPrincipal resolves Principal.ID from the
//     bound account and never from the certificate CommonName, and the CLI Bearer session
//     minted under that principal carries the same account ID as its PrincipalID.
//  2. Authorization source: requirePermission -> hasPermission reads Principal.Permissions,
//     which authenticationMiddleware populates exclusively from the account record. A
//     subject-role assignment targeting that same account ID is recorded by the RBAC store
//     but is NOT consulted on the request path, so its permissions are not granted.
//
// Fact 2 is asserted, not merely narrated: the assigned role carries config:list, the
// read-back confirms the RBAC store holds that grant for the account's subject ID, and the
// request gated on config:list is still denied. If subject-role resolution is ever wired
// into the auth path, this assertion fails loudly — which is the intent.
//
// The operational consequence is recorded in docs/architecture/controller-operating-model.md:
// revoking a role assignment does not revoke API access; account.Permissions is the field
// that governs it.
func TestAccountRBAC_CertBoundSessionAuthorizesFromAccountRecord(t *testing.T) {
	srv, mgr := setupRBACIntegrationServer(t)

	const (
		accountID  = "test-acct-rbac-e2e-01"
		certSerial = int64(70001)
		certCN     = "alice-cert-cn"
		tenantID   = "default"
	)

	// Inject account with audit:list and NOT config:list. CertBindings records the cert
	// serial so getAccountByCertSerial locates this account during cert-auth.
	srv.cacheAccount(&account{
		ID:           accountID,
		Username:     "alice-rbac-e2e",
		TenantID:     tenantID,
		Permissions:  []string{"audit:list"},
		CertBindings: []CertBinding{{Serial: "70001"}},
	})

	peerCert := makeAdminCertWithAttrs(t, certSerial, certCN, false)

	// Set up RBAC: subject for account.ID, role carrying config:list, assignment to
	// account.ID — the same ID every auth surface uses for this account.
	createSubjectForTenant(t, srv, tenantID, accountID, "Alice RBAC E2E")
	createRoleCarryingPermissions(t, srv, tenantID, "rbac-e2e-role-01", "RBAC E2E Role",
		[]string{"config:list"})
	roleRec := callHandleAssignSubjectRole(srv, tenantID, accountID, "rbac-e2e-role-01")
	require.Equal(t, http.StatusCreated, roleRec.Code, "role assignment to account.ID must succeed")
	requireSubjectHoldsPermission(t, srv, tenantID, accountID, "config:list")

	// Step 1 — identity pin: extractAdminPrincipal must resolve to account.ID, not cert CN.
	certReq := requestWithTLSCert(http.MethodGet, "/api/v1/audit/entries", peerCert)
	certPrincipal := srv.extractAdminPrincipal(certReq)
	require.NotNil(t, certPrincipal, "cert auth must succeed for bound, enabled account")
	assert.Equal(t, accountID, certPrincipal.ID,
		"Principal.ID must be the bound account's ID")
	assert.NotEqual(t, certCN, certPrincipal.ID,
		"Principal.ID must never be the certificate CommonName")
	assert.Equal(t, []string{"audit:list"}, certPrincipal.Permissions,
		"cert principal permissions come from the account record verbatim — config:list from the assigned role is absent")

	// Step 2 — issue CLI session under the cert-auth principal; the session's PrincipalID
	// is the account ID, so both surfaces address the same identity.
	sessionBody := bytes.NewBufferString(`{"connection_name":"rbac-integration-test"}`)
	sessionReq := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", sessionBody)
	sessionReq.Header.Set("Content-Type", "application/json")
	sessionReq = withPrincipal(sessionReq, certPrincipal)
	sessionRec := httptest.NewRecorder()
	srv.handleSessionCreate(sessionRec, sessionReq)
	require.Equal(t, http.StatusCreated, sessionRec.Code, "session create must succeed for cert-auth principal")

	var sessResp sessionCreateResponse
	require.NoError(t, json.NewDecoder(sessionRec.Body).Decode(&sessResp))
	require.NotEmpty(t, sessResp.Token, "session token must be returned")

	sess, err := mgr.Validate(context.Background(), sessResp.Token)
	require.NoError(t, err, "minted session must validate")
	assert.Equal(t, accountID, sess.PrincipalID,
		"CLI session PrincipalID must be the account ID, so account lookup on the Bearer path resolves the same record")

	// Step 3 — audit:list is granted because it is in account.Permissions.
	auditReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/entries", nil)
	auditReq.Header.Set("Authorization", "Bearer "+sessResp.Token)
	auditRec := httptest.NewRecorder()
	srv.router.ServeHTTP(auditRec, auditReq)
	assert.Equal(t, http.StatusOK, auditRec.Code,
		"audit:list must be granted: it is present in account.Permissions, the field the Bearer path reads")

	// Step 4 — config:list is DENIED even though the role assigned to account.ID carries
	// it. This pins the actual authorization source: account.Permissions, never the
	// subject's role assignments.
	configReq := httptest.NewRequest(http.MethodGet, "/api/v1/configs", nil)
	configReq.Header.Set("Authorization", "Bearer "+sessResp.Token)
	configRec := httptest.NewRecorder()
	srv.router.ServeHTTP(configRec, configReq)
	assert.Equal(t, http.StatusForbidden, configRec.Code,
		"config:list must be denied: requirePermission reads Principal.Permissions, which is built from account.Permissions only — the subject-role assignment carrying config:list is not consulted")
}

// TestAccountRBAC_PrincipalIDNeverResolvesToCertCN is a [REQUIRED TEST] for Issue #3583:
// a certificate-authenticated principal is identified by the bound account's ID, never by
// the certificate's Subject.CommonName, so a subject-role assignment targeting the CN
// addresses an identity the auth chain never produces.
//
// The denial in Step 3 holds for two independent reasons, and the test states both rather
// than crediting the narrower one: (a) Principal.ID is the account ID, so the CN subject is
// never the acting identity; and (b) subject-role assignments are not consulted on the
// request path at all — asserted directly by
// TestAccountRBAC_CertBoundSessionAuthorizesFromAccountRecord. Reason (a) is what this test
// isolates, via the explicit ID assertions in Step 1.
func TestAccountRBAC_PrincipalIDNeverResolvesToCertCN(t *testing.T) {
	srv, mgr := setupRBACIntegrationServer(t)

	const (
		accountID  = "test-acct-rbac-pin-02"
		certSerial = int64(70002)
		certCN     = "cert-cn-not-account-id"
		tenantID   = "default"
	)

	// Account holds no permissions. A role carrying audit:list is assigned to cert.CN.
	srv.cacheAccount(&account{
		ID:           accountID,
		Username:     "bob-rbac-pin",
		TenantID:     tenantID,
		Permissions:  []string{},
		CertBindings: []CertBinding{{Serial: "70002"}},
	})

	peerCert := makeAdminCertWithAttrs(t, certSerial, certCN, false)

	// Set up RBAC: subject for cert.CN (the wrong target) with a role carrying audit:list.
	// handleAssignSubjectRole validates no foreign key to the account type, so the store
	// accepts the CN string as a subject ID.
	createSubjectForTenant(t, srv, tenantID, certCN, "Bob Cert CN Subject")
	createRoleCarryingPermissions(t, srv, tenantID, "rbac-pin-role-02", "RBAC Pin Role",
		[]string{"audit:list"})
	roleRec := callHandleAssignSubjectRole(srv, tenantID, certCN, "rbac-pin-role-02")
	require.Equal(t, http.StatusCreated, roleRec.Code, "role assignment to cert.CN must succeed at the RBAC layer")
	requireSubjectHoldsPermission(t, srv, tenantID, certCN, "audit:list")

	// Step 1 — identity pin: extractAdminPrincipal resolves to account.ID, not cert.CN.
	certReq := requestWithTLSCert(http.MethodGet, "/api/v1/audit/entries", peerCert)
	certPrincipal := srv.extractAdminPrincipal(certReq)
	require.NotNil(t, certPrincipal, "cert auth must succeed for bound account")
	assert.Equal(t, accountID, certPrincipal.ID,
		"Principal.ID must be account.ID — the acting identity is the account, not the certificate")
	assert.NotEqual(t, certCN, certPrincipal.ID,
		"Principal.ID must not be cert.CN — the subject the role was assigned to is not the acting identity")
	assert.Empty(t, certPrincipal.Permissions,
		"cert principal permissions come from the account record, which grants none here")

	// Step 2 — issue CLI session under the cert-auth principal.
	sessionBody := bytes.NewBufferString(`{"connection_name":"rbac-pin-test"}`)
	sessionReq := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", sessionBody)
	sessionReq.Header.Set("Content-Type", "application/json")
	sessionReq = withPrincipal(sessionReq, certPrincipal)
	sessionRec := httptest.NewRecorder()
	srv.handleSessionCreate(sessionRec, sessionReq)
	require.Equal(t, http.StatusCreated, sessionRec.Code, "session create must succeed")

	var sessResp sessionCreateResponse
	require.NoError(t, json.NewDecoder(sessionRec.Body).Decode(&sessResp))
	require.NotEmpty(t, sessResp.Token)

	sess, err := mgr.Validate(context.Background(), sessResp.Token)
	require.NoError(t, err, "minted session must validate")
	assert.Equal(t, accountID, sess.PrincipalID,
		"CLI session PrincipalID is the account ID; cert.CN appears nowhere in the session identity")
	assert.NotEqual(t, certCN, sess.PrincipalID,
		"cert.CN must never become the session PrincipalID")

	// Step 3 — audit:list is denied: the account grants none, and the CN subject that does
	// hold audit:list is not the acting identity.
	auditReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/entries", nil)
	auditReq.Header.Set("Authorization", "Bearer "+sessResp.Token)
	auditRec := httptest.NewRecorder()
	srv.router.ServeHTTP(auditRec, auditReq)
	assert.Equal(t, http.StatusForbidden, auditRec.Code,
		"audit:list must be denied: the account record grants nothing and the cert.CN subject is not the acting identity")
}
