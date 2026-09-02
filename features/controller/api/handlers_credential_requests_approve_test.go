// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ---- test helpers -----------------------------------------------------------------

// lodgeTestCredentialRequest mints an enrolment token and lodges a request against it
// through the real router, returning the lodge response (fingerprint, request ID).
func lodgeTestCredentialRequest(t *testing.T, server *Server, tenantID string) LodgeCredentialRequestResponse {
	t.Helper()
	minted := mintTestEnrolmentToken(t, server, tenantID)
	rec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "approve-test-device"),
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	return decodeLodgeResponse(t, rec)
}

// approveCredentialRequest calls handleApproveCredentialRequest directly with the
// given principal and route variable injected, exactly as authenticationMiddleware +
// mux would for a real request. Bypassing requirePermission here is deliberate — the
// presence/assurance gate is covered generically by TestBootstrapCredential_* and the
// F2 parity test; these tests exercise the handler's own authority and record logic.
func approveCredentialRequest(t *testing.T, server *Server, principal *Principal, id string, body ApproveCredentialRequestBody) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/"+id+"/approve", bytes.NewReader(payload))
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"id": id})
	rec := httptest.NewRecorder()
	server.handleApproveCredentialRequest(rec, req)
	return rec
}

func decodeApproveResponse(t *testing.T, rec *httptest.ResponseRecorder) ApproveCredentialRequestResponse {
	t.Helper()
	var resp struct {
		Data ApproveCredentialRequestResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func createApprovalTestAccount(t *testing.T, server *Server, username, tenantID string) AccountCreateResponse {
	t.Helper()
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username, TenantID: tenantID})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var resp struct {
		Data AccountCreateResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// implicitAdminPrincipal returns a principal shaped like an ordinary admin-marked mTLS
// cert with no root-scope marker of its own — ImplicitAdmin: true, RootScoped: false,
// CertSerial set (as extractAdminPrincipal would produce for a bound or bootstrap
// admin cert).
func implicitAdminPrincipal(id string) *Principal {
	return &Principal{
		ID:            id,
		Name:          "mtls-admin:" + id,
		Assurance:     session.AssuranceStrong,
		ImplicitAdmin: true,
		CertSerial:    "test-serial-" + id,
	}
}

// ---- happy path ---------------------------------------------------------------------

func TestApproveCredentialRequest_SelectsExistingAccount(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "approve-tenant")
	acct := createApprovalTestAccount(t, server, "device-owner", "approve-tenant")

	approver := implicitAdminPrincipal("approver-1")
	approver.TenantID = "approve-tenant"

	rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
		Fingerprint: lodged.PublicKeyFingerprint,
		AccountID:   acct.ID,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	resp := decodeApproveResponse(t, rec)
	assert.Equal(t, credentialRequestStatusApproved, resp.Status)
	assert.Equal(t, acct.ID, resp.AccountID)
	assert.Empty(t, resp.GrantedMarkers, "no marker was requested — the default is empty")
	assert.False(t, resp.SelfApproved)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, credentialRequestStatusApproved, stored.Status)
	assert.Equal(t, acct.ID, stored.BoundAccountID)
	assert.Equal(t, "approver-1", stored.ApprovedBy)
	require.NotNil(t, stored.ApprovedAt)
	assert.Empty(t, stored.GrantedMarkers)
	assert.False(t, stored.SelfApproved)
}

func TestApproveCredentialRequest_AcceptsShortFingerprintForm(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "approve-tenant-short")
	acct := createApprovalTestAccount(t, server, "device-owner-2", "approve-tenant-short")

	approver := implicitAdminPrincipal("approver-2")
	rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
		Fingerprint: lodged.PublicKeyFingerprintShort,
		AccountID:   acct.ID,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestApproveCredentialRequest_CreatesNewAccount(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "approve-tenant-new")

	approver := implicitAdminPrincipal("approver-3")
	rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
		Fingerprint:        lodged.PublicKeyFingerprint,
		NewAccountUsername: "headless-host-01",
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeApproveResponse(t, rec)
	require.NotEmpty(t, resp.AccountID)

	created, err := server.getAccount(context.Background(), "headless-host-01")
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Equal(t, resp.AccountID, created.ID)
	assert.Equal(t, "approve-tenant-new", created.TenantID)
	assert.Empty(t, created.Permissions)
	assert.False(t, created.RootScope)
}

func TestApproveCredentialRequest_NewAccountAlreadyExists_Conflict(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "approve-tenant-exists")
	createApprovalTestAccount(t, server, "already-there", "approve-tenant-exists")

	approver := implicitAdminPrincipal("approver-4")
	rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
		Fingerprint:        lodged.PublicKeyFingerprint,
		NewAccountUsername: "already-there",
	})
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ACCOUNT_EXISTS", errCode(t, rec.Body.Bytes()))
}

func TestApproveCredentialRequest_BothOrNeitherAccountSelector_BadRequest(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "approve-tenant-badsel")
	approver := implicitAdminPrincipal("approver-5")

	t.Run("neither", func(t *testing.T) {
		rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
			Fingerprint: lodged.PublicKeyFingerprint,
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "INVALID_ACCOUNT_SELECTION", errCode(t, rec.Body.Bytes()))
	})

	t.Run("both", func(t *testing.T) {
		rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
			Fingerprint:        lodged.PublicKeyFingerprint,
			AccountID:          "some-id",
			NewAccountUsername: "some-user",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "INVALID_ACCOUNT_SELECTION", errCode(t, rec.Body.Bytes()))
	})
}

// ---- fingerprint confirmation ---------------------------------------------------------

func TestApproveCredentialRequest_FingerprintMismatch_Conflict(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "approve-tenant-fp")
	acct := createApprovalTestAccount(t, server, "fp-owner", "approve-tenant-fp")
	approver := implicitAdminPrincipal("approver-6")

	rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
		Fingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
		AccountID:   acct.ID,
	})
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "FINGERPRINT_MISMATCH", errCode(t, rec.Body.Bytes()))

	stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.Equal(t, credentialRequestStatusPending, stored.Status, "a rejected approval must not move the request out of pending")
}

// ---- terminal-state and scope checks --------------------------------------------------

func TestApproveCredentialRequest_NotPending_Conflict(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "approve-tenant-denied")

	denyRec := makeAdminRequest(t, "POST", "/api/v1/credential-requests/"+lodged.RequestID+"/deny", nil)
	denyResultRec := httptest.NewRecorder()
	server.router.ServeHTTP(denyResultRec, denyRec)
	require.Equal(t, http.StatusOK, denyResultRec.Code)

	acct := createApprovalTestAccount(t, server, "denied-owner", "approve-tenant-denied")
	approver := implicitAdminPrincipal("approver-7")
	rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
		Fingerprint: lodged.PublicKeyFingerprint,
		AccountID:   acct.ID,
	})
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "REQUEST_NOT_PENDING", errCode(t, rec.Body.Bytes()))
}

func TestApproveCredentialRequest_UnknownID_NotFound(t *testing.T) {
	server := setupTestServer(t)
	approver := implicitAdminPrincipal("approver-8")
	rec := approveCredentialRequest(t, server, approver, "cr-does-not-exist", ApproveCredentialRequestBody{
		Fingerprint: "irrelevant",
		AccountID:   "irrelevant",
	})
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

func TestApproveCredentialRequest_OutOfTenantScope_NotFound(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "scoped-tenant")

	approver := implicitAdminPrincipal("approver-9")
	approver.TenantID = "other-tenant" // ImplicitAdmin is unrelated to tenant scoping here
	rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
		Fingerprint: lodged.PublicKeyFingerprint,
		AccountID:   "whatever",
	})
	assert.Equal(t, http.StatusNotFound, rec.Code, "a request outside the caller's tenant subtree must not be disclosed")
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

// ---- self-approval --------------------------------------------------------------------

func TestApproveCredentialRequest_SelfApproval(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "self-approve-tenant")
	acct := createApprovalTestAccount(t, server, "self-approver", "self-approve-tenant")

	// The approver's own principal ID equals the account it is binding the request to —
	// exactly the shape of enrolling a second device for oneself.
	approver := implicitAdminPrincipal(acct.ID)

	rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
		Fingerprint:      lodged.PublicKeyFingerprint,
		AccountID:        acct.ID,
		GrantAdminMarker: true,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeApproveResponse(t, rec)
	assert.True(t, resp.SelfApproved)
	assert.Equal(t, []string{credentialMarkerAdmin}, resp.GrantedMarkers)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.True(t, stored.SelfApproved)

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "self-approve-tenant"})
	require.NoError(t, err)
	var approvedEntry *business.AuditEntry
	for _, e := range entries {
		if e.Action == "credential_request.approved" && e.ResourceID == lodged.RequestID {
			approvedEntry = e
			break
		}
	}
	require.NotNil(t, approvedEntry, "credential_request.approved audit event must be recorded")
	assert.Equal(t, true, approvedEntry.Details["self_approved"])
	assert.Equal(t, acct.ID, approvedEntry.Details["bound_account_id"])
}

// ---- [REQUIRED TEST] marker authority: every combination of the three markers ---------

// TestApproveCredentialRequest_MarkerCombinations_WeakPrincipalRefusedForAny is the
// [REQUIRED TEST]: an approver entitled to grant none of the three markers is refused
// for every non-empty combination of them, and the request stays pending (no partial
// grant leaks through).
func TestApproveCredentialRequest_MarkerCombinations_WeakPrincipalRefusedForAny(t *testing.T) {
	server := setupTestServer(t)

	weak := &Principal{
		ID:            "weak-approver",
		Assurance:     session.AssuranceStrong,
		ImplicitAdmin: false,
		Permissions:   []string{},
		RootScoped:    false,
	}

	combos := []struct {
		name                 string
		admin, payload, root bool
		slug                 string
	}{
		{"admin only", true, false, false, "admin-only"},
		{"payload only", false, true, false, "payload-only"},
		{"root only", false, false, true, "root-only"},
		{"admin+payload", true, true, false, "admin-payload"},
		{"admin+root", true, false, true, "admin-root"},
		{"payload+root", false, true, true, "payload-root"},
		{"all three", true, true, true, "all-three"},
	}

	for _, c := range combos {
		c := c
		t.Run(c.name, func(t *testing.T) {
			tenantID := "weak-tenant-" + c.slug
			lodged := lodgeTestCredentialRequest(t, server, tenantID)
			acct := createApprovalTestAccount(t, server, "acct-"+c.slug, tenantID)

			rec := approveCredentialRequest(t, server, weak, lodged.RequestID, ApproveCredentialRequestBody{
				Fingerprint:               lodged.PublicKeyFingerprint,
				AccountID:                 acct.ID,
				GrantAdminMarker:          c.admin,
				GrantPayloadSigningMarker: c.payload,
				GrantRootScopeMarker:      c.root,
			})
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Equal(t, "MARKER_NOT_GRANTABLE", errCode(t, rec.Body.Bytes()))

			stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
			require.NoError(t, err)
			assert.Equal(t, credentialRequestStatusPending, stored.Status,
				"a refused marker grant must leave the request pending, not partially approved")
		})
	}
}

// [REQUIRED TEST] an approver lacking the signing-credential permission cannot mint a
// certificate carrying the payload-signing marker; an approver who holds it (at
// AssuranceStrong) can.
func TestApproveCredentialRequest_PayloadSigningMarker_RequiresPermission(t *testing.T) {
	server := setupTestServer(t)

	t.Run("without signing-credential:request permission, refused", func(t *testing.T) {
		lodged := lodgeTestCredentialRequest(t, server, "sign-tenant-no-perm")
		acct := createApprovalTestAccount(t, server, "sign-owner-no-perm", "sign-tenant-no-perm")
		approver := &Principal{ID: "signer-no-perm", Assurance: session.AssuranceStrong, Permissions: []string{}}

		rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
			Fingerprint:               lodged.PublicKeyFingerprint,
			AccountID:                 acct.ID,
			GrantPayloadSigningMarker: true,
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, "MARKER_NOT_GRANTABLE", errCode(t, rec.Body.Bytes()))
	})

	t.Run("with signing-credential:request permission at strong assurance, granted", func(t *testing.T) {
		lodged := lodgeTestCredentialRequest(t, server, "sign-tenant-with-perm")
		acct := createApprovalTestAccount(t, server, "sign-owner-with-perm", "sign-tenant-with-perm")
		approver := &Principal{
			ID:          "signer-with-perm",
			Assurance:   session.AssuranceStrong,
			Permissions: []string{"signing-credential:request"},
		}

		rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
			Fingerprint:               lodged.PublicKeyFingerprint,
			AccountID:                 acct.ID,
			GrantPayloadSigningMarker: true,
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		resp := decodeApproveResponse(t, rec)
		assert.Equal(t, []string{credentialMarkerPayloadSigning}, resp.GrantedMarkers)
	})

	t.Run("holds permission but sub-strong assurance, refused (defense in depth)", func(t *testing.T) {
		lodged := lodgeTestCredentialRequest(t, server, "sign-tenant-basic")
		acct := createApprovalTestAccount(t, server, "sign-owner-basic", "sign-tenant-basic")
		approver := &Principal{
			ID:          "signer-basic",
			Assurance:   session.AssuranceBasic,
			Permissions: []string{"signing-credential:request"},
		}

		rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
			Fingerprint:               lodged.PublicKeyFingerprint,
			AccountID:                 acct.ID,
			GrantPayloadSigningMarker: true,
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

// [REQUIRED TEST] an approver who is not root-scoped cannot mint a certificate carrying
// the root-scope marker — including an ordinary ImplicitAdmin principal, for which a
// bare permission-string check would incorrectly succeed.
func TestApproveCredentialRequest_RootScopeMarker_RequiresCertifiedRootScope(t *testing.T) {
	server := setupTestServer(t)

	t.Run("ordinary admin-marked principal (ImplicitAdmin, not root-scoped) refused", func(t *testing.T) {
		lodged := lodgeTestCredentialRequest(t, server, "root-tenant-ordinary")
		acct := createApprovalTestAccount(t, server, "root-owner-ordinary", "root-tenant-ordinary")
		approver := implicitAdminPrincipal("ordinary-admin")
		require.True(t, approver.ImplicitAdmin)
		require.False(t, approver.RootScoped)

		rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
			Fingerprint:          lodged.PublicKeyFingerprint,
			AccountID:            acct.ID,
			GrantRootScopeMarker: true,
		})
		assert.Equal(t, http.StatusForbidden, rec.Code,
			"an ImplicitAdmin principal must not satisfy the root-scope gate by permission breadth alone")
		assert.Equal(t, "MARKER_NOT_GRANTABLE", errCode(t, rec.Body.Bytes()))
	})

	t.Run("RootScoped true but no certified serial (e.g. a session field) refused", func(t *testing.T) {
		lodged := lodgeTestCredentialRequest(t, server, "root-tenant-uncertified")
		acct := createApprovalTestAccount(t, server, "root-owner-uncertified", "root-tenant-uncertified")
		approver := &Principal{ID: "uncertified-root", Assurance: session.AssuranceStrong, RootScoped: true, CertSerial: ""}

		rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
			Fingerprint:          lodged.PublicKeyFingerprint,
			AccountID:            acct.ID,
			GrantRootScopeMarker: true,
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("certified root-scope principal granted", func(t *testing.T) {
		lodged := lodgeTestCredentialRequest(t, server, "root-tenant-certified")
		acct := createApprovalTestAccount(t, server, "root-owner-certified", "root-tenant-certified")
		approver := &Principal{
			ID: "certified-root", Assurance: session.AssuranceStrong,
			RootScoped: true, CertSerial: "real-cert-serial-1", ImplicitAdmin: true,
		}

		rec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
			Fingerprint:          lodged.PublicKeyFingerprint,
			AccountID:            acct.ID,
			GrantRootScopeMarker: true,
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		resp := decodeApproveResponse(t, rec)
		assert.Equal(t, []string{credentialMarkerRootScope}, resp.GrantedMarkers)
	})
}

// [REQUIRED TEST] granting the root-scope marker is refused for a caller authenticated
// by a session — including a genuinely root-scoped cfg-CLI Bearer session
// (session.Manager.IssueRootScoped) — proving the gate is certificate-specific, not a
// property a session can ever satisfy.
func TestPrincipalHasCertifiedRootScope_RootScopedSessionRefused(t *testing.T) {
	srv := setupTestServer(t)

	bearerCfg := session.DefaultConfig()
	store := session.NewMemStore(bearerCfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(bearerCfg, store, time.Now)
	srv.SetSessionManager(mgr)

	_, token, err := mgr.IssueRootScoped(context.Background(), "root-cli-op", "cfg-cli")
	require.NoError(t, err)

	var captured *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/x/approve", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, captured)
	require.True(t, captured.RootScoped, "sanity: the session must be genuinely root-scoped")
	assert.Empty(t, captured.CertSerial)
	assert.False(t, principalHasCertifiedRootScope(captured),
		"a root-scoped cfg-CLI Bearer session must never satisfy the certified-root-scope gate — only a certificate can")
}

// [REQUIRED TEST] a revoked root-scope-marked client certificate presented at the TLS
// layer alongside a valid ordinary session is refused the root-scope marker. This is an
// ordinary configuration (the server accepts a client cert the handshake did not
// require, tls.VerifyClientCertIfGiven), not a corner case.
func TestPrincipalHasCertifiedRootScope_RevokedCertFallsBackToOrdinarySession(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	certManager := newSharedTestCertManager(t)
	srv.certManager = certManager

	issuedCert, err := certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "root-operator",
		Organization: "CFGMS",
		ValidityDays: 1,
		TemplateModifier: func(template *x509.Certificate) {
			cert.SetAdminMarker(template)
			cert.SetRootScopeMarker(template)
		},
	})
	require.NoError(t, err)
	require.NoError(t, certManager.Revoke(issuedCert.SerialNumber))

	certBlock, _ := pem.Decode(issuedCert.CertificatePEM)
	require.NotNil(t, certBlock)
	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)

	cookie := issueWebSession(t, mgr, "alice", "")

	var captured *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/x/approve", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"a revoked certificate must fall through to the cookie session, not be rejected outright")
	require.NotNil(t, captured)
	assert.False(t, principalHasCertifiedRootScope(captured),
		"a revoked root-scope-marked certificate presented alongside a valid ordinary session must not grant the root-scope predicate")
}

// TestPrincipalHasCertifiedRootScope_ValidCertGrants is the positive-path sibling: a
// genuinely valid (non-revoked), certificate-authenticated root-scope-marked principal
// must satisfy the predicate — the gate must refuse the negative cases above without
// over-blocking the legitimate one.
func TestPrincipalHasCertifiedRootScope_ValidCertGrants(t *testing.T) {
	srv := setupTestServer(t)
	peerCert := makeAdminCertWithAttrs(t, 4242, "root-op", true)
	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)
	p := srv.extractAdminPrincipal(req)
	require.NotNil(t, p)
	assert.True(t, principalHasCertifiedRootScope(p))
}

// ---- [REQUIRED TEST] structural: no non-certificate code path sets CertSerial --------

// TestCertSerial_OnlySetByExtractAdminPrincipal is the [REQUIRED TEST]: it walks every
// non-test .go file in features/controller/api and asserts that "CertSerial:" appears
// as a struct field only inside extractAdminPrincipal. A later change setting it on a
// session or cookie principal — e.g. for audit correlation — would otherwise silently
// widen principalHasCertifiedRootScope's gate with no failing test to catch it.
func TestCertSerial_OnlySetByExtractAdminPrincipal(t *testing.T) {
	repoRoot := findControllerRepoRoot(t)
	apiDir := filepath.Join(repoRoot, "features", "controller", "api")

	entries, err := os.ReadDir(apiDir)
	require.NoError(t, err)

	fset := token.NewFileSet()
	var violations []string

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(apiDir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err, "parse %s", path)

		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				kv, ok := inner.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				ident, ok := kv.Key.(*ast.Ident)
				if !ok || ident.Name != "CertSerial" {
					return true
				}
				if fn.Name.Name != "extractAdminPrincipal" {
					violations = append(violations, fmt.Sprintf("%s:%d sets CertSerial in func %s",
						name, fset.Position(kv.Pos()).Line, fn.Name.Name))
				}
				return true
			})
			return false // FuncDecl bodies do not nest, no need to recurse further at this level
		})
	}

	assert.Empty(t, violations,
		"CertSerial must be set only inside extractAdminPrincipal: %v", violations)
}

// TestPrincipalHasCertifiedRootScope_SingleCallSite is the structural lock for the AC
// "the gate is a single named predicate with one call site": counts occurrences of the
// predicate's name across non-test source in this package. Exactly two are expected —
// the func declaration and its one call site inside resolveGrantedMarkers.
func TestPrincipalHasCertifiedRootScope_SingleCallSite(t *testing.T) {
	repoRoot := findControllerRepoRoot(t)
	apiDir := filepath.Join(repoRoot, "features", "controller", "api")
	entries, err := os.ReadDir(apiDir)
	require.NoError(t, err)

	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(apiDir, name))
		require.NoError(t, err)
		count += strings.Count(string(data), "principalHasCertifiedRootScope(")
	}
	assert.Equal(t, 2, count,
		"principalHasCertifiedRootScope must have exactly one call site outside its own declaration")
}

// ---- leadership gate ------------------------------------------------------------------

// TestApproveCredentialRequest_LeadershipGate is the [REQUIRED TEST]: the approve
// handler calls the lease-backed leadership check directly in its own body.
func TestApproveCredentialRequest_LeadershipGate(t *testing.T) {
	server := setupTestServer(t)
	server.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/some-id/approve", nil)
	req = withVars(req, map[string]string{"id": "some-id"})
	rec := httptest.NewRecorder()
	server.handleApproveCredentialRequest(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
