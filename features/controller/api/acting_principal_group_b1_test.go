// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// Group B1 of the #6425 sweep: handlers that record who acted through a helper or a
// differently named field (an audit User(...), an acting-ID parameter, a DeniedBy)
// resolve the actor through requireActingPrincipal and refuse with 401
// AUTHENTICATION_REQUIRED, changing nothing, when the context holds no principal or one
// with an empty ID. Each test drives one handler directly with every noActorCases shape
// against an otherwise complete request, checks nothing changed and nothing was audited,
// then sends the same request as a real principal to show the actor was the only reason
// it was refused.

// auditEntriesHeld returns how many audit entries the server holds, 0 when it has no
// audit manager.
func auditEntriesHeld(t *testing.T, server *Server) int {
	t.Helper()
	if server.auditManager == nil {
		return 0
	}
	return auditEntryCount(t, server)
}

// assertRefusedWithoutActor sends the request built by do for each noActorCases shape and
// checks the 401 AUTHENTICATION_REQUIRED, that no audit entry was written, and (through
// unchanged) that the handler's state is as it was.
func assertRefusedWithoutActor(t *testing.T, server *Server, tenantID string,
	do func(p *Principal) *httptest.ResponseRecorder, unchanged func(t *testing.T)) {
	t.Helper()
	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntriesHeld(t, server)
			assertAuthenticationRequired(t, do(tc.principal))
			unchanged(t)
			assert.Equal(t, auditBefore, auditEntriesHeld(t, server), "no audit entry may be written")
		})
	}
}

// b1Operator is a real acting principal: strong assurance, implicit admin, an ID.
func b1Operator() *Principal {
	return &Principal{ID: "operator-b1", Channel: AuthChannelMTLS, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
}

// ---- alerts ---------------------------------------------------------------------------

func newB1AlertServer(t *testing.T) *Server {
	t.Helper()
	server := setupTestServer(t)
	server.SetAlertStore(newTestFlatFileAlertStore(t))
	return server
}

func TestHandleAcknowledgeAlert_NoActor_Returns401(t *testing.T) {
	server := newB1AlertServer(t)
	const alertID = "ack-alert"
	ack := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleAcknowledgeAlert(rec, actorRequest(http.MethodPost, "/api/v1/alerts/"+alertID+"/acknowledge",
			[]byte(`{"reason":"seen"}`), map[string]string{"id": alertID}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", ack, func(t *testing.T) {
		st, err := server.alertStore.GetAlertState(context.Background(), "", alertID)
		require.NoError(t, err)
		assert.True(t, st == nil || !st.Acknowledged, "the alert must not be acknowledged")
	})

	rec := ack(b1Operator())
	require.Equal(t, http.StatusNoContent, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	st, err := server.alertStore.GetAlertState(context.Background(), "", alertID)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.Acknowledged)
	assert.Equal(t, "operator-b1", st.AcknowledgedBy)
}

func TestHandleSilenceAlert_NoActor_Returns401(t *testing.T) {
	server := newB1AlertServer(t)
	const alertID = "silence-alert"
	payload, err := json.Marshal(AlertSilenceRequest{Until: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	silence := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleSilenceAlert(rec, actorRequest(http.MethodPost, "/api/v1/alerts/"+alertID+"/silence",
			payload, map[string]string{"id": alertID}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", silence, func(t *testing.T) {
		st, err := server.alertStore.GetAlertState(context.Background(), "", alertID)
		require.NoError(t, err)
		assert.True(t, st == nil || !st.Silenced, "the alert must not be silenced")
	})

	rec := silence(b1Operator())
	require.Equal(t, http.StatusNoContent, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	st, err := server.alertStore.GetAlertState(context.Background(), "", alertID)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.Silenced)
	assert.Equal(t, "operator-b1", st.SilencedBy)
}

func TestHandleUnsilenceAlert_NoActor_Returns401(t *testing.T) {
	server := newB1AlertServer(t)
	const alertID = "unsilence-alert"
	require.NoError(t, server.alertStore.SilenceAlert(context.Background(), "", alertID, "earlier-operator", time.Now().Add(time.Hour)))
	unsilence := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleUnsilenceAlert(rec, actorRequest(http.MethodPost, "/api/v1/alerts/"+alertID+"/unsilence",
			nil, map[string]string{"id": alertID}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", unsilence, func(t *testing.T) {
		st, err := server.alertStore.GetAlertState(context.Background(), "", alertID)
		require.NoError(t, err)
		require.NotNil(t, st)
		assert.True(t, st.Silenced, "the silence must still be in place")
	})

	rec := unsilence(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	st, err := server.alertStore.GetAlertState(context.Background(), "", alertID)
	require.NoError(t, err)
	assert.False(t, st.Silenced)
}

// ---- accounts -------------------------------------------------------------------------

func TestHandleCreateAccount_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	const username = "b1-created"
	payload, err := json.Marshal(AccountRequest{Username: username, TenantID: "tenant-a"})
	require.NoError(t, err)
	create := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleCreateAccount(rec, actorRequest(http.MethodPost, "/api/v1/accounts", payload, nil, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", create, func(t *testing.T) {
		acct, err := server.getAccount(context.Background(), username)
		require.NoError(t, err)
		assert.Nil(t, acct, "no account may be stored")
	})

	rec := create(b1Operator())
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
}

func TestHandleUpdateAccount_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	const username = "b1-updated"
	require.Equal(t, http.StatusCreated, postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username, TenantID: "tenant-a"}).Code)
	disable := true
	payload, err := json.Marshal(AccountUpdateRequest{Disabled: &disable})
	require.NoError(t, err)
	update := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleUpdateAccount(rec, actorRequest(http.MethodPut, "/api/v1/accounts/"+username, payload,
			map[string]string{"username": username}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", update, func(t *testing.T) {
		dropAccountCache(server)
		acct, err := server.getAccount(context.Background(), username)
		require.NoError(t, err)
		require.NotNil(t, acct)
		assert.False(t, acct.Disabled, "the account must not be disabled")
	})

	rec := update(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	assert.True(t, acct.Disabled)
}

func TestHandleDeleteAccount_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	const username = "b1-deleted"
	require.Equal(t, http.StatusCreated, postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username, TenantID: "tenant-a"}).Code)
	del := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleDeleteAccount(rec, actorRequest(http.MethodDelete, "/api/v1/accounts/"+username, nil,
			map[string]string{"username": username}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", del, func(t *testing.T) {
		dropAccountCache(server)
		acct, err := server.getAccount(context.Background(), username)
		require.NoError(t, err)
		require.NotNil(t, acct, "the account must not be deleted")
		assert.False(t, acct.Disabled, "the account must not be disabled")
	})

	rec := del(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	assert.Nil(t, acct)
}

func TestHandleRevokeEnrollmentLink_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	const username = "b1-link"
	require.Equal(t, http.StatusCreated, postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username, TenantID: "tenant-a"}).Code)
	revoke := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleRevokeEnrollmentLink(rec, actorRequest(http.MethodPost,
			"/api/v1/accounts/"+username+"/enrollment-link/revoke", nil, map[string]string{"username": username}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", revoke, func(t *testing.T) {
		dropAccountCache(server)
		acct, err := server.getAccount(context.Background(), username)
		require.NoError(t, err)
		require.NotNil(t, acct)
		assert.True(t, enrollmentLinkOutstanding(acct), "the enrollment link must still be outstanding")
	})

	rec := revoke(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	assert.False(t, enrollmentLinkOutstanding(acct))
}

// ---- certificate bindings -------------------------------------------------------------

// boundCertSerials returns the serials bound to username's account.
func boundCertSerials(t *testing.T, server *Server, username string) []string {
	t.Helper()
	var serials []string
	for _, b := range getCertBindings(t, server, username) {
		serials = append(serials, b.Serial)
	}
	return serials
}

func TestHandleBindCert_NoActor_Returns401(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	serial := provisionTestClientCert(t, certMgr, "alice-b1-bind")
	payload, err := json.Marshal(BindCertRequest{Serial: serial, Fingerprint: "sha256:b1", Label: "laptop"})
	require.NoError(t, err)
	bind := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleBindCert(rec, actorRequest(http.MethodPost, "/api/v1/accounts/alice/certs/bind", payload,
			map[string]string{"username": "alice"}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", bind, func(t *testing.T) {
		assert.Empty(t, boundCertSerials(t, server, "alice"), "no certificate may be bound")
	})

	rec := bind(b1Operator())
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	assert.Equal(t, []string{serial}, boundCertSerials(t, server, "alice"))
}

func TestHandleRevokeCertBinding_NoActor_Returns401(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	serial := provisionTestClientCert(t, certMgr, "alice-b1-revoke")
	require.Equal(t, http.StatusCreated, bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: serial}).Code)
	revoke := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleRevokeCertBinding(rec, actorRequest(http.MethodPost, "/api/v1/accounts/alice/certs/revoke/"+serial, nil,
			map[string]string{"username": "alice", "serial": serial}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", revoke, func(t *testing.T) {
		assert.Equal(t, []string{serial}, boundCertSerials(t, server, "alice"), "the binding must remain")
		revoked, err := certMgr.IsRevoked(serial)
		require.NoError(t, err)
		assert.False(t, revoked, "the certificate must not be revoked")
	})

	rec := revoke(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	revoked, err := certMgr.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestHandleRotateCert_NoActor_Returns401(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	oldSerial := provisionTestClientCert(t, certMgr, "alice-b1-old")
	newSerial := provisionTestClientCert(t, certMgr, "alice-b1-new")
	require.Equal(t, http.StatusCreated, bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: oldSerial}).Code)
	payload, err := json.Marshal(RotateCertRequest{Serial: newSerial})
	require.NoError(t, err)
	rotate := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleRotateCert(rec, actorRequest(http.MethodPost, "/api/v1/accounts/alice/certs/rotate/"+oldSerial, payload,
			map[string]string{"username": "alice", "old_serial": oldSerial}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", rotate, func(t *testing.T) {
		assert.Equal(t, []string{oldSerial}, boundCertSerials(t, server, "alice"), "the bindings must be unchanged")
		revoked, err := certMgr.IsRevoked(oldSerial)
		require.NoError(t, err)
		assert.False(t, revoked, "the old certificate must not be revoked")
	})

	rec := rotate(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	assert.Equal(t, []string{newSerial}, boundCertSerials(t, server, "alice"))
	revoked, err := certMgr.IsRevoked(oldSerial)
	require.NoError(t, err)
	assert.True(t, revoked)
}

// ---- content approval (humanApprover) and library mode ---------------------------------

// humanApprover is the actor resolution shared by the approve and revoke handlers for
// scripts and workflows; the script approve handler reaches it before reading the body.
func TestHumanApprover_NoActor_Returns401(t *testing.T) {
	f := newScriptApprovalFixture(t)
	approve := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		f.server.handleApproveScript(rec, actorRequest(http.MethodPost, approvalsPath, []byte(f.body(f.approvalHash())), nil, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, f.server, "", approve, func(t *testing.T) {
		assert.Nil(t, f.approvalRecord(t, f.approvalHash()), "no approval may be stored")
	})

	// The same call with a human-channel principal gets past the actor check (the
	// handler then wants a presence tap, which this direct call does not carry).
	rec := approve(b1Operator())
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.NotEqual(t, http.StatusForbidden, rec.Code, rec.Body.String())
}

func TestHandlePutLibraryMode_NoActor_Returns401(t *testing.T) {
	f := newLibraryModeFixture(t)
	put := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		f.srv.handlePutLibraryMode(rec, actorRequest(http.MethodPut, "/api/v1/automation/libraries/script/mode",
			[]byte(`{"mode":"approve"}`), map[string]string{"kind": "script"}, libraryModeTestTenant, p))
		return rec
	}

	assertRefusedWithoutActor(t, f.srv, libraryModeTestTenant, put, func(t *testing.T) {
		assert.Equal(t, ApprovalModeSigned, f.mode(t, LibraryKindScript), "the mode must not change")
	})

	rec := put(libraryModeAdmin())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	assert.Equal(t, ApprovalModeApprove, f.mode(t, LibraryKindScript))
}

// ---- automation run begin -------------------------------------------------------------

func TestHandleAutomationRunBegin_NoActor_Returns401(t *testing.T) {
	f := newRunFixture(t)
	begin := func(tenantID string, p *Principal) *httptest.ResponseRecorder {
		raw, err := json.Marshal(AutomationRunBeginRequest{TenantID: tenantID, EventRef: "evt-b1", EventSource: "psa-a"})
		require.NoError(t, err)
		rec := httptest.NewRecorder()
		f.srv.handleAutomationRunBegin(rec, actorRequest(http.MethodPost, runsBeginPath, raw, nil, runMSP, p))
		return rec
	}

	for _, tc := range noActorCases(runMSP) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, f.srv)
			assertAuthenticationRequired(t, begin(runClient1, tc.principal))
			assert.Equal(t, auditBefore, auditEntryCount(t, f.srv), "no audit entry may be written")
		})
	}

	grantPrincipal := &Principal{Channel: AuthChannelAutomationGrant, ID: f.grant.ID, TenantID: f.grant.TenantID, Assurance: session.AssuranceStrong}
	// A refused call must not have bound the event: the same event for another tenant
	// would be refused with a conflict if it had.
	rec := begin(runClient2, grantPrincipal)
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from a grant principal succeeds: %s", rec.Body.String())
}

// ---- credential containment -----------------------------------------------------------

func TestHandleRevokeCredentialsByEnrolmentToken_NoActor_Returns401(t *testing.T) {
	server := setupCollectTestServer(t)
	tok := mintTestEnrolmentToken(t, server, "b1-revoke-token-tenant")
	lodgeRec := lodgeCredentialRequest(t, server, tok.Token, LodgeCredentialRequestBody{CSRPEM: generateTestCSR(t, "b1-revoke-token-device")})
	require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())
	lodged := decodeLodgeResponse(t, lodgeRec)
	revoke := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleRevokeCredentialsByEnrolmentToken(rec, actorRequest(http.MethodPost,
			"/api/v1/enrolment-tokens/"+tok.ID+"/revoke-issued-credentials", nil, map[string]string{"id": tok.ID}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", revoke, func(t *testing.T) {
		stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Equal(t, credentialRequestStatusPending, stored.Status)
		assert.Empty(t, stored.DeniedBy)
	})

	rec := revoke(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.Equal(t, credentialRequestStatusDenied, stored.Status)
	assert.Equal(t, "operator-b1", stored.DeniedBy)
}

func TestHandleCancelCredentialRequest_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	fx := lodgeAndApprove(t, server, "b1-cancel-tenant", "b1-cancel-owner", ApproveCredentialRequestBody{})
	cancel := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleCancelCredentialRequest(rec, actorRequest(http.MethodPost,
			"/api/v1/credential-requests/"+fx.requestID+"/cancel", nil, map[string]string{"id": fx.requestID}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", cancel, func(t *testing.T) {
		stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Equal(t, credentialRequestStatusApproved, stored.Status)
		assert.Empty(t, stored.DeniedBy)
	})

	rec := cancel(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	assert.Equal(t, credentialRequestStatusDenied, stored.Status)
	assert.Equal(t, "operator-b1", stored.DeniedBy)
}

func TestHandleRevokeOrphanedCredential_NoActor_Returns401(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := collectThenOrphan(t, server, "b1-orphan-tenant", "b1-orphan-owner", ApproveCredentialRequestBody{})
	revoke := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleRevokeOrphanedCredential(rec, actorRequest(http.MethodPost,
			"/api/v1/credential-requests/orphaned/"+fx.serial+"/revoke", nil, map[string]string{"serial": fx.serial}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", revoke, func(t *testing.T) {
		revoked, err := server.certManager.IsRevoked(fx.serial)
		require.NoError(t, err)
		assert.False(t, revoked, "the certificate must not be revoked")
	})

	rec := revoke(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	revoked, err := server.certManager.IsRevoked(fx.serial)
	require.NoError(t, err)
	assert.True(t, revoked)
}

// ---- credential renewal ---------------------------------------------------------------

// renewalPayload is a renewal request body over a fresh keypair.
func renewalPayload(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	payload, err := json.Marshal(RenewCredentialRequest{CSRPEM: encodeTestCSR(t, key, "renew-test-device")})
	require.NoError(t, err)
	return payload
}

// withPeerCertificate presents cert as the mutual-TLS client certificate.
func withPeerCertificate(req *http.Request, cert *x509.Certificate) *http.Request {
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return req
}

// The renewal handler already refuses a request without the certificate being renewed;
// a missing principal or an empty ID is refused first, as AUTHENTICATION_REQUIRED, before
// any lookup, because the renewed binding records the principal ID as its actor.
func TestHandleRenewCredential_NoActor_Returns401(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "b1-renew-tenant", "b1-renew-owner", ApproveCredentialRequestBody{}, nil)
	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))
	payload := renewalPayload(t)
	renew := func(p *Principal) *httptest.ResponseRecorder {
		req := actorRequest(http.MethodPost, "/api/v1/credential-renewal", payload, nil, fx.tenantID, p)
		req = withPeerCertificate(req, presented)
		rec := httptest.NewRecorder()
		server.handleRenewCredential(rec, req)
		return rec
	}

	assertRefusedWithoutActor(t, server, fx.tenantID, renew, func(t *testing.T) {
		revoked, err := server.certManager.IsRevoked(fx.oldSerial)
		require.NoError(t, err)
		assert.False(t, revoked, "the old certificate must not be revoked")
		acct, err := server.getAccount(context.Background(), fx.accountUser)
		require.NoError(t, err)
		require.Len(t, acct.CertBindings, 1)
		assert.Equal(t, fx.oldSerial, acct.CertBindings[0].Serial)
	})

	renewer := &Principal{ID: fx.accountID, TenantID: fx.tenantID, Assurance: session.AssuranceStrong, CertSerial: fx.oldSerial}
	rec := renew(renewer)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from the certificate's principal succeeds: %s", rec.Body.String())
	revoked, err := server.certManager.IsRevoked(fx.oldSerial)
	require.NoError(t, err)
	assert.True(t, revoked)
}

// ---- enrolment tokens and credential requests ------------------------------------------

func TestHandleRevokeEnrolmentToken_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	tok := mintTestEnrolmentToken(t, server, "b1-token-tenant")
	revoke := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleRevokeEnrolmentToken(rec, actorRequest(http.MethodPost,
			"/api/v1/enrolment-tokens/"+tok.ID+"/revoke", nil, map[string]string{"id": tok.ID}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", revoke, func(t *testing.T) {
		stored, err := server.getEnrolmentTokenByID(context.Background(), tok.ID)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.False(t, stored.Revoked, "the token must not be revoked")
	})

	rec := revoke(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := server.getEnrolmentTokenByID(context.Background(), tok.ID)
	require.NoError(t, err)
	assert.True(t, stored.Revoked)
}

func TestHandleDenyCredentialRequest_NoActor_Returns401(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "b1-deny-tenant")
	deny := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleDenyCredentialRequest(rec, actorRequest(http.MethodPost,
			"/api/v1/credential-requests/"+lodged.RequestID+"/deny", []byte(`{"reason":"unknown device"}`),
			map[string]string{"id": lodged.RequestID}, "", p))
		return rec
	}

	assertRefusedWithoutActor(t, server, "", deny, func(t *testing.T) {
		stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Equal(t, credentialRequestStatusPending, stored.Status)
		assert.Empty(t, stored.DeniedBy)
		assert.Nil(t, stored.DeniedAt)
	})

	rec := deny(b1Operator())
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.Equal(t, credentialRequestStatusDenied, stored.Status)
	assert.Equal(t, "operator-b1", stored.DeniedBy)
}

// ---- no actor recorded: unchanged ------------------------------------------------------

// The cluster drain and decommission handlers resolve the principal to authorize the
// caller's scope and name it in an operational log line only; they store no actor and
// write no audit entry. They keep their existing 403 for a request with no principal.
func TestClusterLifecycle_NoPrincipalKeepsForbidden(t *testing.T) {
	server := setupTestServer(t)
	for name, handler := range map[string]http.HandlerFunc{
		"drain":        server.handleClusterNodeDrain,
		"decommission": server.handleClusterNodeDecommission,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, actorRequest(http.MethodPost, "/api/v1/cluster/nodes/node-1/"+name, nil,
				map[string]string{"id": "node-1"}, "", nil))
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}
}
