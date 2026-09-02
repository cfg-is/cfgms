// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ---- test helpers -----------------------------------------------------------------

// cancelCredentialRequest calls handleCancelCredentialRequest directly with the given
// principal and route variable injected, mirroring approveCredentialRequest.
func cancelCredentialRequest(t *testing.T, server *Server, principal *Principal, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/"+id+"/cancel", nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"id": id})
	rec := httptest.NewRecorder()
	server.handleCancelCredentialRequest(rec, req)
	return rec
}

// denyCredentialRequestDirect calls handleDenyCredentialRequest directly, used here
// only to drive a request into the "denied" state for cancel's refusal tests.
func denyCredentialRequestDirect(t *testing.T, server *Server, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/"+id+"/deny", nil)
	req = withVars(req, map[string]string{"id": id})
	rec := httptest.NewRecorder()
	server.handleDenyCredentialRequest(rec, req)
	return rec
}

// revokeByEnrolmentToken calls handleRevokeCredentialsByEnrolmentToken directly.
func revokeByEnrolmentToken(t *testing.T, server *Server, principal *Principal, tokenID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enrolment-tokens/"+tokenID+"/revoke-issued-credentials", nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"id": tokenID})
	rec := httptest.NewRecorder()
	server.handleRevokeCredentialsByEnrolmentToken(rec, req)
	return rec
}

func decodeRevokeByTokenResponse(t *testing.T, rec *httptest.ResponseRecorder) RevokeByEnrolmentTokenResponse {
	t.Helper()
	var resp struct {
		Data RevokeByEnrolmentTokenResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// listOrphanedCredentials calls handleListOrphanedCredentials directly, with the
// given principal (or nil for an unscoped mTLS-admin-shaped caller) injected.
func listOrphanedCredentials(t *testing.T, server *Server, principal *Principal) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/credential-requests/orphaned", nil)
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	rec := httptest.NewRecorder()
	server.handleListOrphanedCredentials(rec, req)
	return rec
}

func decodeOrphanedList(t *testing.T, rec *httptest.ResponseRecorder) []OrphanedCredentialInfo {
	t.Helper()
	var resp struct {
		Data []OrphanedCredentialInfo `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// revokeOrphanedCredential calls handleRevokeOrphanedCredential directly.
func revokeOrphanedCredential(t *testing.T, server *Server, principal *Principal, serial string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/orphaned/"+serial+"/revoke", nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"serial": serial})
	rec := httptest.NewRecorder()
	server.handleRevokeOrphanedCredential(rec, req)
	return rec
}

// signTestCertificateOutsideEnrolmentFlow signs a certificate directly through
// certManager, with no pendingCredentialRequest record at all — standing in for a
// bootstrap bundle certificate or a steward mTLS transport certificate, neither of
// which is issued through the enrolment-request flow this story's containment
// actions read from (Issue #3725 [REQUIRED TEST]: containment never touches these).
func signTestCertificateOutsideEnrolmentFlow(t *testing.T, server *Server, commonName string) *cert.Certificate {
	t.Helper()
	issued, err := server.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   commonName,
		Organization: "CFGMS",
		ClientID:     commonName,
		ValidityDays: 365,
	})
	require.NoError(t, err)
	return issued
}

// accountPersistFailingSecretStore wraps a real SecretStore and fails only
// account-tagged persists — StoreSecret and CompareAndSwapSecret alike — every
// other operation (including the credential-request listing revoke-by-token itself
// depends on) is served by the real store. Used to inject a failure between
// certManager.Revoke and removeCertBindingFromAccount's persistAccountCAS call,
// mirroring accountListFailingSecretStore's narrow-by-tag shape
// (handlers_credential_requests_test.go). CompareAndSwapSecret must be covered
// alongside StoreSecret: removeCertBindingFromAccount persists through
// persistAccountCAS (Issue #3761, ADR-031 Decision 1), so a fixture that only
// intercepted StoreSecret would let the real store's CompareAndSwapSecret succeed
// and silently defeat the injected failure.
type accountPersistFailingSecretStore struct {
	secretsif.SecretStore
	failErr error
}

func (s *accountPersistFailingSecretStore) StoreSecret(ctx context.Context, req *secretsif.SecretRequest) error {
	for _, tag := range req.Tags {
		if tag == "account" {
			return s.failErr
		}
	}
	return s.SecretStore.StoreSecret(ctx, req)
}

func (s *accountPersistFailingSecretStore) CompareAndSwapSecret(ctx context.Context, key string, expectedVersion int, req *secretsif.SecretRequest) (int, bool, error) {
	for _, tag := range req.Tags {
		if tag == "account" {
			return 0, false, s.failErr
		}
	}
	return s.SecretStore.CompareAndSwapSecret(ctx, key, expectedVersion, req)
}

// ---- cancel -------------------------------------------------------------------------

func TestCancelCredentialRequest_Success(t *testing.T) {
	server := setupTestServer(t)
	fx := lodgeAndApprove(t, server, "cancel-tenant", "cancel-owner", ApproveCredentialRequestBody{})

	rec := cancelCredentialRequest(t, server, testAdminPrincipal(), fx.requestID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, credentialRequestStatusDenied, stored.Status)
	require.NotNil(t, stored.DeniedAt)
	assert.Equal(t, "test-mtls-admin", stored.DeniedBy)
}

func TestCancelCredentialRequest_RefusesPending(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "cancel-pending-tenant")

	rec := cancelCredentialRequest(t, server, testAdminPrincipal(), lodged.RequestID)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "REQUEST_NOT_APPROVED", decodeErrorCode(t, rec).Error.Code)
}

func TestCancelCredentialRequest_RefusesAlreadyCollected(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "cancel-collected-tenant", "cancel-collected-owner", ApproveCredentialRequestBody{})
	collectRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())

	rec := cancelCredentialRequest(t, server, testAdminPrincipal(), fx.requestID)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "REQUEST_ALREADY_COLLECTED", decodeErrorCode(t, rec).Error.Code)
}

func TestCancelCredentialRequest_RefusesAlreadyDenied(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "cancel-denied-tenant")
	denyRec := denyCredentialRequestDirect(t, server, lodged.RequestID)
	require.Equal(t, http.StatusOK, denyRec.Code, denyRec.Body.String())

	rec := cancelCredentialRequest(t, server, testAdminPrincipal(), lodged.RequestID)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "REQUEST_ALREADY_DENIED", decodeErrorCode(t, rec).Error.Code)
}

func TestCancelCredentialRequest_UnknownID_NotFound(t *testing.T) {
	server := setupTestServer(t)
	rec := cancelCredentialRequest(t, server, testAdminPrincipal(), "cr-does-not-exist")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestCancelCredentialRequest_OutOfTenantScope_NotFound(t *testing.T) {
	server := setupTestServer(t)
	fx := lodgeAndApprove(t, server, "cancel-scope-tenant", "cancel-scope-owner", ApproveCredentialRequestBody{})

	scoped := &Principal{ID: "scoped-admin", TenantID: "other-tenant"}
	rec := cancelCredentialRequest(t, server, scoped, fx.requestID)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestCancelCredentialRequest_ThenCollectNeverMints is the [REQUIRED TEST]: after
// cancelling an approved request, a subsequent collect call presenting the correct
// collect secret is rejected and never mints a certificate.
func TestCancelCredentialRequest_ThenCollectNeverMints(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "cancel-then-collect-tenant", "cancel-then-collect-owner", ApproveCredentialRequestBody{})

	cancelRec := cancelCredentialRequest(t, server, testAdminPrincipal(), fx.requestID)
	require.Equal(t, http.StatusOK, cancelRec.Code, cancelRec.Body.String())

	before, err := server.certManager.ListCertificates()
	require.NoError(t, err)

	collectRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	statusResp := decodeCollectStatusResponse(t, collectRec)
	assert.Equal(t, "denied", statusResp.Status)

	after, err := server.certManager.ListCertificates()
	require.NoError(t, err)
	assert.Equal(t, len(before), len(after), "collect must mint no certificate for a cancelled request")

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Empty(t, stored.CollectedSerial)
	assert.Nil(t, stored.CollectedAt)
}

// ---- any-node service (Issue #3761, ADR-031 Decision 1) --------------------------------

// TestCancelCredentialRequest_SucceedsOnNonAuthoritativeNode is the [REQUIRED TEST] for
// this file. The containment handlers used to return 503 without touching any state
// when the serving node held no lease-backed leadership. Any-node service means every
// cluster node serves containment: driven against a real, deliberately non-authoritative
// *ha.Manager (ClusterMode, no lease ever acquired), the cancel must succeed and the
// request must actually be transitioned to denied. Containment is the operation least
// tolerable to defer — a leaked credential is not less leaked on a follower.
func TestCancelCredentialRequest_SucceedsOnNonAuthoritativeNode(t *testing.T) {
	server := setupTestServer(t)
	server.haManager = newNonAuthoritativeHAManager(t)
	fx := lodgeAndApprove(t, server, "cancel-nonauth-tenant", "cancel-nonauth-owner", ApproveCredentialRequestBody{})

	rec := cancelCredentialRequest(t, server, testAdminPrincipal(), fx.requestID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, credentialRequestStatusDenied, stored.Status,
		"the cancel must actually be recorded on a non-authoritative node")
}

// TestRevokeByEnrolmentToken_SucceedsOnNonAuthoritativeNode covers the token-scoped
// containment sweep on a non-authoritative node: every request lodged against the token
// must still be blocked.
func TestRevokeByEnrolmentToken_SucceedsOnNonAuthoritativeNode(t *testing.T) {
	server := setupCollectTestServer(t)
	server.haManager = newNonAuthoritativeHAManager(t)
	tok := mintTestEnrolmentToken(t, server, "revoke-token-nonauth-tenant")
	lodgeRec := lodgeCredentialRequest(t, server, tok.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "revoke-token-nonauth-device"),
	})
	require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())
	lodged := decodeLodgeResponse(t, lodgeRec)

	rec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), tok.ID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRevokeByTokenResponse(t, rec)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "contained", resp.Results[0].Outcome)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, credentialRequestStatusDenied, stored.Status,
		"the containment must actually be recorded on a non-authoritative node")
}

// TestRevokeOrphanedCredential_SucceedsOnNonAuthoritativeNode covers orphan revocation
// on a non-authoritative node: the certificate must actually land on the CRL.
func TestRevokeOrphanedCredential_SucceedsOnNonAuthoritativeNode(t *testing.T) {
	server := setupCollectTestServer(t)
	server.haManager = newNonAuthoritativeHAManager(t)
	fx := collectThenOrphan(t, server, "revoke-orphan-nonauth-tenant", "revoke-orphan-nonauth-owner", ApproveCredentialRequestBody{})
	require.False(t, server.certManager.IsRevoked(fx.serial))

	rec := revokeOrphanedCredential(t, server, testAdminPrincipal(), fx.serial)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, server.certManager.IsRevoked(fx.serial),
		"the orphaned certificate must actually be revoked on a non-authoritative node")
}

// TestCancelCredentialRequest_SucceedsOnAuthoritativeNode is the mirror case for
// continuity: a real, deliberately authoritative *ha.Manager (SingleServerMode, the
// shape every OSS single-controller install runs) must still reach the same containment
// logic unchanged.
func TestCancelCredentialRequest_SucceedsOnAuthoritativeNode(t *testing.T) {
	server := setupTestServer(t)
	server.haManager = newAuthoritativeHAManager(t)
	fx := lodgeAndApprove(t, server, "cancel-auth-tenant", "cancel-auth-owner", ApproveCredentialRequestBody{})

	rec := cancelCredentialRequest(t, server, testAdminPrincipal(), fx.requestID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, credentialRequestStatusDenied, stored.Status)
}

// ---- revoke-by-token --------------------------------------------------------------

func TestRevokeByEnrolmentToken_UnknownToken_NotFound(t *testing.T) {
	server := setupCollectTestServer(t)
	rec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), "et-does-not-exist")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRevokeByEnrolmentToken_OutOfTenantScope_NotFound(t *testing.T) {
	server := setupCollectTestServer(t)
	tok := mintTestEnrolmentToken(t, server, "revoke-token-scope-tenant")

	scoped := &Principal{ID: "scoped-admin", TenantID: "other-tenant"}
	rec := revokeByEnrolmentToken(t, server, scoped, tok.ID)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestRevokeByEnrolmentToken_NoLodgedRequests covers a minted-but-never-spent token:
// the API reports an empty result set (200, zero results) rather than an error — a
// legitimate state at the API layer. Enforcing "zero-match fails fast" is the CLI's job.
func TestRevokeByEnrolmentToken_NoLodgedRequests(t *testing.T) {
	server := setupCollectTestServer(t)
	tok := mintTestEnrolmentToken(t, server, "revoke-token-empty-tenant")

	rec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), tok.ID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRevokeByTokenResponse(t, rec)
	assert.Empty(t, resp.Results)
}

// TestRevokeByEnrolmentToken_BlocksPendingRequest covers the pending branch: a request
// that was never approved must be transitioned so it can never later produce a
// certificate.
func TestRevokeByEnrolmentToken_BlocksPendingRequest(t *testing.T) {
	server := setupCollectTestServer(t)
	tok := mintTestEnrolmentToken(t, server, "revoke-token-pending-tenant")
	lodgeRec := lodgeCredentialRequest(t, server, tok.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "revoke-token-pending-device"),
	})
	require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())
	lodged := decodeLodgeResponse(t, lodgeRec)

	rec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), tok.ID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRevokeByTokenResponse(t, rec)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, lodged.RequestID, resp.Results[0].RequestID)
	assert.Equal(t, "contained", resp.Results[0].Outcome)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, credentialRequestStatusDenied, stored.Status)
}

// TestRevokeByEnrolmentToken_BlocksApprovedRequest covers the approved-but-uncollected
// branch: approval records a decision but mints nothing, so blocking it (not revoking a
// certificate) is what makes containment complete.
func TestRevokeByEnrolmentToken_BlocksApprovedRequest(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "revoke-token-approved-tenant", "revoke-token-approved-owner", ApproveCredentialRequestBody{})

	// Recover the token this fixture's request was lodged against.
	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	require.NotNil(t, stored)

	rec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), stored.EnrolmentTokenID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRevokeByTokenResponse(t, rec)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "contained", resp.Results[0].Outcome)

	after, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.Equal(t, credentialRequestStatusDenied, after.Status)

	// The block must actually stop collection: the correct secret is still rejected.
	collectRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	assert.Equal(t, "denied", decodeCollectStatusResponse(t, collectRec).Status)
}

// TestRevokeByEnrolmentToken_RevokesCollectedCertificate covers the collected branch:
// revoke the certificate, then remove the account binding.
func TestRevokeByEnrolmentToken_RevokesCollectedCertificate(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "revoke-token-collected-tenant", "revoke-token-collected-owner", ApproveCredentialRequestBody{})
	collectRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	collected := decodeCollectResponse(t, collectRec)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	require.False(t, server.certManager.IsRevoked(collected.SerialNumber), "sanity: certificate starts out live")

	rec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), stored.EnrolmentTokenID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRevokeByTokenResponse(t, rec)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "contained", resp.Results[0].Outcome)

	assert.True(t, server.certManager.IsRevoked(collected.SerialNumber))
	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	require.NotNil(t, acct)
	for _, b := range acct.CertBindings {
		assert.NotEqual(t, collected.SerialNumber, b.Serial, "the binding must be removed once the certificate is revoked")
	}
}

// TestRevokeByEnrolmentToken_AlreadyDeniedReportsAlreadyContained covers the no-op
// path: a request already denied before revoke-by-token runs must not error and must
// not be double-processed.
func TestRevokeByEnrolmentToken_AlreadyDeniedReportsAlreadyContained(t *testing.T) {
	server := setupCollectTestServer(t)
	tok := mintTestEnrolmentToken(t, server, "revoke-token-denied-tenant")
	lodgeRec := lodgeCredentialRequest(t, server, tok.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "revoke-token-denied-device"),
	})
	require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())
	lodged := decodeLodgeResponse(t, lodgeRec)
	denyRec := denyCredentialRequestDirect(t, server, lodged.RequestID)
	require.Equal(t, http.StatusOK, denyRec.Code, denyRec.Body.String())

	rec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), tok.ID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRevokeByTokenResponse(t, rec)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "already_contained", resp.Results[0].Outcome)
}

// TestRevokeByEnrolmentToken_RevokeThenUnbindOrdering is the [REQUIRED TEST]:
// revoke-by-token's per-collected-request ordering is revoke-then-unbind. An injected
// failure between certManager.Revoke and removeCertBindingFromAccount must leave
// certManager.IsRevoked(serial) true with the binding still present — never a live
// unbound certificate.
func TestRevokeByEnrolmentToken_RevokeThenUnbindOrdering(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "revoke-token-ordering-tenant", "revoke-token-ordering-owner", ApproveCredentialRequestBody{})
	collectRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	collected := decodeCollectResponse(t, collectRec)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)

	realStore := server.secretStore
	server.secretStore = &accountPersistFailingSecretStore{
		SecretStore: realStore,
		failErr:     errors.New("account store temporarily unavailable"),
	}

	rec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), stored.EnrolmentTokenID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRevokeByTokenResponse(t, rec)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "error", resp.Results[0].Outcome)

	assert.True(t, server.certManager.IsRevoked(collected.SerialNumber),
		"the certificate must be revoked even though the unbind failed")
	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	require.NotNil(t, acct)
	found := false
	for _, b := range acct.CertBindings {
		if b.Serial == collected.SerialNumber {
			found = true
		}
	}
	assert.True(t, found, "the binding must still be present after a failed unbind — never a live unbound certificate")

	// Retry once the store recovers: idempotent Revoke + the now-succeeding unbind
	// complete containment.
	server.secretStore = realStore
	retryRec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), stored.EnrolmentTokenID)
	require.Equal(t, http.StatusOK, retryRec.Code, retryRec.Body.String())
	retryResp := decodeRevokeByTokenResponse(t, retryRec)
	require.Len(t, retryResp.Results, 1)
	assert.Equal(t, "contained", retryResp.Results[0].Outcome)

	acctAfter, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	require.NotNil(t, acctAfter)
	for _, b := range acctAfter.CertBindings {
		assert.NotEqual(t, collected.SerialNumber, b.Serial)
	}
}

// TestRevokeByEnrolmentToken_NeverTouchesCertsOutsideEnrolmentFlow is the
// [REQUIRED TEST]: containment never touches credentials issued outside the enrolment
// flow — a bootstrap bundle certificate and a steward certificate must remain
// unrevoked by a revoke-by-token run.
func TestRevokeByEnrolmentToken_NeverTouchesCertsOutsideEnrolmentFlow(t *testing.T) {
	server := setupCollectTestServer(t)
	bootstrap := signTestCertificateOutsideEnrolmentFlow(t, server, "bootstrap-bundle-admin")
	steward := signTestCertificateOutsideEnrolmentFlow(t, server, "steward-outside-flow-host")

	fx := lodgeAndApprove(t, server, "revoke-token-isolation-tenant", "revoke-token-isolation-owner", ApproveCredentialRequestBody{})
	collectRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	collected := decodeCollectResponse(t, collectRec)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)

	rec := revokeByEnrolmentToken(t, server, testAdminPrincipal(), stored.EnrolmentTokenID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	assert.True(t, server.certManager.IsRevoked(collected.SerialNumber), "sanity: the token's own collected certificate is revoked")
	assert.False(t, server.certManager.IsRevoked(bootstrap.SerialNumber), "a bootstrap bundle certificate must never be touched by revoke-by-token")
	assert.False(t, server.certManager.IsRevoked(steward.SerialNumber), "a steward certificate must never be touched by revoke-by-token")
}

// ---- orphaned certificates ----------------------------------------------------------

func TestListOrphanedCredentials_FindsOrphan(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := collectThenOrphan(t, server, "list-orphan-tenant", "list-orphan-owner", ApproveCredentialRequestBody{})

	rec := listOrphanedCredentials(t, server, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	list := decodeOrphanedList(t, rec)

	var found *OrphanedCredentialInfo
	for i := range list {
		if list[i].RequestID == fx.requestID {
			found = &list[i]
		}
	}
	require.NotNil(t, found, "the orphaned collected certificate must be listed")
	assert.Equal(t, fx.serial, found.Serial)
	assert.Equal(t, fx.tenantID, found.TenantID)
}

func TestListOrphanedCredentials_ExcludesBoundCertificate(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "list-bound-tenant", "list-bound-owner", ApproveCredentialRequestBody{})
	collectRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	collected := decodeCollectResponse(t, collectRec)

	rec := listOrphanedCredentials(t, server, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	list := decodeOrphanedList(t, rec)
	for _, o := range list {
		assert.NotEqual(t, collected.SerialNumber, o.Serial, "a properly bound certificate must not be listed as orphaned")
	}
}

func TestListOrphanedCredentials_TenantScoped(t *testing.T) {
	server := setupCollectTestServer(t)
	collectThenOrphan(t, server, "list-scope-tenant-a", "list-scope-owner-a", ApproveCredentialRequestBody{})

	scoped := &Principal{ID: "scoped-admin", TenantID: "list-scope-tenant-b"}
	rec := listOrphanedCredentials(t, server, scoped)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	list := decodeOrphanedList(t, rec)
	for _, o := range list {
		assert.NotEqual(t, "list-scope-tenant-a", o.TenantID, "a caller scoped to a different tenant must not see this orphan")
	}
}

func TestRevokeOrphanedCredential_Success(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := collectThenOrphan(t, server, "revoke-orphan-tenant", "revoke-orphan-owner", ApproveCredentialRequestBody{})
	require.False(t, server.certManager.IsRevoked(fx.serial))

	rec := revokeOrphanedCredential(t, server, testAdminPrincipal(), fx.serial)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, server.certManager.IsRevoked(fx.serial))

	// Listing and revoking are separate actions: the now-revoked serial no longer
	// appears in the list (sweepOrphanedCollectedCertificates' own IsRevoked skip
	// applies here identically).
	listRec := listOrphanedCredentials(t, server, nil)
	require.Equal(t, http.StatusOK, listRec.Code, listRec.Body.String())
	for _, o := range decodeOrphanedList(t, listRec) {
		assert.NotEqual(t, fx.serial, o.Serial)
	}
}

func TestRevokeOrphanedCredential_RefusesBoundCertificate(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "revoke-orphan-bound-tenant", "revoke-orphan-bound-owner", ApproveCredentialRequestBody{})
	collectRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	collected := decodeCollectResponse(t, collectRec)

	rec := revokeOrphanedCredential(t, server, testAdminPrincipal(), collected.SerialNumber)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "NOT_ORPHANED", decodeErrorCode(t, rec).Error.Code)
	assert.False(t, server.certManager.IsRevoked(collected.SerialNumber))
}

func TestRevokeOrphanedCredential_UnknownSerial_NotFound(t *testing.T) {
	server := setupCollectTestServer(t)
	rec := revokeOrphanedCredential(t, server, testAdminPrincipal(), "nosuchserial")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRevokeOrphanedCredential_AlreadyRevoked_Conflict(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := collectThenOrphan(t, server, "revoke-orphan-twice-tenant", "revoke-orphan-twice-owner", ApproveCredentialRequestBody{})

	first := revokeOrphanedCredential(t, server, testAdminPrincipal(), fx.serial)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())

	second := revokeOrphanedCredential(t, server, testAdminPrincipal(), fx.serial)
	assert.Equal(t, http.StatusConflict, second.Code)
	assert.Equal(t, "ALREADY_REVOKED", decodeErrorCode(t, second).Error.Code)
}

// ---- audit ----------------------------------------------------------------------------

func TestCancelCredentialRequest_EmitsAudit(t *testing.T) {
	server := setupTestServer(t)
	fx := lodgeAndApprove(t, server, "cancel-audit-tenant", "cancel-audit-owner", ApproveCredentialRequestBody{})

	rec := cancelCredentialRequest(t, server, testAdminPrincipal(), fx.requestID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "cancel-audit-tenant"})
	require.NoError(t, err)
	entry := findAuditEntryByAction(t, entries, "credential_request.cancelled")
	assert.Equal(t, fx.requestID, entry.ResourceID)
}

func TestRevokeOrphanedCredential_EmitsAudit(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := collectThenOrphan(t, server, "revoke-orphan-audit-tenant", "revoke-orphan-audit-owner", ApproveCredentialRequestBody{})

	rec := revokeOrphanedCredential(t, server, testAdminPrincipal(), fx.serial)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "revoke-orphan-audit-tenant"})
	require.NoError(t, err)
	entry := findAuditEntryByAction(t, entries, "credential_request.orphaned_certificate_revoked")
	assert.Equal(t, fx.requestID, entry.ResourceID)
}
