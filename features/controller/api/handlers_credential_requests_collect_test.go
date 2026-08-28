// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ---- test helpers -----------------------------------------------------------------

// setupCollectTestServer returns a server wired with a real certificate manager — the
// collect endpoint is the only credential-request handler that mints, so it is the one
// case in this package where setupTestServer's nil certManager is not sufficient
// (mirrors TestPrincipalHasCertifiedRootScope_RevokedCertFallsBackToOrdinarySession's
// setup, which does the same for the same reason).
func setupCollectTestServer(t *testing.T) *Server {
	t.Helper()
	server := setupTestServer(t)
	server.certManager = newTestCertManager(t)
	return server
}

// collectCredentialRequest calls handleCollectCredentialRequest directly with the
// given collect secret and route variable injected, mirroring approveCredentialRequest.
// Bypassing the router (and its rate limiter) is deliberate — the rate limit itself is
// exercised generically elsewhere (Issue #3714); these tests exercise the handler's own
// authentication and state-machine logic.
func collectCredentialRequest(t *testing.T, server *Server, id, secret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/"+id+"/collect", nil)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	req = withVars(req, map[string]string{"id": id})
	rec := httptest.NewRecorder()
	server.handleCollectCredentialRequest(rec, req)
	return rec
}

func decodeCollectResponse(t *testing.T, rec *httptest.ResponseRecorder) CollectCredentialRequestResponse {
	t.Helper()
	var resp struct {
		Data CollectCredentialRequestResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func errMessage(t *testing.T, body []byte) string {
	t.Helper()
	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	require.NotNil(t, resp.Error)
	return resp.Error.Message
}

func decodeCollectStatusResponse(t *testing.T, rec *httptest.ResponseRecorder) credentialRequestCollectStatusResponse {
	t.Helper()
	var resp struct {
		Data credentialRequestCollectStatusResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// lodgeApproveCollectFixture lodges a request, approves it onto a fresh account (with
// the given marker grants), and returns everything a collect test needs.
type lodgeApproveCollectFixture struct {
	requestID     string
	collectSecret string
	accountID     string
	accountUser   string
}

func lodgeAndApprove(t *testing.T, server *Server, tenantID, username string, grant ApproveCredentialRequestBody) lodgeApproveCollectFixture {
	t.Helper()
	lodged := lodgeTestCredentialRequest(t, server, tenantID)
	acct := createApprovalTestAccount(t, server, username, tenantID)

	grant.Fingerprint = lodged.PublicKeyFingerprint
	grant.AccountID = acct.ID
	approver := implicitAdminPrincipal("approver-" + username)
	rec := approveCredentialRequest(t, server, approver, lodged.RequestID, grant)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	return lodgeApproveCollectFixture{
		requestID:     lodged.RequestID,
		collectSecret: lodged.CollectSecret,
		accountID:     acct.ID,
		accountUser:   acct.Username,
	}
}

// ---- happy path ---------------------------------------------------------------------

func TestCollectCredentialRequest_Success(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-tenant", "collect-owner", ApproveCredentialRequestBody{})

	rec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	resp := decodeCollectResponse(t, rec)
	assert.NotEmpty(t, resp.CertificatePEM)
	assert.NotEmpty(t, resp.CACertificatePEM)
	assert.NotEmpty(t, resp.SerialNumber)
	assert.Equal(t, fx.accountID, resp.AccountID)
	assert.Empty(t, resp.GrantedMarkers)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, credentialRequestStatusCollected, stored.Status)
	require.NotNil(t, stored.CollectedAt)
	assert.Equal(t, resp.SerialNumber, stored.CollectedSerial)

	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	require.NotNil(t, acct)
	found := false
	for _, b := range acct.CertBindings {
		if b.Serial == resp.SerialNumber {
			found = true
		}
	}
	assert.True(t, found, "collected certificate serial must be bound to the account")
}

func TestCollectCredentialRequest_GrantedMarkersAreSignedIntoCertificate(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-marker-tenant", "collect-marker-owner", ApproveCredentialRequestBody{
		GrantAdminMarker: true,
	})

	rec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeCollectResponse(t, rec)
	assert.Equal(t, []string{credentialMarkerAdmin}, resp.GrantedMarkers)

	x509Cert := parseCertPEM(t, resp.CertificatePEM)
	assert.True(t, cert.HasAdminMarker(x509Cert))
	assert.False(t, cert.HasRootScopeMarker(x509Cert))
	assert.False(t, cert.HasPayloadSigningMarker(x509Cert))
}

func parseCertPEM(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return parsed
}

// ---- [REQUIRED TEST] wrong secret / unknown ID are indistinguishable ----------------

func TestCollectCredentialRequest_WrongSecret_NotFoundIndistinguishableFromUnknownID(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-wrong-secret", "collect-wrong-owner", ApproveCredentialRequestBody{})

	wrongSecretRec := collectCredentialRequest(t, server, fx.requestID, "not-the-right-secret")
	unknownIDRec := collectCredentialRequest(t, server, "cr-does-not-exist", fx.collectSecret)
	noSecretRec := collectCredentialRequest(t, server, fx.requestID, "")

	require.Equal(t, http.StatusNotFound, wrongSecretRec.Code)
	require.Equal(t, http.StatusNotFound, unknownIDRec.Code)
	require.Equal(t, http.StatusNotFound, noSecretRec.Code)
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, wrongSecretRec.Body.Bytes()))
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, unknownIDRec.Body.Bytes()))
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, noSecretRec.Body.Bytes()))
	// The response shape must be identical — a caller must not be able to distinguish
	// "this ID exists but your secret is wrong" from "this ID does not exist". Compare
	// status code and error code/message rather than the raw body, which also carries
	// a per-response timestamp.
	assert.Equal(t, wrongSecretRec.Code, unknownIDRec.Code)
	assert.Equal(t, errMessage(t, wrongSecretRec.Body.Bytes()), errMessage(t, unknownIDRec.Body.Bytes()))

	// The request must remain fully collectible by its rightful holder afterward — a
	// failed guess must not have consumed or altered anything.
	rightfulRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	assert.Equal(t, http.StatusOK, rightfulRec.Code, rightfulRec.Body.String())
}

// ---- [REQUIRED TEST] machine A cannot collect machine B's certificate --------------

func TestCollectCredentialRequest_CrossRequestSecretsAreNotInterchangeable(t *testing.T) {
	server := setupCollectTestServer(t)
	fxA := lodgeAndApprove(t, server, "collect-cross-a", "collect-cross-owner-a", ApproveCredentialRequestBody{})
	fxB := lodgeAndApprove(t, server, "collect-cross-b", "collect-cross-owner-b", ApproveCredentialRequestBody{})

	// Machine B's secret must not collect machine A's request, in either direction.
	recBOnA := collectCredentialRequest(t, server, fxA.requestID, fxB.collectSecret)
	assert.Equal(t, http.StatusNotFound, recBOnA.Code)
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, recBOnA.Body.Bytes()))

	recAOnB := collectCredentialRequest(t, server, fxB.requestID, fxA.collectSecret)
	assert.Equal(t, http.StatusNotFound, recAOnB.Code)
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, recAOnB.Body.Bytes()))

	// Both remain collectible by their rightful holder.
	recA := collectCredentialRequest(t, server, fxA.requestID, fxA.collectSecret)
	assert.Equal(t, http.StatusOK, recA.Code, recA.Body.String())
	recB := collectCredentialRequest(t, server, fxB.requestID, fxB.collectSecret)
	assert.Equal(t, http.StatusOK, recB.Code, recB.Body.String())
}

// ---- [REQUIRED TEST] conditional transition before minting; restart yields no second cert --

func TestCollectCredentialRequest_SecondAttemptAfterCollectionIsGone(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-second-attempt", "collect-second-owner", ApproveCredentialRequestBody{})

	first := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	firstResp := decodeCollectResponse(t, first)

	// A second call with the same, still-valid secret — whether a retry by the
	// original machine or a race loser — must never mint a second certificate.
	second := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	assert.Equal(t, http.StatusGone, second.Code)
	assert.NotContains(t, second.Body.String(), "BEGIN CERTIFICATE")
	assert.NotEqual(t, firstResp.SerialNumber, "")
}

// TestCollectCredentialRequest_TransitionCommittedBeforeMinting is the [REQUIRED TEST]
// simulating a restart between the durable approved->collected transition and the
// response: force the record to "collected" directly (as claimCredentialRequestForCollection
// would have durably persisted, whether or not the process that did so ever returned a
// response) and confirm a fresh call — standing in for the restarted process, or the
// original caller retrying after losing the response — finds it already collected and
// never signs a certificate.
func TestCollectCredentialRequest_TransitionCommittedBeforeMinting(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-restart", "collect-restart-owner", ApproveCredentialRequestBody{})

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	now := time.Now().UTC()
	stored.Status = credentialRequestStatusCollected
	stored.CollectedAt = &now
	require.NoError(t, server.persistPendingCredentialRequest(context.Background(), stored))

	rec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	assert.Equal(t, http.StatusGone, rec.Code)
	assert.NotContains(t, rec.Body.String(), "BEGIN CERTIFICATE")

	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	assert.Empty(t, acct.CertBindings, "no certificate must ever have been bound for a request the transition already closed")
}

// TestCollectCredentialRequest_ConcurrentRaceYieldsExactlyOneCertificate is the
// [REQUIRED TEST] for the race-loser guarantee: many concurrent collect calls against
// one approved request, all holding the correct secret, must yield exactly one 200
// with a certificate and every other call 410 Gone.
func TestCollectCredentialRequest_ConcurrentRaceYieldsExactlyOneCertificate(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-race", "collect-race-owner", ApproveCredentialRequestBody{})

	const contenders = 12
	start := make(chan struct{})
	recorders := make([]*httptest.ResponseRecorder, contenders)
	var wg sync.WaitGroup
	wg.Add(contenders)
	for i := 0; i < contenders; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			recorders[i] = collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
		}(i)
	}
	close(start)
	wg.Wait()

	successes, gones := 0, 0
	for _, rec := range recorders {
		switch rec.Code {
		case http.StatusOK:
			successes++
			assert.Contains(t, rec.Body.String(), "BEGIN CERTIFICATE")
		case http.StatusGone:
			gones++
			assert.NotContains(t, rec.Body.String(), "BEGIN CERTIFICATE")
		default:
			t.Errorf("unexpected collect status %d: %s", rec.Code, rec.Body.String())
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent collect call may receive a certificate")
	assert.Equal(t, contenders-1, gones, "every other concurrent call must receive 410 Gone")
}

// ---- [REQUIRED TEST] constant-time compare; secret never logged or returned --------

func TestCollectCredentialRequest_SecretNeverLoggedOrReturned(t *testing.T) {
	capLogger := &captureAllLogger{}
	server := setupTestServerWithLogger(t, capLogger)
	server.certManager = newTestCertManager(t)

	fx := lodgeAndApprove(t, server, "collect-log-tenant", "collect-log-owner", ApproveCredentialRequestBody{})

	wrongRec := collectCredentialRequest(t, server, fx.requestID, "guess-"+fx.collectSecret)
	assert.Equal(t, http.StatusNotFound, wrongRec.Code)
	assert.NotContains(t, wrongRec.Body.String(), fx.collectSecret)

	okRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, okRec.Code, okRec.Body.String())
	assert.NotContains(t, okRec.Body.String(), fx.collectSecret)

	logs := capLogger.captured()
	assert.NotContains(t, logs, fx.collectSecret, "the raw collect secret must never be logged")

	reqMeta, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Tags: []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"id":                            fx.requestID,
		},
		IncludeExpired: true,
	})
	require.NoError(t, err)
	require.Len(t, reqMeta, 1)
	for k, v := range reqMeta[0].Metadata {
		assert.NotEqual(t, fx.collectSecret, v, "metadata key %q must not hold the raw collect secret", k)
		assert.NotContains(t, v, fx.collectSecret, "metadata key %q must not contain the raw collect secret", k)
	}
}

// TestCollectSecretMatches_UsesHashComparison is a structural check that
// collectSecretMatches never compares raw secrets directly — only their hashes — and
// that it is symmetric with hashCredentialSecret used at lodge time.
func TestCollectSecretMatches_UsesHashComparison(t *testing.T) {
	raw := "a-raw-collect-secret-value"
	storedHash := hashCredentialSecret(raw)

	assert.True(t, collectSecretMatches(raw, storedHash))
	assert.False(t, collectSecretMatches("wrong-value", storedHash))
	assert.False(t, collectSecretMatches(raw, ""))
	assert.False(t, collectSecretMatches("", storedHash))
	// A raw secret is never itself a valid "stored hash" for a different raw value —
	// proves the comparison hashes the presented value rather than comparing raw
	// strings against whatever was stored.
	assert.False(t, collectSecretMatches(raw, raw))
}

// ---- distinguishable pending / denied / expired ------------------------------------

func TestCollectCredentialRequest_PendingIsDistinguishable(t *testing.T) {
	server := setupCollectTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "collect-pending-tenant")

	rec := collectCredentialRequest(t, server, lodged.RequestID, lodged.CollectSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "pending", decodeCollectStatusResponse(t, rec).Status)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.Equal(t, credentialRequestStatusPending, stored.Status, "polling a pending request must not alter it")
}

func TestCollectCredentialRequest_DeniedIsDistinguishable(t *testing.T) {
	server := setupCollectTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "collect-denied-tenant")

	denyReq := makeAdminRequest(t, "POST", "/api/v1/credential-requests/"+lodged.RequestID+"/deny", nil)
	denyRec := httptest.NewRecorder()
	server.router.ServeHTTP(denyRec, denyReq)
	require.Equal(t, http.StatusOK, denyRec.Code)

	rec := collectCredentialRequest(t, server, lodged.RequestID, lodged.CollectSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "denied", decodeCollectStatusResponse(t, rec).Status)
}

func TestCollectCredentialRequest_ExpiredIsDistinguishable(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-expired-tenant", "collect-expired-owner", ApproveCredentialRequestBody{})

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	stored.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	require.NoError(t, server.persistPendingCredentialRequest(context.Background(), stored))

	rec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "expired", decodeCollectStatusResponse(t, rec).Status)
}

// ---- leadership gate ----------------------------------------------------------------

// TestCollectCredentialRequest_LeadershipGate is the [REQUIRED TEST]: the minting
// branch calls the lease-backed leadership check, and a non-authoritative node leaves
// the request "approved" rather than consuming it.
func TestCollectCredentialRequest_LeadershipGate(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-leadership", "collect-leadership-owner", ApproveCredentialRequestBody{})
	// Lodged while still leader — mint and lodge are themselves leadership-gated, so a
	// fixture needed for the follower branch below must be created first.
	pending := lodgeTestCredentialRequest(t, server, "collect-leadership-poll")

	server.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}
	rec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	assert.Equal(t, credentialRequestStatusApproved, stored.Status, "a 503 from a non-leader must leave the request untouched")

	// Polling responses must remain available regardless of leadership.
	pollRec := collectCredentialRequest(t, server, pending.RequestID, pending.CollectSecret)
	assert.Equal(t, http.StatusOK, pollRec.Code, pollRec.Body.String())
	assert.Equal(t, "pending", decodeCollectStatusResponse(t, pollRec).Status)

	server.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: true}
	retryRec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	assert.Equal(t, http.StatusOK, retryRec.Code, retryRec.Body.String())
}

// ---- [REQUIRED TEST] no certificate observable without its account binding --------

// TestCollectCredentialRequest_BindFailureRevokesCertificateAndDeniesBootstrapFallback
// injects a failure between signing and binding (the account already holds the maximum
// number of certificate bindings) and asserts: the certificate is revoked, unusable,
// and — because extractAdminPrincipal checks IsRevoked before ever reaching the
// bootstrap-fallback branch — a revoked certificate carrying the admin marker can never
// resolve through that fallback as implicit root.
func TestCollectCredentialRequest_BindFailureRevokesCertificateAndDeniesBootstrapFallback(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-bind-fail", "collect-bind-fail-owner", ApproveCredentialRequestBody{
		GrantAdminMarker: true,
	})

	// Fill the account's certificate bindings to the cap so the post-sign bind fails.
	for i := 0; i < maxCertBindingsPerAccount; i++ {
		require.NoError(t, server.bindCertOnAccount(context.Background(), fx.accountUser, CertBinding{
			Serial:  "filler-serial-" + fx.accountUser + "-" + strconv.Itoa(i),
			BoundAt: time.Now().UTC(),
		}, "test-setup"))
	}
	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	require.Len(t, acct.CertBindings, maxCertBindingsPerAccount)

	revokedBefore, err := server.certManager.ListRevoked()
	require.NoError(t, err)

	rec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	assert.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "BEGIN CERTIFICATE")

	// The request is durably "collected" (the transition committed before the failed
	// mint) but no certificate is bound to the account.
	stored, err := server.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	assert.Equal(t, credentialRequestStatusCollected, stored.Status)
	require.NotEmpty(t, stored.CollectedSerial, "the signed serial must be durably recorded even though the bind failed")

	revokedAfter, err := server.certManager.ListRevoked()
	require.NoError(t, err)
	require.Len(t, revokedAfter, len(revokedBefore)+1, "exactly one new certificate must have been revoked")

	// The newly revoked serial must be the one collect signed.
	assert.True(t, server.certManager.IsRevoked(stored.CollectedSerial))

	// The account must not have gained a binding for it.
	acct, err = server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	for _, b := range acct.CertBindings {
		assert.NotEqual(t, stored.CollectedSerial, b.Serial, "a certificate revoked after a failed bind must never appear bound")
	}

	// Construct a certificate carrying the revoked serial and the admin marker — as
	// the actual collected certificate did — and present it at the TLS layer. Chain
	// verification happens at the TLS layer (extractAdminPrincipal's own doc comment),
	// so a synthetic self-signed certificate with the same serial exercises exactly the
	// revocation-lookup branch that must fire before the bootstrap fallback ever runs.
	serialInt, ok := new(big.Int).SetString(stored.CollectedSerial, 10)
	require.True(t, ok, "collected serial must be a base-10 integer")
	synthetic := makeAdminCertWithAttrs(t, 0, "irrelevant", false)
	synthetic.SerialNumber = serialInt

	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", synthetic)
	principal := server.extractAdminPrincipal(req)
	assert.Nil(t, principal, "a revoked certificate must never authenticate — including through the bootstrap fallback")
}

// ---- [REQUIRED TEST] marker set is verbatim from the recorded decision ------------

// TestCollectCredentialRequest_MarkersAreVerbatimNeverDerivedFromAccount is the
// [REQUIRED TEST]: approving with no marker grants onto an account that is itself
// root-scoped (i.e. an account whose own attributes, if consulted, would imply a very
// powerful credential) must still yield a certificate carrying none of the three
// markers — the marker set comes only from what was recorded at approval, never
// recomputed or widened from the bound account's own fields.
func TestCollectCredentialRequest_MarkersAreVerbatimNeverDerivedFromAccount(t *testing.T) {
	server := setupCollectTestServer(t)
	lodged := lodgeTestCredentialRequest(t, server, "collect-verbatim-tenant")

	rootAcctResp := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username:  "collect-verbatim-root-owner",
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, rootAcctResp.Code, rootAcctResp.Body.String())
	var created struct {
		Data AccountCreateResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rootAcctResp.Body.Bytes(), &created))
	require.True(t, created.Data.RootScope, "sanity: the target account must genuinely be root-scoped")

	approver := implicitAdminPrincipal("verbatim-approver")
	approveRec := approveCredentialRequest(t, server, approver, lodged.RequestID, ApproveCredentialRequestBody{
		Fingerprint: lodged.PublicKeyFingerprint,
		AccountID:   created.Data.ID,
		// Deliberately no Grant*Marker flags set.
	})
	require.Equal(t, http.StatusOK, approveRec.Code, approveRec.Body.String())

	rec := collectCredentialRequest(t, server, lodged.RequestID, lodged.CollectSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeCollectResponse(t, rec)
	assert.Empty(t, resp.GrantedMarkers, "no marker was granted at approval; the response must reflect exactly that")

	x509Cert := parseCertPEM(t, resp.CertificatePEM)
	assert.False(t, cert.HasAdminMarker(x509Cert),
		"the bound account being root-scoped must not cause the admin marker to be signed")
	assert.False(t, cert.HasRootScopeMarker(x509Cert),
		"the bound account being root-scoped must not cause the root-scope marker to be signed")
	assert.False(t, cert.HasPayloadSigningMarker(x509Cert))
}

// ---- audit --------------------------------------------------------------------------

func TestCollectCredentialRequest_AuditEvent(t *testing.T) {
	server := setupCollectTestServer(t)
	fx := lodgeAndApprove(t, server, "collect-audit-tenant", "collect-audit-owner", ApproveCredentialRequestBody{
		GrantAdminMarker: true,
	})

	rec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeCollectResponse(t, rec)

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "collect-audit-tenant"})
	require.NoError(t, err)

	var collectedEntry *business.AuditEntry
	for _, e := range entries {
		if e.Action == "credential_request.collected" && e.ResourceID == fx.requestID {
			collectedEntry = e
			break
		}
	}
	require.NotNil(t, collectedEntry, "credential_request.collected audit event must be recorded")
	assert.Equal(t, fx.accountID, collectedEntry.Details["account_id"])
	assert.Equal(t, resp.SerialNumber, collectedEntry.Details["serial"])

	for _, v := range collectedEntry.Details {
		assert.NotEqual(t, fx.collectSecret, v, "the audit event must never carry the raw collect secret")
	}
}
