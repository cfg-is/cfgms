// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3775 (Epic #3751 / ADR-031 Decision 1): [REQUIRED TEST] cross-node
// concurrent-transition coverage for the six compare-and-set transitions this story
// moves off per-process sync.Mutex guards (or, for the credential-request approve
// transition, adds real protection to for the first time) and onto
// SecretStore.CompareAndSwapSecret. Each test uses setupTwoNodeSharedStoreServers
// (handlers_accounts_test.go, Issue #3311) — two independent *Server instances
// sharing one durable secret store, modelling two controller nodes — and proves that
// of two concurrent attempts at the same transition, exactly one succeeds and the
// other observes a conflict, never a double-grant or lost update.
//
// Scope, stated precisely so these are not read as more than they are: the shared
// store here is flatfile-backed, so what they exercise is the handler logic plus the
// file-locked compare-and-swap — two processes, one host. They do NOT exercise the
// production cluster shape, where the backend is PostgreSQL and atomicity comes from
// a conditional write rather than a file lock. That primitive is proved directly
// against a real database in
// pkg/storage/providers/database/config_store_cas_test.go, the secret store's
// selection of it in pkg/secrets/providers/sops/cas_test.go, and the refusal to run a
// cluster-mode controller without it in
// TestNewSecretStore_ClusterModeRejectsNonAtomicSwap (secret_store_guard_test.go).
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// lodgeCredentialRequestDirect calls handleLodgeCredentialRequest directly rather
// than through server.router — the handler itself checks the Authorization header,
// so no router dispatch is needed, and calling it directly keeps this file's cross-
// node tests independent of each node's individual router/middleware wiring.
func lodgeCredentialRequestDirect(t *testing.T, server *Server, bearerToken string, body LodgeCredentialRequestBody) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/lodge", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	rec := httptest.NewRecorder()
	server.handleLodgeCredentialRequest(rec, req)
	return rec
}

// base64URLEncode matches the credential_id path-parameter encoding
// handleWebAuthnRevokeCredential expects (base64.RawURLEncoding).
func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// errIsAlreadyCollected reports whether err is errCredentialRequestAlreadyCollected.
func errIsAlreadyCollected(err error) bool {
	return errors.Is(err, errCredentialRequestAlreadyCollected)
}

// clientCertConfigForTest builds a minimal cert.ClientCertConfig for acct, mirroring
// the shape signAndBindCollectedCertificate and renewBoundCertificate use in
// production, for tests that sign a certificate directly.
func clientCertConfigForTest(_ *testing.T, acct *account) cert.ClientCertConfig {
	return cert.ClientCertConfig{
		CommonName:   acct.Username,
		Organization: "CFGMS",
		ClientID:     acct.ID,
		ValidityDays: credentialCollectValidityDays,
	}
}

// ---- 1. handleWebAuthnRevokeCredential (formerly credentialMu) ----------------------

func TestCrossNode_WebAuthnRevoke_ConcurrentTransition(t *testing.T) {
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)

	rec := postAccount(t, nodeA, testAdminPrincipal(), AccountRequest{Username: "cross-node-webauthn"})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// Three credentials so removing any single one never reaches zero — the
	// anti-lockout guard must not confound this test with a second, unrelated
	// reason for a 409.
	credA := []byte("cross-node-cred-a")
	credB := []byte("cross-node-cred-b")
	credC := []byte("cross-node-cred-c")
	injectCredential(t, nodeA, "cross-node-webauthn", credA)
	injectCredential(t, nodeA, "cross-node-webauthn", credB)
	injectCredential(t, nodeA, "cross-node-webauthn", credC)

	acct, err := nodeA.getAccount(context.Background(), "cross-node-webauthn")
	require.NoError(t, err)
	require.Len(t, acct.Credentials, 3)

	credAParam := base64URLEncode(credA)
	credBParam := base64URLEncode(credB)

	var wg sync.WaitGroup
	var recA, recB *httptest.ResponseRecorder
	wg.Add(2)
	go func() {
		defer wg.Done()
		recA = doRevokeCredentialCookieAuth(t, nodeA, acct, "cross-node-webauthn", credAParam)
	}()
	go func() {
		defer wg.Done()
		recB = doRevokeCredentialCookieAuth(t, nodeB, acct, "cross-node-webauthn", credBParam)
	}()
	wg.Wait()

	codes := []int{recA.Code, recB.Code}
	successes, conflicts := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusNoContent:
			successes++
		case http.StatusConflict:
			conflicts++
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent revoke must succeed (204): %v", codes)
	assert.Equal(t, 1, conflicts, "exactly one concurrent revoke must lose the compare-and-swap (409): %v", codes)

	final, err := nodeB.getAccount(context.Background(), "cross-node-webauthn")
	require.NoError(t, err)
	assert.Len(t, final.Credentials, 2, "exactly one credential must have been removed, never both or neither")
}

// ---- 2. enrolment-token spend-then-lodge (formerly credentialRequestMu) ------------

func TestCrossNode_EnrolmentTokenSpend_ConcurrentTransition(t *testing.T) {
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)

	rawToken := "cross-node-raw-token-0123456789abcdef0123456789abcdef"
	tok := &enrolmentToken{
		ID:          "et-cross-node",
		TenantID:    "cross-node-tenant",
		TokenHash:   hashCredentialSecret(rawToken),
		TokenPrefix: enrolmentTokenDisplayPrefix(rawToken),
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   "test-setup",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	require.NoError(t, nodeA.persistEnrolmentToken(context.Background(), tok))

	csrA := generateTestCSR(t, "cross-node-lodge-a")
	csrB := generateTestCSR(t, "cross-node-lodge-b")

	var wg sync.WaitGroup
	var recA, recB *httptest.ResponseRecorder
	wg.Add(2)
	go func() {
		defer wg.Done()
		recA = lodgeCredentialRequestDirect(t, nodeA, rawToken, LodgeCredentialRequestBody{CSRPEM: csrA})
	}()
	go func() {
		defer wg.Done()
		recB = lodgeCredentialRequestDirect(t, nodeB, rawToken, LodgeCredentialRequestBody{CSRPEM: csrB})
	}()
	wg.Wait()

	codes := []int{recA.Code, recB.Code}
	successes, unauthorized := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusCreated:
			successes++
		case http.StatusUnauthorized:
			unauthorized++
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent lodge must spend the token and succeed (201): %v", codes)
	assert.Equal(t, 1, unauthorized, "the race loser must observe the same uniform unauthorized response as an already-spent token (401): %v", codes)

	metas, err := nodeB.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		TenantID: "cross-node-tenant",
		Tags:     []string{"credential_request"},
	})
	require.NoError(t, err)
	assert.Len(t, metas, 1, "exactly one pending credential request must have been lodged against this token, never two")
}

// ---- 3. credential-request approved->collected (formerly credentialRequestCollectMu) --

func TestCrossNode_CredentialRequestCollect_ConcurrentTransition(t *testing.T) {
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)
	nodeA.certManager = newTestCertManager(t)
	nodeB.certManager = newTestCertManager(t)

	fx := lodgeAndApprove(t, nodeA, "cross-node-collect-tenant", "cross-node-collect-owner", ApproveCredentialRequestBody{})

	var wg sync.WaitGroup
	var claimedA, claimedB *pendingCredentialRequest
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		claimedA, errA = nodeA.claimCredentialRequestForCollection(context.Background(), fx.requestID)
	}()
	go func() {
		defer wg.Done()
		claimedB, errB = nodeB.claimCredentialRequestForCollection(context.Background(), fx.requestID)
	}()
	wg.Wait()

	results := []struct {
		claimed *pendingCredentialRequest
		err     error
	}{{claimedA, errA}, {claimedB, errB}}
	successes, conflicts := 0, 0
	for _, r := range results {
		switch {
		case r.err == nil && r.claimed != nil:
			successes++
		case errIsAlreadyCollected(r.err):
			conflicts++
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent claim must win the approved->collected transition")
	assert.Equal(t, 1, conflicts, "the race loser must observe errCredentialRequestAlreadyCollected, never a second claim")

	final, err := nodeB.getPendingCredentialRequestByID(context.Background(), fx.requestID)
	require.NoError(t, err)
	require.NotNil(t, final)
	assert.Equal(t, credentialRequestStatusCollected, final.Status, "the request must be collected exactly once")
}

// ---- 4. CLI-login approved->collected (formerly cliLoginCollectMu) -----------------

func TestCrossNode_CliLoginCollect_ConcurrentTransition(t *testing.T) {
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)

	now := time.Now().UTC()
	approvedBy := "cross-node-approver"
	req := &pendingCliLoginRequest{
		ID:           "cli-cross-node",
		Status:       cliLoginRequestStatusApproved,
		VerifierHash: hashCredentialSecret("cross-node-verifier"),
		UserCode:     "CROS-NODE",
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Hour),
		ApprovedAt:   &now,
		ApprovedBy:   approvedBy,
		SessionID:    "sess-cross-node",
		SessionToken: "tok-cross-node",
	}
	require.NoError(t, nodeA.persistCliLoginRequest(context.Background(), req))

	var wg sync.WaitGroup
	var claimedA, claimedB *pendingCliLoginRequest
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		claimedA, errA = nodeA.claimCliLoginRequestForCollection(context.Background(), req.ID)
	}()
	go func() {
		defer wg.Done()
		claimedB, errB = nodeB.claimCliLoginRequestForCollection(context.Background(), req.ID)
	}()
	wg.Wait()

	results := []struct {
		claimed *pendingCliLoginRequest
		err     error
	}{{claimedA, errA}, {claimedB, errB}}
	successes, conflicts := 0, 0
	for _, r := range results {
		switch {
		case r.err == nil && r.claimed != nil:
			successes++
			assert.Equal(t, "tok-cross-node", r.claimed.SessionToken, "the winner must receive the session token exactly once")
		case r.err == errCliLoginRequestAlreadyCollected:
			conflicts++
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent claim must win the approved->collected transition")
	assert.Equal(t, 1, conflicts, "the race loser must observe errCliLoginRequestAlreadyCollected, never a second claim, and never a second copy of the token")

	final, err := nodeB.getCliLoginRequestByID(context.Background(), req.ID)
	require.NoError(t, err)
	require.NotNil(t, final)
	assert.Equal(t, cliLoginRequestStatusCollected, final.Status)
	assert.Empty(t, final.SessionToken, "the durable record must never retain the token once collected")
}

// ---- 5. credential issue-and-rebind (formerly credentialRenewalMu) -----------------

func TestCrossNode_CredentialRenewal_ConcurrentTransition(t *testing.T) {
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)
	certMgrA := newTestCertManager(t)
	certMgrB := newTestCertManager(t)
	nodeA.certManager = certMgrA
	nodeB.certManager = certMgrB

	// Bind an initial certificate to a shared account via nodeA (durable, so nodeB
	// sees it too).
	rec := postAccount(t, nodeA, testAdminPrincipal(), AccountRequest{Username: "cross-node-renewal"})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	acct, err := nodeA.getAccount(context.Background(), "cross-node-renewal")
	require.NoError(t, err)

	oldCSR := generateTestCSR(t, "cross-node-renewal-old")
	oldParsed, err := parseAndVerifyCSR(oldCSR)
	require.NoError(t, err)
	oldCfg := clientCertConfigForTest(t, acct)
	issuedOld, err := certMgrA.SignClientCertificateRequest(oldParsed.PublicKey, &oldCfg)
	require.NoError(t, err)

	oldFP, _ := publicKeyFingerprint(oldParsed.RawSubjectPublicKeyInfo)
	require.NoError(t, nodeA.bindCertOnAccount(context.Background(), acct.Username, CertBinding{
		Serial:      issuedOld.SerialNumber,
		Fingerprint: oldFP,
		BoundAt:     time.Now().UTC(),
	}, "test-setup"))

	newCSRA, err := parseAndVerifyCSR(generateTestCSR(t, "cross-node-renewal-new-a"))
	require.NoError(t, err)
	newCSRB, err := parseAndVerifyCSR(generateTestCSR(t, "cross-node-renewal-new-b"))
	require.NoError(t, err)
	fpA, _ := publicKeyFingerprint(newCSRA.RawSubjectPublicKeyInfo)
	fpB, _ := publicKeyFingerprint(newCSRB.RawSubjectPublicKeyInfo)

	var wg sync.WaitGroup
	var okA, okB bool
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _, okA, errA = nodeA.renewBoundCertificate(context.Background(), issuedOld.SerialNumber, newCSRA, fpA, nil, "renewer-a")
	}()
	go func() {
		defer wg.Done()
		_, _, okB, errB = nodeB.renewBoundCertificate(context.Background(), issuedOld.SerialNumber, newCSRB, fpB, nil, "renewer-b")
	}()
	wg.Wait()
	_ = okA
	_ = okB

	successes, conflicts := 0, 0
	for _, err := range []error{errA, errB} {
		switch err {
		case nil:
			successes++
		case errCredentialRenewalInProgress:
			conflicts++
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent renewal must claim and sign a new certificate: errA=%v errB=%v", errA, errB)
	assert.Equal(t, 1, conflicts, "the race loser must observe errCredentialRenewalInProgress before ever signing a new certificate")

	final, err := nodeB.getAccount(context.Background(), "cross-node-renewal")
	require.NoError(t, err)
	newSerials := 0
	for _, b := range final.CertBindings {
		if b.Serial != issuedOld.SerialNumber {
			newSerials++
		}
	}
	assert.Equal(t, 1, newSerials, "exactly one new certificate must ever have been bound for this renewal, never two")
}

// TestCrossNode_CredentialRenewal_AbandonedClaimIsRecoverable proves a renewal that
// died between claiming and releasing does not lock the certificate out of renewal
// forever.
//
// The claim record is durable and nothing sweeps it: no read path can see it once it
// expires and releaseCertificateRenewalClaim never runs for a process that crashed.
// Recovery therefore rests entirely on CompareAndSwapSecret treating an expired
// record as absent (Issue #3775). Without that, every later renewal of this serial
// answers 409 RENEWAL_IN_PROGRESS forever — and for an admin whose only credential is
// that certificate, expiry is a permanent lockout.
//
// The abandoned claim is created here with a short TTL rather than by waiting out
// credentialRenewalClaimTTL: the state under test is "a claim record whose TTL has
// elapsed", and this constructs exactly that state through the same
// CompareAndSwapSecret call the production claim path uses.
func TestCrossNode_CredentialRenewal_AbandonedClaimIsRecoverable(t *testing.T) {
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)
	certMgr := newTestCertManager(t)
	nodeA.certManager = certMgr
	nodeB.certManager = certMgr

	rec := postAccount(t, nodeA, testAdminPrincipal(), AccountRequest{Username: "abandoned-claim"})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	acct, err := nodeA.getAccount(context.Background(), "abandoned-claim")
	require.NoError(t, err)

	oldParsed, err := parseAndVerifyCSR(generateTestCSR(t, "abandoned-claim-old"))
	require.NoError(t, err)
	oldCfg := clientCertConfigForTest(t, acct)
	issuedOld, err := certMgr.SignClientCertificateRequest(oldParsed.PublicKey, &oldCfg)
	require.NoError(t, err)
	oldFP, _ := publicKeyFingerprint(oldParsed.RawSubjectPublicKeyInfo)
	require.NoError(t, nodeA.bindCertOnAccount(context.Background(), acct.Username, CertBinding{
		Serial:      issuedOld.SerialNumber,
		Fingerprint: oldFP,
		BoundAt:     time.Now().UTC(),
	}, "test-setup"))

	claimTenant := accountStorageTenant(acct.TenantID)
	claimKey := credentialRenewalClaimKey(issuedOld.SerialNumber)

	// A live claim blocks a second attempt — the property the claim exists for, and
	// the control for the recovery assertion below.
	_, ok, err := nodeA.secretStore.CompareAndSwapSecret(context.Background(), claimTenant+"/"+claimKey, 0,
		&secretsif.SecretRequest{
			Key: claimKey, Value: "", TenantID: claimTenant, CreatedBy: "crashed-renewer",
			Tags: []string{"credential_renewal_claim"}, TTL: time.Hour,
		})
	require.NoError(t, err)
	require.True(t, ok)

	blockedCSR, err := parseAndVerifyCSR(generateTestCSR(t, "abandoned-claim-blocked"))
	require.NoError(t, err)
	blockedFP, _ := publicKeyFingerprint(blockedCSR.RawSubjectPublicKeyInfo)
	_, _, _, err = nodeB.renewBoundCertificate(context.Background(), issuedOld.SerialNumber, blockedCSR, blockedFP, nil, "renewer-b")
	require.ErrorIs(t, err, errCredentialRenewalInProgress,
		"a live claim must block a concurrent renewal on another node")

	// Replace it with the state a crashed renewer leaves behind once its TTL has
	// elapsed: the record is still on disk, but expired.
	current, err := nodeA.secretStore.GetSecret(context.Background(), claimTenant+"/"+claimKey)
	require.NoError(t, err)
	_, ok, err = nodeA.secretStore.CompareAndSwapSecret(context.Background(), claimTenant+"/"+claimKey, current.Version,
		&secretsif.SecretRequest{
			Key: claimKey, Value: "", TenantID: claimTenant, CreatedBy: "crashed-renewer",
			Tags: []string{"credential_renewal_claim"}, TTL: 20 * time.Millisecond,
		})
	require.NoError(t, err)
	require.True(t, ok)

	require.Eventually(t, func() bool {
		_, err := nodeA.secretStore.GetSecret(context.Background(), claimTenant+"/"+claimKey)
		return err != nil
	}, time.Second, 5*time.Millisecond, "the abandoned claim must become unreadable once its TTL elapses")

	recoveredCSR, err := parseAndVerifyCSR(generateTestCSR(t, "abandoned-claim-recovered"))
	require.NoError(t, err)
	recoveredFP, _ := publicKeyFingerprint(recoveredCSR.RawSubjectPublicKeyInfo)
	issuedNew, _, _, err := nodeB.renewBoundCertificate(context.Background(), issuedOld.SerialNumber, recoveredCSR, recoveredFP, nil, "renewer-b")
	require.NoError(t, err, "an expired claim must not block renewal forever; the TTL is the fail-safe")
	require.NotNil(t, issuedNew)

	final, err := nodeA.getAccount(context.Background(), "abandoned-claim")
	require.NoError(t, err)
	newSerials := 0
	for _, b := range final.CertBindings {
		if b.Serial != issuedOld.SerialNumber {
			newSerials++
		}
	}
	assert.Equal(t, 1, newSerials,
		"recovery must issue exactly one new certificate — the blocked attempt must never have signed one")
}

// ---- 6. credential-request pending->approved (previously unprotected) -------------

func TestCrossNode_CredentialRequestApprove_ConcurrentTransition(t *testing.T) {
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)

	lodged := lodgeTestCredentialRequest(t, nodeA, "cross-node-approve-tenant")
	acctA := createApprovalTestAccount(t, nodeA, "cross-node-approve-owner-a", "cross-node-approve-tenant")
	acctB := createApprovalTestAccount(t, nodeA, "cross-node-approve-owner-b", "cross-node-approve-tenant")

	bodyA := ApproveCredentialRequestBody{Fingerprint: lodged.PublicKeyFingerprint, AccountID: acctA.ID}
	bodyB := ApproveCredentialRequestBody{Fingerprint: lodged.PublicKeyFingerprint, AccountID: acctB.ID}

	var wg sync.WaitGroup
	var recA, recB *httptest.ResponseRecorder
	wg.Add(2)
	go func() {
		defer wg.Done()
		recA = approveCredentialRequest(t, nodeA, implicitAdminPrincipal("approver-a"), lodged.RequestID, bodyA)
	}()
	go func() {
		defer wg.Done()
		recB = approveCredentialRequest(t, nodeB, implicitAdminPrincipal("approver-b"), lodged.RequestID, bodyB)
	}()
	wg.Wait()

	codes := []int{recA.Code, recB.Code}
	successes, conflicts := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			successes++
		case http.StatusConflict:
			conflicts++
		}
	}
	// This is the transition that had NO protection at all before Issue #3775: two
	// concurrent approvals could both pass the pending check and both write, binding
	// two different accounts to one CSR with the second write silently winning.
	require.Equal(t, 1, successes, "exactly one concurrent approval must succeed (200): %v", codes)
	require.Equal(t, 1, conflicts, "the race loser must receive 409 Conflict, never a silent second write: %v", codes)

	final, err := nodeB.getPendingCredentialRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	require.NotNil(t, final)
	assert.Equal(t, credentialRequestStatusApproved, final.Status)
	assert.Contains(t, []string{acctA.ID, acctB.ID}, final.BoundAccountID,
		"the durably bound account must be exactly the winner's, not a merge or corruption")
}
