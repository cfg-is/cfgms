// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Revocation-store outage tests for Issue #3852. Moving the revocation list off a
// node-local JSON file and behind certinterfaces.RevocationStore made IsRevoked a
// call that can fail for reasons other than a corrupt local file — a Postgres
// connection drop on a cluster node returns an error where the file-backed store
// previously returned "not revoked". Every IsRevoked call site in this package
// therefore grew an explicit error branch, and each of those branches is a
// security decision: fail closed where the answer gates authentication or
// signature trust, skip-and-log where the answer only decides whether a
// background sweep acts.
//
// These tests drive each branch through a real cert.Manager whose RevocationStore
// is a real file-backed store wrapped by failableRevocationStore below (no mock
// framework — see certinterfaces.RevocationStore). Every test arms the failure
// only after its fixture is built, and most disarm it afterwards, so the
// assertion isolates the error branch rather than a broken fixture.
package api

import (
	"context"
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
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// errRevocationStoreOutage is the error the wrapped store returns while armed.
var errRevocationStoreOutage = errors.New("revocation store temporarily unavailable")

// failableRevocationStore wraps a real certinterfaces.RevocationStore and makes
// IsRevoked return an error while armed. Revoke and ListRevoked always run
// against the wrapped store, so a test can build its fixture (issue, collect,
// revoke) for real and then arm the failure for the one call under test.
//
// It complements failingRevocationStore in handlers_accounts_test.go, which
// fails Revoke rather than IsRevoked and cannot be disarmed.
type failableRevocationStore struct {
	certinterfaces.RevocationStore

	mu     sync.Mutex
	failed bool
}

// arm makes every subsequent IsRevoked call return errRevocationStoreOutage.
func (s *failableRevocationStore) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = true
}

// disarm restores real IsRevoked behaviour, so a test can read the true
// revocation state back out after exercising the error branch.
func (s *failableRevocationStore) disarm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = false
}

func (s *failableRevocationStore) IsRevoked(ctx context.Context, serial string) (bool, error) {
	s.mu.Lock()
	failed := s.failed
	s.mu.Unlock()
	if failed {
		return false, errRevocationStoreOutage
	}
	return s.RevocationStore.IsRevoked(ctx, serial)
}

// newFailableRevocationCertManager returns a real cert.Manager backed by the
// process-wide shared test CA (so certificates it issues chain to the same CA
// the rest of the package's fixtures use) whose RevocationStore's IsRevoked can
// be made to fail on demand.
func newFailableRevocationCertManager(t *testing.T) (*cert.Manager, *failableRevocationStore) {
	t.Helper()
	storagePath := t.TempDir()
	seedSharedTestCA(t, storagePath)

	base, err := cert.NewFileRevocationStore(storagePath)
	require.NoError(t, err)
	store := &failableRevocationStore{RevocationStore: base}

	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:     storagePath,
		LoadExistingCA:  true,
		RevocationStore: store,
	})
	require.NoError(t, err)
	return mgr, store
}

// TestExtractAdminPrincipal_RevocationCheckFailure_FailsClosed is the security-critical
// case: middleware.go's IsRevoked error branch decides whether a revocation-store
// outage can be exploited to authenticate with a certificate the operator believes
// is revoked. Treating the error as "not revoked" would make an outage a
// re-enablement window for every revoked admin certificate, so the branch must
// reject the request.
//
// The test proves the certificate authenticates normally first, then changes only
// one thing — IsRevoked now errors — and asserts both the principal extraction and
// a real request through authenticationMiddleware are rejected.
func TestExtractAdminPrincipal_RevocationCheckFailure_FailsClosed(t *testing.T) {
	server, _ := setupCertBindingServer(t)

	rec := postAccount(t, server, strongPrincipal(), AccountRequest{
		Username:    "outage-operator",
		TenantID:    "msp-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())

	peerCert := makeAdminCertWithAttrs(t, 9961, "outage-operator", false)
	bindRec := bindCertReq(t, server, strongPrincipal(), "outage-operator", BindCertRequest{
		Serial: peerCert.SerialNumber.String(),
		Label:  "outage laptop",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code, "bind: %s", bindRec.Body.String())

	certMgr, revStore := newFailableRevocationCertManager(t)
	server.SetCertManager(certMgr)

	// Control: with the revocation store healthy the certificate authenticates.
	before := server.extractAdminPrincipal(
		requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert))
	require.NotNil(t, before, "sanity: the bound certificate must authenticate while the store is healthy")
	require.Equal(t, "msp-a", before.TenantID)

	// The only change: the revocation store can no longer answer.
	revStore.arm()

	after := server.extractAdminPrincipal(
		requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert))
	assert.Nil(t, after,
		"a revocation-check failure must fail closed — an unanswerable store must never be read as 'not revoked'")

	// The same decision at the HTTP boundary: the request is rejected and the
	// wrapped handler never runs.
	reached := false
	handler := server.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	httpRec := httptest.NewRecorder()
	handler.ServeHTTP(httpRec, requestWithTLSCert(http.MethodGet, "/api/v1/stewards", peerCert))
	assert.Equal(t, http.StatusUnauthorized, httpRec.Code,
		"a request presenting an admin certificate must be rejected while revocation cannot be checked: %s",
		httpRec.Body.String())
	assert.False(t, reached, "the authenticated handler must not run when the revocation check failed")

	// Once the store recovers the same certificate authenticates again, proving the
	// rejection came from the error branch and not from a damaged fixture.
	revStore.disarm()
	recovered := server.extractAdminPrincipal(
		requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert))
	assert.NotNil(t, recovered, "the certificate must authenticate again once the revocation store recovers")
}

// TestRevokeOrphanedCredential_RevocationCheckFailure_StoreError covers
// handleRevokeOrphanedCredential's IsRevoked error branch. The handler cannot tell
// "already revoked" from "unknown" while the store is down, and proceeding would
// report a revocation it never confirmed — the silent-divergence failure this story
// exists to remove — so it returns 500 STORE_ERROR instead.
func TestRevokeOrphanedCredential_RevocationCheckFailure_StoreError(t *testing.T) {
	server := setupCollectTestServer(t)
	certMgr, revStore := newFailableRevocationCertManager(t)
	server.certManager = certMgr

	fx := collectThenOrphan(t, server, "revoke-outage-tenant", "revoke-outage-owner", ApproveCredentialRequestBody{})

	revStore.arm()

	rec := revokeOrphanedCredential(t, server, testAdminPrincipal(), fx.serial)
	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"an unanswerable revocation store must surface as a server error, not a claimed revocation: %s", rec.Body.String())
	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "STORE_ERROR", resp.Error.Code)

	// The certificate must be left untouched: the handler returned before revoking.
	revStore.disarm()
	revoked, err := server.certManager.IsRevoked(fx.serial)
	require.NoError(t, err)
	assert.False(t, revoked, "the handler must not have revoked anything after failing the revocation check")

	// And with the store healthy the same call succeeds, proving the 500 came from
	// the error branch rather than from the fixture.
	retry := revokeOrphanedCredential(t, server, testAdminPrincipal(), fx.serial)
	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	revokedAfter, err := server.certManager.IsRevoked(fx.serial)
	require.NoError(t, err)
	assert.True(t, revokedAfter, "the retry after recovery must actually revoke the certificate")
}

// TestListOrphanedCredentials_RevocationCheckFailure_SkipsEntry covers
// handleListOrphanedCredentials' IsRevoked error branch. Listing is advisory: an
// entry whose revocation state cannot be read is omitted rather than presented as a
// live orphan an operator would then try to revoke. The list itself still succeeds.
func TestListOrphanedCredentials_RevocationCheckFailure_SkipsEntry(t *testing.T) {
	server := setupCollectTestServer(t)
	certMgr, revStore := newFailableRevocationCertManager(t)
	server.certManager = certMgr

	fx := collectThenOrphan(t, server, "list-outage-tenant", "list-outage-owner", ApproveCredentialRequestBody{})

	// Control: while the store is healthy the orphan is listed.
	healthyRec := listOrphanedCredentials(t, server, nil)
	require.Equal(t, http.StatusOK, healthyRec.Code, healthyRec.Body.String())
	require.True(t, orphanListContainsSerial(decodeOrphanedList(t, healthyRec), fx.serial),
		"sanity: the orphaned certificate must be listed while the revocation store is healthy")

	revStore.arm()

	rec := listOrphanedCredentials(t, server, nil)
	require.Equal(t, http.StatusOK, rec.Code,
		"a per-entry revocation-check failure must not fail the whole listing: %s", rec.Body.String())
	assert.False(t, orphanListContainsSerial(decodeOrphanedList(t, rec), fx.serial),
		"an entry whose revocation state cannot be read must be skipped, not reported as a live orphan")

	revStore.disarm()
	recoveredRec := listOrphanedCredentials(t, server, nil)
	require.Equal(t, http.StatusOK, recoveredRec.Code, recoveredRec.Body.String())
	assert.True(t, orphanListContainsSerial(decodeOrphanedList(t, recoveredRec), fx.serial),
		"the entry must reappear once the revocation store recovers")
}

// orphanListContainsSerial reports whether the listing carries the given serial.
func orphanListContainsSerial(list []OrphanedCredentialInfo, serial string) bool {
	for _, o := range list {
		if o.Serial == serial {
			return true
		}
	}
	return false
}

// TestSweepOrphanedCollectedCertificates_RevocationCheckFailure_SkipsEntry covers the
// sweep's IsRevoked error branch. The sweep runs unattended, so the branch must skip
// the entry and log rather than panic or act on an unknown state — and, critically,
// the skip must not be permanent: the next sweep after the store recovers still
// revokes the orphan.
func TestSweepOrphanedCollectedCertificates_RevocationCheckFailure_SkipsEntry(t *testing.T) {
	server := setupCollectTestServer(t)
	certMgr, revStore := newFailableRevocationCertManager(t)
	server.certManager = certMgr

	ctx := context.Background()
	fx := collectThenOrphan(t, server, "sweep-outage-tenant", "sweep-outage-owner", ApproveCredentialRequestBody{
		GrantAdminMarker: true,
	})

	revStore.arm()
	server.sweepOrphanedCollectedCertificates(ctx)
	revStore.disarm()

	revoked, err := server.certManager.IsRevoked(fx.serial)
	require.NoError(t, err)
	assert.False(t, revoked,
		"the sweep must skip an entry whose revocation state it could not read, not act on an unknown state")
	assert.Equal(t, 0,
		countAuditEntries(t, server, fx.tenantID, "credential_request.orphaned_certificate_revoked", fx.requestID),
		"a skipped entry must emit no revocation audit event")

	// The skip is transient, not terminal: the orphan is still genuinely orphaned and
	// the next sweep after recovery revokes it. This is what distinguishes skipping
	// from mis-classifying the entry as handled.
	server.sweepOrphanedCollectedCertificates(ctx)
	revokedAfter, err := server.certManager.IsRevoked(fx.serial)
	require.NoError(t, err)
	assert.True(t, revokedAfter,
		"the sweep after the store recovers must revoke the still-orphaned certificate")
	assert.Equal(t, 1,
		countAuditEntries(t, server, fx.tenantID, "credential_request.orphaned_certificate_revoked", fx.requestID),
		"the recovered sweep must emit exactly one revocation audit event")
}

// TestValidateCommandSignature_RevocationCheckFailure_FailsClosed covers
// validatePublicBetaCommandSignature's IsRevoked error branch. This check sits on
// the trust boundary for ad-hoc command execution: if an unreadable revocation store
// were treated as "not revoked", a revoked operator signing certificate would keep
// authorising fleet-wide command dispatch for the duration of the outage.
func TestValidateCommandSignature_RevocationCheckFailure_FailsClosed(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	certMgr, revStore := newFailableRevocationCertManager(t)
	server.certManager = certMgr

	content := []byte("hostname")
	targets := []string{"steward-1"}
	fields := signedOperatorEnvelopeFields(t, server, content, "bash", targets)
	sig, nonce, expiresAt := envelopeSignatureFields(t, fields)

	// Control: the signature validates while the revocation store is healthy.
	require.NoError(t,
		server.validatePublicBetaCommandSignature(content, "bash", targets, nonce, expiresAt, sig),
		"sanity: a well-formed operator signature must validate while the store is healthy")

	revStore.arm()

	err := server.validatePublicBetaCommandSignature(content, "bash", targets, nonce, expiresAt, sig)
	require.Error(t, err,
		"an unreadable revocation store must fail the signature check closed, not authorise the command")
	assert.ErrorIs(t, err, errRevocationStoreOutage,
		"the failure must be the revocation-store error, not an unrelated validation failure")

	revStore.disarm()
	assert.NoError(t,
		server.validatePublicBetaCommandSignature(content, "bash", targets, nonce, expiresAt, sig),
		"the same signature must validate again once the revocation store recovers")
}

// envelopeSignatureFields unpacks signedOperatorEnvelopeFields' request-body map into
// the arguments validatePublicBetaCommandSignature takes directly, so a test can drive
// the validator without going through the HTTP handler.
func envelopeSignatureFields(t *testing.T, fields map[string]interface{}) (*execCommandSignature, string, time.Time) {
	t.Helper()
	sigMap, ok := fields["signature"].(map[string]interface{})
	require.True(t, ok, "signature field must be a map")
	sig := &execCommandSignature{
		Algorithm: sigMap["algorithm"].(string),
		Value:     sigMap["value"].(string),
		PublicKey: sigMap["public_key"].(string),
	}
	nonce, ok := fields["nonce"].(string)
	require.True(t, ok, "nonce field must be a string")
	expiresAt, err := time.Parse(time.RFC3339, fields["expires_at"].(string))
	require.NoError(t, err)
	return sig, nonce, expiresAt
}
