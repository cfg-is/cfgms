// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ---- test helpers -----------------------------------------------------------------

// setupRenewalTestServer returns a server wired with a real certificate manager —
// renewal signs certificates, so (mirroring setupCollectTestServer) it is one of the
// handlers in this package that needs one.
func setupRenewalTestServer(t *testing.T) *Server {
	t.Helper()
	server := setupTestServer(t)
	server.certManager = newTestCertManager(t)
	return server
}

// renewalFixture is a fully issued enrolment-issued credential ready for renewal
// tests: a real signed certificate, bound to a real account, with the caller-supplied
// keypair retained so a test can build a reuse-the-old-key CSR.
type renewalFixture struct {
	accountID   string
	accountUser string
	tenantID    string
	oldSerial   string
	oldCert     *x509.Certificate
	oldKey      *ecdsa.PrivateKey
}

// encodeTestCSR builds a self-signed CSR PEM over key — like generateTestCSR, but
// taking a caller-supplied key so the test can later build a second CSR that reuses
// the same public key (Issue #3724's key-reuse-rejection [REQUIRED TEST]).
func encodeTestCSR(t *testing.T, key *ecdsa.PrivateKey, commonName string) string {
	t.Helper()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// issueRenewableCredential runs the full lodge -> approve -> collect pipeline
// (#3717/#3718/#3719) with a caller-controlled keypair and returns everything a
// renewal test needs, including the parsed, real, CA-signed certificate to present
// over "mutual TLS" in the renewal request.
func issueRenewableCredential(t *testing.T, server *Server, tenantID, username string, grant ApproveCredentialRequestBody, approver *Principal) renewalFixture {
	t.Helper()
	minted := mintTestEnrolmentToken(t, server, tenantID)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrPEM := encodeTestCSR(t, key, "renew-test-device")

	lodgeRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{CSRPEM: csrPEM})
	require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())
	lodged := decodeLodgeResponse(t, lodgeRec)

	acct := createApprovalTestAccount(t, server, username, tenantID)

	grant.Fingerprint = lodged.PublicKeyFingerprint
	grant.AccountID = acct.ID
	if approver == nil {
		approver = implicitAdminPrincipal("renew-approver-" + username)
	}
	approveRec := approveCredentialRequest(t, server, approver, lodged.RequestID, grant)
	require.Equal(t, http.StatusOK, approveRec.Code, approveRec.Body.String())

	collectRec := collectCredentialRequest(t, server, lodged.RequestID, lodged.CollectSecret)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	collected := decodeCollectResponse(t, collectRec)

	return renewalFixture{
		accountID:   acct.ID,
		accountUser: acct.Username,
		tenantID:    tenantID,
		oldSerial:   collected.SerialNumber,
		oldCert:     parseCertPEM(t, collected.CertificatePEM),
		oldKey:      key,
	}
}

// withNotAfter returns a shallow copy of c with NotAfter replaced. x509.Certificate is
// an ordinary struct with no unexported state relevant to extractAdminPrincipal or this
// handler (both only ever read fields, never re-verify the signature — chain
// verification is documented as the TLS layer's job), so mutating a copy is sufficient
// to simulate "this certificate is close to expiry" without re-signing anything.
func withNotAfter(c *x509.Certificate, notAfter time.Time) *x509.Certificate {
	clone := *c
	clone.NotAfter = notAfter
	return &clone
}

// renewCredentialRaw POSTs rawBody to /api/v1/credential-renewal through the real
// router (so authenticationMiddleware, and therefore extractAdminPrincipal, actually
// runs), presenting peerCert as the mTLS client certificate.
func renewCredentialRaw(t *testing.T, server *Server, peerCert *x509.Certificate, rawBody []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-renewal", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	if peerCert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerCert}}
	}
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

// renewCredential is the common case: build a fresh keypair, submit its CSR against
// peerCert, and return the response.
func renewCredential(t *testing.T, server *Server, peerCert *x509.Certificate) (*httptest.ResponseRecorder, *ecdsa.PrivateKey) {
	t.Helper()
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrPEM := encodeTestCSR(t, newKey, "renew-test-device")
	body, err := json.Marshal(RenewCredentialRequest{CSRPEM: csrPEM})
	require.NoError(t, err)
	return renewCredentialRaw(t, server, peerCert, body), newKey
}

func decodeRenewResponse(t *testing.T, rec *httptest.ResponseRecorder) RenewCredentialResponse {
	t.Helper()
	var resp struct {
		Data RenewCredentialResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// certBindingBySerial finds the CertBinding matching serial on acctUsername, or nil.
func certBindingBySerial(t *testing.T, server *Server, acctUsername, serial string) *CertBinding {
	t.Helper()
	acct, err := server.getAccount(context.Background(), acctUsername)
	require.NoError(t, err)
	require.NotNil(t, acct)
	for i := range acct.CertBindings {
		if acct.CertBindings[i].Serial == serial {
			return &acct.CertBindings[i]
		}
	}
	return nil
}

// certifiedRootScopeApprover returns a principal that satisfies
// principalHasCertifiedRootScope, for tests that grant the root-scope marker.
func certifiedRootScopeApprover(id string) *Principal {
	return &Principal{
		ID: id, Assurance: session.AssuranceStrong,
		RootScoped: true, CertSerial: "real-cert-serial-" + id, ImplicitAdmin: true,
	}
}

// ---- happy path ---------------------------------------------------------------------

func TestRenewCredential_Success(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-tenant", "renew-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	// The real issued certificate is valid for credentialCollectValidityDays (365
	// days) — far outside the 30-day renewal window. Simulate "close to expiry"
	// without re-signing anything (see withNotAfter's doc comment).
	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))

	rec, _ := renewCredential(t, server, presented)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRenewResponse(t, rec)

	assert.NotEmpty(t, resp.CertificatePEM)
	assert.NotEmpty(t, resp.CACertificatePEM)
	assert.NotEmpty(t, resp.SerialNumber)
	assert.NotEqual(t, fx.oldSerial, resp.SerialNumber, "renewal must mint a new serial, not reuse the old one")
	assert.Equal(t, fx.accountID, resp.AccountID)
	assert.Equal(t, []string{credentialMarkerAdmin}, resp.GrantedMarkers)

	assert.True(t, server.certManager.IsRevoked(fx.oldSerial), "the old serial must be revoked after a successful renewal")

	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	require.Len(t, acct.CertBindings, 1, "exactly one live certificate binding must exist for this account after renewal")
	assert.Equal(t, resp.SerialNumber, acct.CertBindings[0].Serial)
}

// ---- renewal window -----------------------------------------------------------------

func TestRenewCredential_RefusedOutsideRenewalWindow(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-window-tenant", "renew-window-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	// Well beyond credentialRenewalWindow (30 days) from expiry.
	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(200*24*time.Hour))
	rec, _ := renewCredential(t, server, presented)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "OUTSIDE_RENEWAL_WINDOW", errCode(t, rec.Body.Bytes()))

	assert.False(t, server.certManager.IsRevoked(fx.oldSerial), "a refused renewal must not revoke the still-valid old certificate")
	assert.NotNil(t, certBindingBySerial(t, server, fx.accountUser, fx.oldSerial), "the old binding must remain intact")
}

func TestRenewCredential_RefusedForAlreadyExpiredCertificate(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-expired-tenant", "renew-expired-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(-time.Hour))
	rec, _ := renewCredential(t, server, presented)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "CERTIFICATE_EXPIRED", errCode(t, rec.Body.Bytes()))

	assert.False(t, server.certManager.IsRevoked(fx.oldSerial))
	assert.NotNil(t, certBindingBySerial(t, server, fx.accountUser, fx.oldSerial))
}

// ---- revoked serial -------------------------------------------------------------------

// TestRenewCredential_RefusedForRevokedSerial: a revoked certificate cannot even
// authenticate — extractAdminPrincipal checks certManager.IsRevoked before ever
// constructing a Principal (middleware.go) — so the whole request is rejected as
// unauthenticated, never reaching the renewal handler's own logic.
func TestRenewCredential_RefusedForRevokedSerial(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-revoked-tenant", "renew-revoked-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	require.NoError(t, server.certManager.Revoke(fx.oldSerial))

	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))
	rec, _ := renewCredential(t, server, presented)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
}

// ---- [REQUIRED TEST] marker set is never widened, across every combination ---------

// TestRenewCredential_MarkerSetNeverWidened is the [REQUIRED TEST]: for every
// combination of the three markers on the presented certificate, the renewed
// certificate carries exactly that set — never more. The admin marker must be present
// for the request to authenticate at all (extractAdminPrincipal requires it), so the
// "admin absent" combinations are asserted as outright authentication failures: no
// certificate is ever minted for them, which is the strongest form of "never widened".
func TestRenewCredential_MarkerSetNeverWidened(t *testing.T) {
	cases := []struct {
		name           string
		slug           string
		admin          bool
		payloadSigning bool
		rootScope      bool
	}{
		{"admin only", "a1", true, false, false},
		{"admin + payload_signing", "a2", true, true, false},
		{"admin + root_scope", "a3", true, false, true},
		{"admin + payload_signing + root_scope", "a4", true, true, true},
		{"payload_signing only, no admin", "b1", false, true, false},
		{"root_scope only, no admin", "b2", false, false, true},
		{"payload_signing + root_scope, no admin", "b3", false, true, true},
		{"no markers at all", "b4", false, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := setupRenewalTestServer(t)
			grant := ApproveCredentialRequestBody{
				GrantAdminMarker:          tc.admin,
				GrantPayloadSigningMarker: tc.payloadSigning,
				GrantRootScopeMarker:      tc.rootScope,
			}
			approver := certifiedRootScopeApprover("marker-test-" + tc.slug)
			fx := issueRenewableCredential(t, server, "renew-marker-tenant-"+tc.slug, "renew-marker-owner-"+tc.slug, grant, approver)

			presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))
			rec, _ := renewCredential(t, server, presented)

			if !tc.admin {
				// No admin marker on the presented certificate: extractAdminPrincipal
				// never authenticates it, so the renewal handler is never reached.
				assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
				return
			}

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			resp := decodeRenewResponse(t, rec)
			newCert := parseCertPEM(t, resp.CertificatePEM)

			assert.True(t, cert.HasAdminMarker(newCert))
			assert.Equal(t, tc.payloadSigning, cert.HasPayloadSigningMarker(newCert))
			assert.Equal(t, tc.rootScope, cert.HasRootScopeMarker(newCert))
		})
	}
}

// ---- [REQUIRED TEST] binds to exactly the presented certificate's account ----------

// TestRenewCredential_RequestNamingAccountIsRefused proves the request body cannot
// name, select, or otherwise widen which account is renewed into: any unrecognised
// top-level key (e.g. an attempt to smuggle an account selector) is refused outright
// at decode time (DisallowUnknownFields), and the account the renewal actually binds
// to is always exactly the presented certificate's own bound account.
func TestRenewCredential_RequestNamingAccountIsRefused(t *testing.T) {
	server := setupRenewalTestServer(t)
	fxA := issueRenewableCredential(t, server, "renew-named-a", "renew-named-owner-a", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)
	_ = issueRenewableCredential(t, server, "renew-named-b", "renew-named-owner-b", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrPEM := encodeTestCSR(t, newKey, "renew-test-device")

	// A request naming an account (however it might be spelled) is not a field this
	// type declares — DisallowUnknownFields refuses it rather than silently ignoring it.
	raw, err := json.Marshal(map[string]string{
		"csr_pem":    csrPEM,
		"account_id": "renew-named-owner-b",
	})
	require.NoError(t, err)

	presented := withNotAfter(fxA.oldCert, time.Now().UTC().Add(10*24*time.Hour))
	rec := renewCredentialRaw(t, server, presented, raw)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "INVALID_JSON", errCode(t, rec.Body.Bytes()))

	// A well-formed request (no account field at all) must still succeed and must
	// bind to exactly A's own account — never B's.
	rec2, _ := renewCredential(t, server, presented)
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
	resp := decodeRenewResponse(t, rec2)
	assert.Equal(t, fxA.accountID, resp.AccountID)
}

// TestRenewCredential_NoAccountBindingRefusedNotBootstrapFallback is the other half of
// the [REQUIRED TEST]: a presented certificate with no account binding at all — the
// bootstrap-fallback case in extractAdminPrincipal — is refused outright by the
// renewal handler rather than being allowed to "renew into" the fallback.
func TestRenewCredential_NoAccountBindingRefusedNotBootstrapFallback(t *testing.T) {
	server := setupRenewalTestServer(t)
	// An admin-marked certificate that authenticates via the bootstrap fallback: no
	// account in the store has ever been bound to this serial.
	unbound := makeSelfSignedAdminCert(t)
	unbound = withNotAfter(unbound, time.Now().UTC().Add(10*24*time.Hour))

	// Sanity: this certificate really does authenticate via the bootstrap fallback.
	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", unbound)
	principal := server.extractAdminPrincipal(req)
	require.NotNil(t, principal, "an admin-marked certificate with no binding must still authenticate via the bootstrap fallback")
	require.True(t, principal.ImplicitAdmin)

	rec, _ := renewCredential(t, server, unbound)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "NO_ACCOUNT_BINDING", errCode(t, rec.Body.Bytes()))
}

// ---- [REQUIRED TEST] old serial revoked+unbound; failure mid-sequence keeps a working credential --

func TestRenewCredential_OldSerialRevokedAndUnbound_ExactlyOneLiveCertificate(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-cleanup-tenant", "renew-cleanup-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))
	rec, _ := renewCredential(t, server, presented)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRenewResponse(t, rec)

	assert.True(t, server.certManager.IsRevoked(fx.oldSerial))
	assert.Nil(t, certBindingBySerial(t, server, fx.accountUser, fx.oldSerial), "the old binding must be removed")
	assert.NotNil(t, certBindingBySerial(t, server, fx.accountUser, resp.SerialNumber), "the new binding must exist")

	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	assert.Len(t, acct.CertBindings, 1, "exactly one live certificate must exist for this account")
}

// TestRenewCredential_BindFailureLeavesOldCredentialWorking is the failure-mid-sequence
// [REQUIRED TEST]: fill the account's certificate bindings to the cap so binding the
// newly-signed certificate fails. The host must still hold a working credential
// afterward — its old, still-valid certificate — never zero.
func TestRenewCredential_BindFailureLeavesOldCredentialWorking(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-bindfail-tenant", "renew-bindfail-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	// Fill remaining slots up to the cap (the fixture's own binding already occupies one).
	var fillerSerials []string
	for i := 0; i < maxCertBindingsPerAccount-1; i++ {
		serial := "filler-serial-renew-" + fx.accountUser + "-" + strconv.Itoa(i)
		fillerSerials = append(fillerSerials, serial)
		require.NoError(t, server.bindCertOnAccount(context.Background(), fx.accountUser, CertBinding{
			Serial:  serial,
			BoundAt: time.Now().UTC(),
		}, "test-setup"))
	}
	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	require.Len(t, acct.CertBindings, maxCertBindingsPerAccount)

	revokedBefore, err := server.certManager.ListRevoked()
	require.NoError(t, err)

	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))
	rec, _ := renewCredential(t, server, presented)
	assert.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())

	// The old certificate must still be valid and bound — the host has a working
	// credential, not none.
	assert.False(t, server.certManager.IsRevoked(fx.oldSerial), "a failed renewal must never revoke the old, still-working certificate")
	assert.NotNil(t, certBindingBySerial(t, server, fx.accountUser, fx.oldSerial))

	// The orphaned newly-signed certificate must have been revoked (never left live
	// with no binding).
	revokedAfter, err := server.certManager.ListRevoked()
	require.NoError(t, err)
	assert.Len(t, revokedAfter, len(revokedBefore)+1, "exactly the orphaned new certificate must have been revoked")

	// A subsequent renewal attempt with the still-valid old credential must still work
	// once room exists — proving the host was never locked out.
	require.NoError(t, server.removeCertBindingFromAccount(context.Background(), fx.accountUser, fillerSerials[0], "test-cleanup"))
	rec2, _ := renewCredential(t, server, presented)
	assert.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
}

// ---- [REQUIRED TEST] disabling the bound account blocks renewal and authentication --

func TestRenewCredential_DisablingAccountBlocksRenewalAndAuthentication(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-disable-tenant", "renew-disable-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))

	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	acct.Disabled = true
	require.NoError(t, server.persistAccount(context.Background(), acct, "test-setup"))

	rec, _ := renewCredential(t, server, presented)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String(),
		"a disabled account's certificate must not even authenticate, let alone renew")

	// The certificate cannot authenticate for anything else either.
	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", presented)
	principal := server.extractAdminPrincipal(req)
	assert.Nil(t, principal, "a certificate bound to a disabled account must never authenticate")
}

// ---- [REQUIRED TEST] fresh keypair required; reusing the old public key refused ----

func TestRenewCredential_ReusingOldPublicKeyIsRefused(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-reuse-tenant", "renew-reuse-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	// Build a CSR reusing fx.oldKey — the same key the presented certificate itself
	// carries the public half of.
	reusedCSR := encodeTestCSR(t, fx.oldKey, "renew-test-device")
	body, err := json.Marshal(RenewCredentialRequest{CSRPEM: reusedCSR})
	require.NoError(t, err)

	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))
	rec := renewCredentialRaw(t, server, presented, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "KEY_REUSE_REJECTED", errCode(t, rec.Body.Bytes()))

	assert.False(t, server.certManager.IsRevoked(fx.oldSerial))
	assert.NotNil(t, certBindingBySerial(t, server, fx.accountUser, fx.oldSerial))

	// A fresh keypair still works.
	rec2, _ := renewCredential(t, server, presented)
	assert.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
}

// ---- human-approval date survives renewal ------------------------------------------

func TestRenewCredential_HumanApprovedAtSurvivesRenewal(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-approved-at-tenant", "renew-approved-at-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	original := certBindingBySerial(t, server, fx.accountUser, fx.oldSerial)
	require.NotNil(t, original)
	require.NotNil(t, original.HumanApprovedAt, "the original binding must record when a human approved it")
	originalApprovedAt := *original.HumanApprovedAt

	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))
	rec, _ := renewCredential(t, server, presented)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRenewResponse(t, rec)

	renewed := certBindingBySerial(t, server, fx.accountUser, resp.SerialNumber)
	require.NotNil(t, renewed)
	require.NotNil(t, renewed.HumanApprovedAt)
	assert.True(t, originalApprovedAt.Equal(*renewed.HumanApprovedAt),
		"the human-approval date must survive renewal unchanged")
}

// ---- authentication must be the certificate itself, never API key or session ------

func TestRenewCredential_APIKeyCannotAuthenticate(t *testing.T) {
	server := setupRenewalTestServer(t)
	_ = issueRenewableCredential(t, server, "renew-apikey-tenant", "renew-apikey-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrPEM := encodeTestCSR(t, newKey, "renew-test-device")
	body, err := json.Marshal(RenewCredentialRequest{CSRPEM: csrPEM})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-renewal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "not-a-real-api-key")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusOK, rec.Code, rec.Body.String())
}

// ---- leadership gate ----------------------------------------------------------------

func TestRenewCredential_LeadershipGate(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-leadership-tenant", "renew-leadership-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)
	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))

	server.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}
	rec, _ := renewCredential(t, server, presented)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.NotNil(t, certBindingBySerial(t, server, fx.accountUser, fx.oldSerial), "a 503 from a non-leader must leave the old binding untouched")

	server.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: true}
	rec2, _ := renewCredential(t, server, presented)
	assert.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
}

// ---- audit --------------------------------------------------------------------------

func TestRenewCredential_AuditEvent(t *testing.T) {
	server := setupRenewalTestServer(t)
	fx := issueRenewableCredential(t, server, "renew-audit-tenant", "renew-audit-owner", ApproveCredentialRequestBody{GrantAdminMarker: true}, nil)
	presented := withNotAfter(fx.oldCert, time.Now().UTC().Add(10*24*time.Hour))

	rec, _ := renewCredential(t, server, presented)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeRenewResponse(t, rec)

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "renew-audit-tenant"})
	require.NoError(t, err)

	var renewedEntry *business.AuditEntry
	for _, e := range entries {
		if e.Action == "account.cert_binding.renewed" {
			renewedEntry = e
			break
		}
	}
	require.NotNil(t, renewedEntry, "account.cert_binding.renewed audit event must be recorded")
	assert.Equal(t, fx.oldSerial, renewedEntry.Details["old_serial"])
	assert.Equal(t, resp.SerialNumber, renewedEntry.Details["new_serial"])
}
