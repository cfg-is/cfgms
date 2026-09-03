// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3691: tests for the signed operator-certificate revocation manifest.
// Issue #3697: tests for the manifest's AuthorizedWebAuthnCredentials extension and
// SignerCertificatePEM field.
package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
)

// unscopedAdminManifestRequest builds a manifest GET authenticated as an unscoped
// mTLS admin: an admin-marked certificate with no bound account resolves to
// TenantID "" (the same principal shape TestHandleListCertificates_TenantScope_*
// uses for an unscoped admin). This is the only principal the endpoint serves —
// API keys always carry a tenant, since generateEphemeralKey rejects an empty
// tenant ID, so a scoped key can never reach the manifest.
func unscopedAdminManifestRequest(t *testing.T, certMgr *cert.Manager) *http.Request {
	t.Helper()
	adminCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(adminCert.CertificatePEM)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1/certificates/revocation-manifest", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
	return req
}

// serveManifest issues req through the real router (exercising the certificate:list
// permission gate and the unscoped-principal requirement) and decodes the envelope.
func serveManifest(t *testing.T, server *Server, req *http.Request) (*httptest.ResponseRecorder, SignedRevocationManifest) {
	t.Helper()
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	var resp struct {
		Data SignedRevocationManifest `json:"data"`
	}
	if rec.Code == http.StatusOK {
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	}
	return rec, resp.Data
}

// getRevocationManifest requests the manifest as an unscoped mTLS admin.
func getRevocationManifest(t *testing.T, server *Server, certMgr *cert.Manager) (*httptest.ResponseRecorder, SignedRevocationManifest) {
	t.Helper()
	return serveManifest(t, server, unscopedAdminManifestRequest(t, certMgr))
}

// TestHandleGetRevocationManifest_SignatureVerifies verifies the manifest's
// signature validates against the PurposeSigning certificate's public key
// (REQUIRED TEST, Issue #3691 AC).
func TestHandleGetRevocationManifest_SignatureVerifies(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)

	rec, body := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	require.NotNil(t, body.Signature)
	assert.Equal(t, RevocationManifestKind, body.Manifest.Kind)

	signingCert, err := certMgr.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(signingCert.CertificatePEM)
	require.NoError(t, err)

	verifier, err := signature.NewVerifierFromCertificate(x509Cert)
	require.NoError(t, err)

	data, err := json.Marshal(body.Manifest)
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(data, body.Signature),
		"manifest signature must verify against the PurposeSigning cert's public key")
}

// TestHandleGetRevocationManifest_RevokeIncreasesVersionAndSerials verifies that
// revoking a certificate via Manager.Revoke and re-requesting the manifest produces
// a higher version containing the newly revoked serial (REQUIRED TEST, Issue #3691 AC).
func TestHandleGetRevocationManifest_RevokeIncreasesVersionAndSerials(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)

	issued, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-manifest-revoke",
		Organization: "Test CFGMS",
		ClientID:     "steward-manifest-revoke",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	recBefore, before := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, recBefore.Code, "body: %s", recBefore.Body.String())
	assert.NotContains(t, before.Manifest.RevokedSerials, issued.SerialNumber)

	require.NoError(t, certMgr.Revoke(issued.SerialNumber))

	recAfter, after := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, recAfter.Code, "body: %s", recAfter.Body.String())

	assert.Greater(t, after.Manifest.Version, before.Manifest.Version,
		"version must strictly increase after a new revocation")
	assert.Contains(t, after.Manifest.RevokedSerials, issued.SerialNumber,
		"newly revoked serial must appear in the manifest")
}

// TestHandleGetRevocationManifest_SerialsSorted verifies RevokedSerials is
// deterministically sorted regardless of revocation order.
func TestHandleGetRevocationManifest_SerialsSorted(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)

	for i := 0; i < 3; i++ {
		issued, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
			CommonName:   "steward-sort-order",
			Organization: "Test CFGMS",
			ClientID:     "steward-sort-order",
			ValidityDays: 365,
		})
		require.NoError(t, err)
		require.NoError(t, certMgr.Revoke(issued.SerialNumber))
	}

	rec, body := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	sorted := make([]string, len(body.Manifest.RevokedSerials))
	copy(sorted, body.Manifest.RevokedSerials)
	assert.True(t, sortStringsIsSorted(sorted), "revoked serials must be sorted")
}

// TestHandleGetRevocationManifest_NilCertManager_Returns503 verifies the handler
// fails closed when no cert manager is configured. The admin certificate is minted
// by a standalone manager because the server under test has none.
func TestHandleGetRevocationManifest_NilCertManager_Returns503(t *testing.T) {
	server := setupTestServer(t) // no cert manager
	rec, _ := serveManifest(t, server, unscopedAdminManifestRequest(t, newTestCertManager(t)))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleGetRevocationManifest_NoSigningCert_Returns500 verifies the handler
// surfaces a clear server error rather than a panic when no PurposeSigning
// certificate has been provisioned yet.
func TestHandleGetRevocationManifest_NoSigningCert_Returns500(t *testing.T) {
	server, certMgr := setupCertTestServer(t) // no EnsureSigningCertificate call

	rec, _ := getRevocationManifest(t, server, certMgr)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestHandleGetRevocationManifest_RequiresPermission verifies a principal without
// certificate:list is rejected by the permission gate — this endpoint must not be
// reachable without it even though it requires no elevated assurance.
func TestHandleGetRevocationManifest_RequiresPermission(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)
	apiKey := NewTestKey(t, server, []string{"steward:list"}) // unrelated permission

	req := httptest.NewRequest("GET", "/api/v1/certificates/revocation-manifest", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec, _ := serveManifest(t, server, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errResp.Error.Code,
		"rejection must come from the permission gate, not the scope guard")
}

// TestHandleGetRevocationManifest_TenantScopedCallerDenied verifies a tenant-scoped
// caller holding certificate:list is denied the fleet-wide manifest. The manifest
// lists every revoked serial fleet-wide — including steward-cert serials written by
// handleRevokeCertificate — and cannot be tenant-filtered without producing a signed
// manifest that omits revocations, so scoped callers get 403 and no serials at all.
func TestHandleGetRevocationManifest_TenantScopedCallerDenied(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)

	// A revoked certificate belonging to a steward outside the caller's tenant.
	issued, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-other-tenant",
		Organization: "Test CFGMS",
		ClientID:     "steward-other-tenant",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NoError(t, certMgr.Revoke(issued.SerialNumber))

	scopedKey := NewEphemeralTestKey(t, server, []string{"certificate:list"}, "client-1", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/certificates/revocation-manifest", nil)
	req.Header.Set("X-API-Key", scopedKey)
	rec, _ := serveManifest(t, server, req)

	require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	responseBody := rec.Body.String()
	assert.NotContains(t, responseBody, issued.SerialNumber,
		"a tenant-scoped caller must not receive another tenant's revoked serial")
	assert.False(t, strings.Contains(responseBody, `"revoked_serials"`),
		"the denial response must not carry the manifest payload")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(strings.NewReader(responseBody)).Decode(&errResp))
	assert.Equal(t, "FORBIDDEN", errResp.Error.Code)
}

// TestHandleGetRevocationManifest_UnscopedCallerServedFleetWide is the positive
// counterpart: an unscoped administrator still receives the complete fleet-wide
// manifest, including serials owned by stewards in any tenant.
func TestHandleGetRevocationManifest_UnscopedCallerServedFleetWide(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)

	issued, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-any-tenant",
		Organization: "Test CFGMS",
		ClientID:     "steward-any-tenant",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NoError(t, certMgr.Revoke(issued.SerialNumber))

	rec, body := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, body.Manifest.RevokedSerials, issued.SerialNumber,
		"an unscoped admin must receive the complete fleet-wide manifest")
}

// setupManifestServerWithWebAuthn returns a setupCertTestServer server (real certMgr,
// for manifest signing) additionally configured with WebAuthn and one pre-created
// account holding operator-payload signing authority, so a test can inject a credential
// and confirm it surfaces in the manifest.
func setupManifestServerWithWebAuthn(t *testing.T) (*Server, *cert.Manager, string) {
	t.Helper()
	server, certMgr := setupManifestServerWithoutAccount(t)

	const username = "manifest-webauthn-user"
	createManifestAccount(t, server, AccountRequest{
		Username:    username,
		TenantID:    "root/msp-a",
		Permissions: []string{OperatorPayloadSignGrant},
	})
	return server, certMgr, username
}

// setupManifestServerWithoutAccount is setupManifestServerWithWebAuthn without any
// account, for tests that create their own with a specific authority shape.
func setupManifestServerWithoutAccount(t *testing.T) (*Server, *cert.Manager) {
	t.Helper()
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)

	wa, err := NewWebAuthnFromConfig(tvRPID, tvRPID, []string{tvOrigin})
	require.NoError(t, err)
	server.SetWebAuthn(wa)

	return server, certMgr
}

// createManifestAccount creates req's account through the real handler and fails the
// test if creation did not succeed.
func createManifestAccount(t *testing.T, server *Server, req AccountRequest) {
	t.Helper()
	rec := postAccount(t, server, testAdminPrincipal(), req)
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())
}

// TestHandleGetRevocationManifest_AuthorizedWebAuthnCredentials_IncludesRegisteredCredential
// verifies Issue #3697's manifest extension: a WebAuthn credential registered to an
// account that holds operator-payload signing authority appears in the fleet-wide
// manifest as a Kind-discriminated entry carrying its exact credential ID, COSE public
// key, owning tenant and grant, and the manifest's signature still verifies with the
// extended shape included.
func TestHandleGetRevocationManifest_AuthorizedWebAuthnCredentials_IncludesRegisteredCredential(t *testing.T) {
	server, certMgr, username := setupManifestServerWithWebAuthn(t)
	credID := []byte("manifest-cred-1")
	_, pubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, credID, pubKey, 0)

	rec, body := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	require.Len(t, body.Manifest.AuthorizedWebAuthnCredentials, 1)
	entry := body.Manifest.AuthorizedWebAuthnCredentials[0]
	assert.Equal(t, AuthorizedWebAuthnCredentialKind, entry.Kind)
	assert.Equal(t, credID, entry.CredentialID)
	assert.Equal(t, pubKey, entry.PublicKey)
	assert.Equal(t, "root/msp-a", entry.TenantID,
		"the entry must name the tenant the credential's account belongs to")
	assert.False(t, entry.RootScope, "a tenant-scoped account's entry must not claim root scope")
	assert.Contains(t, entry.Grants, OperatorPayloadSignGrant,
		"the entry must carry the grant that authorizes it, not merely exist")

	// The relying-party binding a steward needs for the rpIdHash/origin checks travels
	// inside the signed manifest, since a steward has no other trustworthy source.
	require.NotNil(t, body.Manifest.WebAuthnRelyingParty)
	assert.Equal(t, tvRPID, body.Manifest.WebAuthnRelyingParty.ID)
	assert.Equal(t, []string{tvOrigin}, body.Manifest.WebAuthnRelyingParty.Origins)

	// IssuedAt is the freshness anchor a consumer bounds the manifest's age against.
	assert.WithinDuration(t, time.Now(), body.Manifest.IssuedAt, time.Minute,
		"the manifest must state when it was issued")

	// The signature must still verify with AuthorizedWebAuthnCredentials populated —
	// proves the extended shape didn't break the existing sign/verify round trip.
	signingCert, err := certMgr.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(signingCert.CertificatePEM)
	require.NoError(t, err)
	verifier, err := signature.NewVerifierFromCertificate(x509Cert)
	require.NoError(t, err)
	data, err := json.Marshal(body.Manifest)
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(data, body.Signature),
		"manifest signature must verify with AuthorizedWebAuthnCredentials populated")
}

// TestHandleGetRevocationManifest_SignerCertificatePEM_ChainsToCA verifies Issue #3697's
// SignerCertificatePEM field: it is the exact PurposeSigning certificate the signature
// was produced with, and it chain-verifies against the CA — the property a caller with
// no other side channel (e.g. a steward) relies on to trust it.
func TestHandleGetRevocationManifest_SignerCertificatePEM_ChainsToCA(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)

	rec, body := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	require.NotEmpty(t, body.SignerCertificatePEM)

	signingCert, err := certMgr.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	assert.Equal(t, string(signingCert.CertificatePEM), body.SignerCertificatePEM,
		"SignerCertificatePEM must be the exact cert the signature was produced with")

	parsedSigner, err := cert.ParseCertificateFromPEM([]byte(body.SignerCertificatePEM))
	require.NoError(t, err)

	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	_, err = parsedSigner.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	require.NoError(t, err, "SignerCertificatePEM must chain-verify to the CA with CodeSigning EKU")
}

// TestHandleGetRevocationManifest_AuthorizedWebAuthnCredentials_ZeroPrivilegeAccountExcluded
// verifies the roster is an authority list, not a credential census: a passkey belonging
// to an account that holds no permission at all never appears, so it can never authorize
// inline execution on a steward.
func TestHandleGetRevocationManifest_AuthorizedWebAuthnCredentials_ZeroPrivilegeAccountExcluded(t *testing.T) {
	server, certMgr := setupManifestServerWithoutAccount(t)
	const username = "manifest-zero-privilege"
	createManifestAccount(t, server, AccountRequest{Username: username, TenantID: "root/msp-a"})

	_, pubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, []byte("manifest-cred-zero-priv"), pubKey, 0)

	rec, body := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Empty(t, body.Manifest.AuthorizedWebAuthnCredentials,
		"a passkey on a zero-privilege account must not authorize operator payloads")
}

// TestHandleGetRevocationManifest_AuthorizedWebAuthnCredentials_DisabledAccountExcluded
// verifies a disabled account's credentials are excluded. Disabling is a login gate that
// deliberately leaves credentials in place (Issue #3126), so they remain enumerable and
// must be filtered out here — otherwise disabling a compromised operator would not stop
// their passkey authorizing execution.
func TestHandleGetRevocationManifest_AuthorizedWebAuthnCredentials_DisabledAccountExcluded(t *testing.T) {
	server, certMgr := setupManifestServerWithoutAccount(t)
	const username = "manifest-disabled-user"
	createManifestAccount(t, server, AccountRequest{
		Username:    username,
		TenantID:    "root/msp-a",
		Permissions: []string{OperatorPayloadSignGrant},
	})
	_, pubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, []byte("manifest-cred-disabled"), pubKey, 0)

	// Present while enabled...
	rec, body := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	require.Len(t, body.Manifest.AuthorizedWebAuthnCredentials, 1)

	disabled := true
	updateRec := putAccount(t, server, testAdminPrincipal(), username,
		AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, updateRec.Code, "disable account: %s", updateRec.Body.String())

	// ...and gone once disabled.
	rec, body = getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Empty(t, body.Manifest.AuthorizedWebAuthnCredentials,
		"a disabled account's passkey must not authorize operator payloads")
}

// TestHandleGetRevocationManifest_AuthorizedWebAuthnCredentials_RootScopeAccountMarked
// verifies a root-scope (unscoped platform administrator) account's entry is marked as
// such and carries no tenant — the only shape a steward accepts fleet-wide.
func TestHandleGetRevocationManifest_AuthorizedWebAuthnCredentials_RootScopeAccountMarked(t *testing.T) {
	server, certMgr := setupManifestServerWithoutAccount(t)
	const username = "manifest-root-scope-user"
	createManifestAccount(t, server, AccountRequest{Username: username, RootScope: true})

	_, pubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, []byte("manifest-cred-root"), pubKey, 0)

	rec, body := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	require.Len(t, body.Manifest.AuthorizedWebAuthnCredentials, 1)
	entry := body.Manifest.AuthorizedWebAuthnCredentials[0]
	assert.True(t, entry.RootScope, "a root-scope administrator's entry must be marked root-scope")
	assert.Empty(t, entry.TenantID)
	assert.Contains(t, entry.Grants, OperatorPayloadSignGrant,
		"a root-scope administrator holds every permission, including this one")
}

// TestHandleGetRevocationManifest_NoWebAuthnCredentials_EmptyRoster verifies the
// no-credentials case is a valid, signable empty roster rather than an error.
func TestHandleGetRevocationManifest_NoWebAuthnCredentials_EmptyRoster(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)

	rec, body := getRevocationManifest(t, server, certMgr)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Empty(t, body.Manifest.AuthorizedWebAuthnCredentials)
}

func sortStringsIsSorted(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}
