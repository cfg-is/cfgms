// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3691: tests for the signed operator-certificate revocation manifest.
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

func sortStringsIsSorted(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}
