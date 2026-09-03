// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package operatorroster

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/cert"
)

// revTestCA creates a real, self-signed CA for tests — no mocks.
func revTestCA(t *testing.T) (*cert.CA, *x509.CertPool) {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{
		Organization: "Test Controller CA",
		Country:      "US",
		ValidityDays: 365,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)
	return ca, pool
}

// revTestSigningCert issues a real CodeSigning certificate from ca, mirroring the
// controller's own PurposeSigning certificate (pkg/cert.PurposeSigning).
func revTestSigningCert(t *testing.T, ca *cert.CA) *cert.Certificate {
	t.Helper()
	c, err := ca.GenerateSigningCertificate(&cert.SigningCertConfig{
		CommonName:   "test-config-signer",
		Organization: "Test CFGMS",
		ValidityDays: 365,
		KeySize:      2048,
	})
	require.NoError(t, err)
	return c
}

// revTestSignManifest signs a revocationManifest with signingCert and wraps it in
// the signedRevocationManifest envelope, returning the JSON bytes exactly as the
// controller's GET /api/v1/certificates/revocation-manifest serves them.
func revTestSignManifest(t *testing.T, signingCert *cert.Certificate, version int64, revokedSerials []string) []byte {
	t.Helper()
	manifest := revocationManifest{
		Kind:           revocationManifestKind,
		Version:        version,
		IssuedAt:       time.Now().UTC().Truncate(time.Second),
		RevokedSerials: revokedSerials,
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)

	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: signingCert.CertificatePEM,
		PrivateKeyPEM:  signingCert.PrivateKeyPEM,
	})
	require.NoError(t, err)
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	out, err := json.Marshal(signedRevocationManifest{
		Manifest:             manifest,
		Signature:            sig,
		SignerCertificatePEM: string(signingCert.CertificatePEM),
	})
	require.NoError(t, err)
	return out
}

func TestRevocationVerifier_VerifyManifest_Strict_Accepted(t *testing.T) {
	ca, caPool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	raw := revTestSignManifest(t, signingCert, 1, []string{"12345"})

	v := NewRevocationVerifier(caPool)
	require.NoError(t, v.VerifyManifest(raw, stewardtypes.ModuleTrustModeStrict))
	assert.True(t, v.IsRevoked("12345"))
	assert.False(t, v.IsRevoked("99999"))
}

// TestRevocationVerifier_VerifyManifest_Strict_UntrustedSigner_Rejected is the
// [REQUIRED TEST] for Issue #3699: module_trust.mode: strict — a manifest signed by
// a key not chaining to the pinned root CA is rejected even if the controller
// serving it claims validity. Here "the controller serving it" is simulated by the
// manifest being otherwise perfectly well-formed and internally self-consistent
// (a real signature verifying against the real cert embedded in the payload) — the
// only thing wrong is that the signing certificate itself does not chain to this
// steward's pinned root, exactly the case an attacker controlling the transport (or
// a compromised controller) would present.
func TestRevocationVerifier_VerifyManifest_Strict_UntrustedSigner_Rejected(t *testing.T) {
	_, pinnedCAPool := revTestCA(t) // this steward's real pinned root
	foreignCA, _ := revTestCA(t)    // an unrelated CA the attacker/compromised controller controls
	foreignSigningCert := revTestSigningCert(t, foreignCA)
	raw := revTestSignManifest(t, foreignSigningCert, 1, []string{"12345"})

	v := NewRevocationVerifier(pinnedCAPool)
	err := v.VerifyManifest(raw, stewardtypes.ModuleTrustModeStrict)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain verification")
	assert.False(t, v.IsRevoked("12345"), "an unverifiable manifest must never be applied")
}

func TestRevocationVerifier_VerifyManifest_Strict_TamperedSignature_Rejected(t *testing.T) {
	ca, caPool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	raw := revTestSignManifest(t, signingCert, 1, []string{"12345"})

	var sm signedRevocationManifest
	require.NoError(t, json.Unmarshal(raw, &sm))
	sm.Manifest.RevokedSerials = append(sm.Manifest.RevokedSerials, "99999") // tamper after signing
	tampered, err := json.Marshal(sm)
	require.NoError(t, err)

	v := NewRevocationVerifier(caPool)
	err = v.VerifyManifest(tampered, stewardtypes.ModuleTrustModeStrict)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestRevocationVerifier_VerifyManifest_Strict_WrongKind_Rejected(t *testing.T) {
	ca, caPool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)

	manifest := revocationManifest{Kind: "some-other-kind", Version: 1, IssuedAt: time.Now().UTC()}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: signingCert.CertificatePEM, PrivateKeyPEM: signingCert.PrivateKeyPEM,
	})
	require.NoError(t, err)
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	raw, err := json.Marshal(signedRevocationManifest{
		Manifest: manifest, Signature: sig, SignerCertificatePEM: string(signingCert.CertificatePEM),
	})
	require.NoError(t, err)

	v := NewRevocationVerifier(caPool)
	err = v.VerifyManifest(raw, stewardtypes.ModuleTrustModeStrict)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected manifest kind")
}

func TestRevocationVerifier_VerifyManifest_AntiRollback_Rejected(t *testing.T) {
	ca, caPool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	v := NewRevocationVerifier(caPool)

	newer := revTestSignManifest(t, signingCert, 2, []string{"111", "222"})
	require.NoError(t, v.VerifyManifest(newer, stewardtypes.ModuleTrustModeStrict))
	assert.True(t, v.IsRevoked("222"))

	older := revTestSignManifest(t, signingCert, 1, []string{"111"})
	err := v.VerifyManifest(older, stewardtypes.ModuleTrustModeStrict)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "anti-rollback")
	// The older manifest must not have been applied: "222" is still revoked.
	assert.True(t, v.IsRevoked("222"))
}

func TestRevocationVerifier_VerifyManifest_ControllerMode_SkipsChainVerification(t *testing.T) {
	_, pinnedCAPool := revTestCA(t)
	foreignCA, _ := revTestCA(t)
	foreignSigningCert := revTestSigningCert(t, foreignCA)
	raw := revTestSignManifest(t, foreignSigningCert, 1, []string{"12345"})

	v := NewRevocationVerifier(pinnedCAPool)
	require.NoError(t, v.VerifyManifest(raw, stewardtypes.ModuleTrustModeController),
		"controller mode trusts the controller's own judgment, matching StewardTrustEnforcer's controller mode for module bundles")
	assert.True(t, v.IsRevoked("12345"))
}

func TestRevocationVerifier_VerifyManifest_BypassMode_NoOp(t *testing.T) {
	ca, caPool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	raw := revTestSignManifest(t, signingCert, 1, []string{"12345"})

	v := NewRevocationVerifier(caPool)
	require.NoError(t, v.VerifyManifest(raw, stewardtypes.ModuleTrustModeBypass))
	assert.False(t, v.IsRevoked("12345"), "bypass mode must not apply the manifest at all")
}

func TestRevocationVerifier_VerifyManifest_UnknownMode_Rejected(t *testing.T) {
	v := NewRevocationVerifier(x509.NewCertPool())
	err := v.VerifyManifest([]byte(`{}`), "not-a-real-mode")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown module trust mode")
}

func TestRevocationVerifier_IsRevoked_NeverVerified_ReturnsFalse(t *testing.T) {
	v := NewRevocationVerifier(x509.NewCertPool())
	assert.False(t, v.IsRevoked("anything"))
}

// TestRevocationVerifier_FetchAndVerify_EndToEnd is the [REQUIRED TEST] for Issue
// #3699: revoking a certificate, re-fetching the manifest, and observing that the
// certificate's serial is now rejected — end to end through the real HTTP fetch
// path (a real httptest.Server standing in for the controller's
// GET /api/v1/certificates/revocation-manifest, real request/response bytes over
// the wire), not a hand-built manifest passed directly to VerifyManifest. The
// certificate-revoke flow itself belongs to the controller (features/controller/api,
// out of this story's scope per its Out of Scope note); this test proves the
// steward side of "revoke, re-fetch, reject" — that a live serial can transition
// from not-revoked to revoked strictly by re-fetching and re-verifying.
func TestRevocationVerifier_FetchAndVerify_EndToEnd(t *testing.T) {
	ca, caPool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)

	const operatorCertSerial = "424242"
	var currentManifest []byte
	currentManifest = revTestSignManifest(t, signingCert, 1, nil) // not yet revoked

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(currentManifest)
	}))
	defer srv.Close()

	v := NewRevocationVerifier(caPool)
	require.NoError(t, v.FetchAndVerify(context.Background(), srv.Client(), srv.URL, stewardtypes.ModuleTrustModeStrict))
	assert.False(t, v.IsRevoked(operatorCertSerial), "the certificate is not yet revoked")

	// Simulate the controller's certificate:revoke flow having run: the next
	// manifest served now lists the certificate's serial, at a higher version.
	currentManifest = revTestSignManifest(t, signingCert, 2, []string{operatorCertSerial})

	require.NoError(t, v.FetchAndVerify(context.Background(), srv.Client(), srv.URL, stewardtypes.ModuleTrustModeStrict))
	assert.True(t, v.IsRevoked(operatorCertSerial),
		"re-fetching after revocation must surface the now-revoked serial")
}

func TestRevocationVerifier_FetchAndVerify_NonOKStatus_Rejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	v := NewRevocationVerifier(x509.NewCertPool())
	err := v.FetchAndVerify(context.Background(), srv.Client(), srv.URL, stewardtypes.ModuleTrustModeStrict)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status")
}

func TestRevocationVerifier_RunPeriodicRefresh_FetchesOnStartupAndOnInterval(t *testing.T) {
	ca, caPool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	raw := revTestSignManifest(t, signingCert, 1, []string{"555"})

	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	v := NewRevocationVerifier(caPool)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		v.RunPeriodicRefresh(ctx, srv.Client(), srv.URL, stewardtypes.ModuleTrustModeStrict, 50*time.Millisecond, nil)
		close(done)
	}()
	<-done

	assert.True(t, v.IsRevoked("555"), "the startup fetch must have applied the manifest")
	assert.GreaterOrEqual(t, requestCount, 2, "the periodic ticker must have fetched at least once more after startup")
}
