// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package operatorroster

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

// revTestControllerManifest mirrors features/controller/api.RevocationManifest
// field-for-field, declared independently of the production revocationManifest struct
// under test. It is the test's own statement of the wire shape the controller actually
// signs (handlers_revocation_manifest.go), so a field silently dropped from the
// production mirror is caught here instead of cancelling out on both sides — which is
// exactly how the AuthorizedWebAuthnCredentials/WebAuthnRelyingParty omission survived
// the original test suite, where every manifest was built and signed through the
// production struct itself.
type revTestControllerManifest struct {
	Kind                          string                                `json:"kind"`
	Version                       int64                                 `json:"version"`
	IssuedAt                      time.Time                             `json:"issued_at"`
	RevokedSerials                []string                              `json:"revoked_serials"`
	AuthorizedWebAuthnCredentials []revTestControllerWebAuthnCredential `json:"authorized_webauthn_credentials,omitempty"`
	WebAuthnRelyingParty          *revTestControllerRelyingParty        `json:"webauthn_relying_party,omitempty"`
}

// revTestControllerWebAuthnCredential mirrors
// features/controller/api.AuthorizedWebAuthnCredential.
type revTestControllerWebAuthnCredential struct {
	Kind         string   `json:"kind"`
	CredentialID []byte   `json:"credential_id"`
	PublicKey    []byte   `json:"public_key"`
	TenantID     string   `json:"tenant_id"`
	RootScope    bool     `json:"root_scope"`
	Grants       []string `json:"grants"`
}

// revTestControllerRelyingParty mirrors features/controller/api.WebAuthnRelyingParty.
type revTestControllerRelyingParty struct {
	ID      string   `json:"id"`
	Origins []string `json:"origins"`
}

// revTestSignControllerManifest signs manifest exactly as the controller's
// signRevocationManifest does — json.Marshal of the full payload struct — and wraps it
// in the envelope byte-for-byte as GET /api/v1/certificates/revocation-manifest serves
// it, marshalling the signed payload back out through the same full-field struct.
func revTestSignControllerManifest(t *testing.T, signingCert *cert.Certificate, manifest revTestControllerManifest) []byte {
	t.Helper()
	data, err := json.Marshal(manifest)
	require.NoError(t, err)

	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: signingCert.CertificatePEM,
		PrivateKeyPEM:  signingCert.PrivateKeyPEM,
	})
	require.NoError(t, err)
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	out, err := json.Marshal(struct {
		Manifest             revTestControllerManifest  `json:"manifest"`
		Signature            *signature.ConfigSignature `json:"signature"`
		SignerCertificatePEM string                     `json:"signer_certificate_pem"`
	}{
		Manifest:             manifest,
		Signature:            sig,
		SignerCertificatePEM: string(signingCert.CertificatePEM),
	})
	require.NoError(t, err)
	return out
}

// revTestSignManifest signs a revocation manifest with signingCert and wraps it in
// the signed envelope, returning the JSON bytes exactly as the controller's
// GET /api/v1/certificates/revocation-manifest serves them. It builds the payload
// through revTestControllerManifest — the controller's shape — never through the
// production struct under test.
func revTestSignManifest(t *testing.T, signingCert *cert.Certificate, version int64, revokedSerials []string) []byte {
	t.Helper()
	if revokedSerials == nil {
		// buildRevocationManifest always emits a non-nil slice, so the real wire bytes
		// carry "revoked_serials":[] rather than null even with nothing revoked.
		revokedSerials = []string{}
	}
	return revTestSignControllerManifest(t, signingCert, revTestControllerManifest{
		Kind:           revocationManifestKind,
		Version:        version,
		IssuedAt:       time.Now().UTC().Truncate(time.Second),
		RevokedSerials: revokedSerials,
	})
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

// TestRevocationVerifier_VerifyManifest_Strict_NilCARoots_Rejected pins the fail-closed
// behaviour a nil CA pool must have. x509.VerifyOptions documents a nil Roots as "the
// system roots or the platform verifier are used", so handing v.caRoots straight to
// Verify would turn a steward with no pinned bundle into one that accepts any manifest
// whose signer chains to any platform-trusted CA with a CodeSigning EKU — a strictly
// wider trust set than the pinned controller root, reached by configuring less. A
// steward can legitimately reach this state: client_transport.go leaves controllerCARoots
// nil whenever the controller CA PEM is unusable and the deployment is neither public
// beta nor require_signed_adhoc.
func TestRevocationVerifier_VerifyManifest_Strict_NilCARoots_Rejected(t *testing.T) {
	ca, _ := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	raw := revTestSignManifest(t, signingCert, 1, []string{"12345"})

	v := NewRevocationVerifier(nil)
	err := v.VerifyManifest(raw, stewardtypes.ModuleTrustModeStrict)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "strict mode requires pinned controller CA roots",
		"a nil pool must be refused outright, never passed to x509 where it means 'system roots'")
	assert.False(t, v.IsRevoked("12345"), "a manifest that was never verified must not be applied")
}

// TestRevocationVerifier_VerifyManifest_Strict_WebAuthnFieldsPresent_Accepted covers the
// manifest shape a controller with WebAuthn configured actually signs (Issue #3697):
// handleGetRevocationManifest populates AuthorizedWebAuthnCredentials and
// WebAuthnRelyingParty on the SAME manifest object before signRevocationManifest runs, so
// the signed bytes are json.Marshal of all six fields.
//
// VerifyManifest re-marshals the payload it unmarshalled to recompute the bytes to check
// the signature against. While revocationManifest declared only four of the six fields,
// that round trip dropped the two WebAuthn members and strict mode rejected every such
// manifest with "signature does not match data" — meaning a steward in
// module_trust.mode: strict could never accept a manifest from any controller that also
// had WebAuthn credentials or a relying party configured.
func TestRevocationVerifier_VerifyManifest_Strict_WebAuthnFieldsPresent_Accepted(t *testing.T) {
	ca, caPool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)

	raw := revTestSignControllerManifest(t, signingCert, revTestControllerManifest{
		Kind:           revocationManifestKind,
		Version:        3,
		IssuedAt:       time.Now().UTC().Truncate(time.Second),
		RevokedSerials: []string{"12345"},
		AuthorizedWebAuthnCredentials: []revTestControllerWebAuthnCredential{{
			Kind:         "webauthn-credential",
			CredentialID: []byte{0x01, 0x02, 0x03},
			PublicKey:    []byte{0x0a, 0x0b, 0x0c},
			TenantID:     "root/msp-a",
			RootScope:    false,
			Grants:       []string{"operator-payload:sign"},
		}},
		WebAuthnRelyingParty: &revTestControllerRelyingParty{
			ID:      "controller.example.com",
			Origins: []string{"https://controller.example.com"},
		},
	})

	v := NewRevocationVerifier(caPool)
	require.NoError(t, v.VerifyManifest(raw, stewardtypes.ModuleTrustModeStrict),
		"a manifest carrying the WebAuthn roster fields must verify: the steward re-marshals "+
			"what it unmarshalled, so every signed field must survive the round trip")
	assert.True(t, v.IsRevoked("12345"))
	assert.False(t, v.IsRevoked("99999"))
}

// TestRevocationVerifier_VerifyManifest_Strict_WebAuthnFieldsRoundTripByteIdentical asserts
// the round trip directly: the bytes the controller signed and the bytes VerifyManifest
// recomputes must be identical, not merely both acceptable. This is the invariant the
// field-for-field mirror exists to hold, checked independently of the signature so a
// future field added to the controller's RevocationManifest fails here with a readable
// diff rather than as an opaque signature mismatch.
func TestRevocationVerifier_VerifyManifest_Strict_WebAuthnFieldsRoundTripByteIdentical(t *testing.T) {
	controllerManifest := revTestControllerManifest{
		Kind:           revocationManifestKind,
		Version:        3,
		IssuedAt:       time.Now().UTC().Truncate(time.Second),
		RevokedSerials: []string{"12345"},
		AuthorizedWebAuthnCredentials: []revTestControllerWebAuthnCredential{{
			Kind:         "webauthn-credential",
			CredentialID: []byte{0x01, 0x02, 0x03},
			PublicKey:    []byte{0x0a, 0x0b, 0x0c},
			TenantID:     "root/msp-a",
			RootScope:    false,
			Grants:       []string{"operator-payload:sign"},
		}},
		WebAuthnRelyingParty: &revTestControllerRelyingParty{
			ID:      "controller.example.com",
			Origins: []string{"https://controller.example.com"},
		},
	}
	signedBytes, err := json.Marshal(controllerManifest)
	require.NoError(t, err)

	var mirrored revocationManifest
	require.NoError(t, json.Unmarshal(signedBytes, &mirrored))
	recomputed, err := json.Marshal(mirrored)
	require.NoError(t, err)

	assert.Equal(t, string(signedBytes), string(recomputed),
		"revocationManifest must mirror the controller's RevocationManifest field-for-field")
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

	// requestCount is incremented on the httptest handler goroutine and read on the
	// test goroutine, so it is atomic; fetches are observed over a channel so the
	// test synchronises on real progress instead of a wall-clock deadline.
	var requestCount atomic.Int64
	fetched := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
		select {
		case fetched <- struct{}{}:
		default: // never block the handler once the test has seen enough fetches
		}
	}))
	defer srv.Close()

	v := NewRevocationVerifier(caPool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		v.RunPeriodicRefresh(ctx, srv.Client(), srv.URL, stewardtypes.ModuleTrustModeStrict, 10*time.Millisecond, nil)
		close(done)
	}()

	// The startup fetch, then at least one more driven by the ticker.
	for i := 1; i <= 2; i++ {
		select {
		case <-fetched:
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for fetch %d of 2 (observed %d)", i, requestCount.Load())
		}
	}
	cancel()
	<-done

	assert.True(t, v.IsRevoked("555"), "the startup fetch must have applied the manifest")
	assert.GreaterOrEqual(t, requestCount.Load(), int64(2), "the periodic ticker must have fetched at least once more after startup")
}
