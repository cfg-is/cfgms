// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3697: unit tests for webauthnOperatorCredentialVerifier in isolation — direct
// calls to Verify()/resolveCredential(), as opposed to execute_script_test.go's coverage
// of the full dispatch path (h.HandleCommand). Real cryptographic material throughout —
// no mocks, matching the [REQUIRED TEST] end-to-end tests' own discipline.
package commands

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

const (
	// sigTestRPID / sigTestAssertionOrigin are the relying-party binding the signed
	// test manifests carry and the test assertions are produced under — the same pair
	// a real controller's webauthn.Config holds.
	sigTestRPID              = "controller.test"
	sigTestAssertionOrigin   = "https://controller.test"
	sigTestStewardTenant     = "root/msp-a/client-1"
	sigTestFlagsUserPresent  = 0x01
	sigTestFlagsUserVerified = 0x04
)

// sigTestAuthorizedEntry builds a roster entry for a root-scope (platform
// administrator) account holding operator-payload signing authority — the shape the
// controller's buildAuthorizedWebAuthnCredentials emits for such an account.
func sigTestAuthorizedEntry(credID, pubKey []byte) authorizedWebAuthnCredential {
	return authorizedWebAuthnCredential{
		Kind:         authorizedWebAuthnCredentialKind,
		CredentialID: credID,
		PublicKey:    pubKey,
		RootScope:    true,
		Grants:       []string{operatorPayloadSignGrant},
	}
}

// sigTestAssertionOpts parameterizes sigTestWebAuthnProofOpts so a negative test can
// move exactly one property away from a valid assertion. The zero value produces the
// valid assertion every positive test uses.
type sigTestAssertionOpts struct {
	flags             byte   // 0 → UP|UV set
	rpID              string // "" → sigTestRPID
	origin            string // "" → sigTestAssertionOrigin
	ceremonyType      string // "" → "webauthn.get"
	challengeOverride string // "" → the domain-separated envelope challenge
}

// sigTestWebAuthnProof builds a real ECDSA P-256 assertion over
// authenticatorData||sha256(clientDataJSON) whose clientDataJSON.challenge equals
// operatorpayload.ChallengeHash(envelope) — the same bytes and algorithm production
// verification uses — and returns the envelope alongside the marshaled
// webauthnAssertionProof JSON bytes. Shared by this file's unit tests and
// execute_script_test.go's sigTestWebAuthnAssertionParams (dispatch-path tests).
func sigTestWebAuthnProof(t *testing.T, priv *ecdsa.PrivateKey, credID, manifestJSON, content []byte, shell string, targets []string, nonce string, expiresAt time.Time) (operatorpayload.Envelope, []byte) {
	t.Helper()
	return sigTestWebAuthnProofOpts(t, priv, credID, manifestJSON, content, shell, targets, nonce, expiresAt,
		sigTestAssertionOpts{})
}

// sigTestWebAuthnProofOpts is sigTestWebAuthnProof with one or more assertion
// properties overridden (flags, RP ID, origin, ceremony type, challenge).
func sigTestWebAuthnProofOpts(t *testing.T, priv *ecdsa.PrivateKey, credID, manifestJSON, content []byte, shell string, targets []string, nonce string, expiresAt time.Time, opts sigTestAssertionOpts) (operatorpayload.Envelope, []byte) {
	t.Helper()
	env := operatorpayload.Envelope{
		Content:   content,
		Shell:     shell,
		Targets:   targets,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}
	challengeHash, err := operatorpayload.ChallengeHash(env)
	require.NoError(t, err)
	challengeB64 := base64.RawURLEncoding.EncodeToString(challengeHash[:])
	if opts.challengeOverride != "" {
		challengeB64 = opts.challengeOverride
	}

	flags := opts.flags
	if flags == 0 {
		flags = sigTestFlagsUserPresent | sigTestFlagsUserVerified
	}
	rpID := opts.rpID
	if rpID == "" {
		rpID = sigTestRPID
	}
	origin := opts.origin
	if origin == "" {
		origin = sigTestAssertionOrigin
	}
	ceremonyType := opts.ceremonyType
	if ceremonyType == "" {
		ceremonyType = "webauthn.get"
	}

	// authenticatorData: 32-byte rpIDHash + 1 flags byte + 4-byte sign count.
	authData := make([]byte, 37)
	rpIDHash := sha256.Sum256([]byte(rpID))
	copy(authData[:32], rpIDHash[:])
	authData[32] = flags

	clientData := struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}{Type: ceremonyType, Challenge: challengeB64, Origin: origin}
	clientDataJSON, err := json.Marshal(clientData)
	require.NoError(t, err)

	clientDataHash := sha256.Sum256(clientDataJSON)
	sigData := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(sigData)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	require.NoError(t, err)

	proof, err := json.Marshal(webauthnAssertionProof{
		AuthenticatorData:  authData,
		ClientDataJSON:     clientDataJSON,
		Signature:          sigBytes,
		CredentialID:       credID,
		SignedManifestJSON: string(manifestJSON),
	})
	require.NoError(t, err)
	return env, proof
}

// newSigTestWebAuthnVerifier builds the verifier under test with a fresh (per-test)
// freshness floor, so one test's accepted manifest never sets a floor another test's
// manifest has to clear.
func newSigTestWebAuthnVerifier(caPool *x509.CertPool) *webauthnOperatorCredentialVerifier {
	return &webauthnOperatorCredentialVerifier{
		caRoots:       caPool,
		stewardTenant: sigTestStewardTenant,
		freshness:     &manifestFreshnessFloor{},
	}
}

// TestWebAuthnOperatorCredentialVerifier_Verify_Success is the positive baseline every
// negative test below mutates one field away from.
func TestWebAuthnOperatorCredentialVerifier_Verify_Success(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-success")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	v := newSigTestWebAuthnVerifier(caPool)
	assert.NoError(t, v.Verify(env, proof))
}

// TestWebAuthnOperatorCredentialVerifier_Verify_ChallengeMismatch_Rejected verifies a
// clientDataJSON whose challenge does not equal sha256(CanonicalBytes(envelope)) —
// e.g. an assertion obtained for a different envelope — is rejected.
func TestWebAuthnOperatorCredentialVerifier_Verify_ChallengeMismatch_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-challenge-mismatch")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	// Verify against a DIFFERENT envelope than the one the assertion was built for —
	// the recomputed challenge will not match clientDataJSON.challenge.
	tampered := env
	tampered.Content = []byte("echo something-else")

	v := newSigTestWebAuthnVerifier(caPool)
	err := v.Verify(tampered, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "challenge")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_TamperedSignature_Rejected verifies a
// bit-flipped signature is rejected.
func TestWebAuthnOperatorCredentialVerifier_Verify_TamperedSignature_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-tampered-sig")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	var p webauthnAssertionProof
	require.NoError(t, json.Unmarshal(proof, &p))
	tamperedSig := append([]byte{}, p.Signature...)
	tamperedSig[len(tamperedSig)-1] ^= 0xFF
	p.Signature = tamperedSig
	tamperedProof, err := json.Marshal(p)
	require.NoError(t, err)

	v := newSigTestWebAuthnVerifier(caPool)
	require.Error(t, v.Verify(env, tamperedProof))
}

// TestWebAuthnOperatorCredentialVerifier_Verify_UnregisteredCredential_Rejected verifies
// a validly-signed assertion is rejected when its credential ID is absent from the
// CA-signed manifest.
func TestWebAuthnOperatorCredentialVerifier_Verify_UnregisteredCredential_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, _ := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-unregistered")
	manifestJSON := sigTestSignManifest(t, signingCert, nil) // empty roster

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	v := newSigTestWebAuthnVerifier(caPool)
	err := v.Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not independently verifiable")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_ManifestSignatureInvalid_Rejected
// verifies a manifest whose claimed content doesn't match what was actually signed
// (e.g. an attacker appended an extra authorized credential after signing) is rejected.
func TestWebAuthnOperatorCredentialVerifier_Verify_ManifestSignatureInvalid_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-manifest-tamper")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	var wrapped signedRevocationManifest
	require.NoError(t, json.Unmarshal(manifestJSON, &wrapped))
	// Append an entry after signing — the manifest bytes no longer match what was signed.
	wrapped.Manifest.AuthorizedWebAuthnCredentials = append(wrapped.Manifest.AuthorizedWebAuthnCredentials,
		authorizedWebAuthnCredential{Kind: authorizedWebAuthnCredentialKind, CredentialID: []byte("injected"), PublicKey: pubKey})
	tamperedManifest, err := json.Marshal(wrapped)
	require.NoError(t, err)

	env, proof := sigTestWebAuthnProof(t, priv, credID, tamperedManifest, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	v := newSigTestWebAuthnVerifier(caPool)
	err = v.Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest signature verification failed")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_ManifestWrongKind_Rejected verifies a
// manifest whose Kind is not the revocation-manifest kind is rejected — type-confusion
// protection against a payload signed by the same PurposeSigning cert for a different
// purpose being replayed here.
func TestWebAuthnOperatorCredentialVerifier_Verify_ManifestWrongKind_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-wrong-kind")

	manifest := revocationManifestPayload{
		Kind:                          "some-other-signed-payload",
		Version:                       1,
		RevokedSerials:                []string{},
		AuthorizedWebAuthnCredentials: []authorizedWebAuthnCredential{{Kind: authorizedWebAuthnCredentialKind, CredentialID: credID, PublicKey: pubKey}},
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
	manifestJSON, err := json.Marshal(signedRevocationManifest{
		Manifest: manifest, Signature: sig, SignerCertificatePEM: string(signingCert.CertificatePEM),
	})
	require.NoError(t, err)

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	v := newSigTestWebAuthnVerifier(caPool)
	err = v.Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected manifest kind")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_SignerNotChainedToCA_Rejected verifies a
// manifest whose embedded signer certificate does not chain to the steward's configured
// CA roots is rejected — a different (attacker-controlled) CA's signing cert.
func TestWebAuthnOperatorCredentialVerifier_Verify_SignerNotChainedToCA_Rejected(t *testing.T) {
	_, caPool := sigTestCA(t) // the steward's real, trusted CA
	otherCA, _ := sigTestCA(t)
	untrustedSigningCert := sigTestSigningCert(t, otherCA)

	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-untrusted-signer")
	manifestJSON := sigTestSignManifest(t, untrustedSigningCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	v := newSigTestWebAuthnVerifier(caPool)
	err := v.Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain verification")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_SignerWrongEKU_Rejected verifies a
// manifest signed by a certificate carrying ClientAuth (an ordinary operator/admin
// certificate) rather than CodeSigning is rejected — the PurposeSigning cert shape is
// required, not merely "any cert this CA issued".
func TestWebAuthnOperatorCredentialVerifier_Verify_SignerWrongEKU_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	// A client-auth cert (sigTestOperatorCert), not a CodeSigning signing cert.
	clientCert := sigTestOperatorCert(t, ca, nil)

	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-wrong-eku")
	manifest := revocationManifestPayload{
		Kind:                          revocationManifestKind,
		Version:                       1,
		RevokedSerials:                []string{},
		AuthorizedWebAuthnCredentials: []authorizedWebAuthnCredential{{Kind: authorizedWebAuthnCredentialKind, CredentialID: credID, PublicKey: pubKey}},
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: clientCert.CertificatePEM,
		PrivateKeyPEM:  clientCert.PrivateKeyPEM,
	})
	require.NoError(t, err)
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	manifestJSON, err := json.Marshal(signedRevocationManifest{
		Manifest: manifest, Signature: sig, SignerCertificatePEM: string(clientCert.CertificatePEM),
	})
	require.NoError(t, err)

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	v := newSigTestWebAuthnVerifier(caPool)
	err = v.Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain verification")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_IncompleteProof_Rejected verifies a
// proof missing a required field is rejected before any cryptographic work.
func TestWebAuthnOperatorCredentialVerifier_Verify_IncompleteProof_Rejected(t *testing.T) {
	_, caPool := sigTestCA(t)
	env := operatorpayload.Envelope{
		Content: []byte("echo hi"), Shell: "bash", Targets: []string{"steward-test"},
		Nonce: "n", ExpiresAt: time.Now().Add(time.Minute),
	}
	proof, err := json.Marshal(webauthnAssertionProof{CredentialID: []byte("x")}) // everything else missing
	require.NoError(t, err)

	v := newSigTestWebAuthnVerifier(caPool)
	err = v.Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_InvalidProofJSON_Rejected verifies
// malformed proof bytes are rejected cleanly rather than panicking.
func TestWebAuthnOperatorCredentialVerifier_Verify_InvalidProofJSON_Rejected(t *testing.T) {
	_, caPool := sigTestCA(t)
	env := operatorpayload.Envelope{
		Content: []byte("echo hi"), Shell: "bash", Targets: []string{"steward-test"},
		Nonce: "n", ExpiresAt: time.Now().Add(time.Minute),
	}
	v := newSigTestWebAuthnVerifier(caPool)
	err := v.Verify(env, []byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid webauthn assertion proof")
}

// ---------------------------------------------------------------------------
// W3C WebAuthn §7.2 assertion checks — the steward is the independent verifier,
// so it applies at least the verification the controller's own ceremony does.
// ---------------------------------------------------------------------------

// sigTestVerifyWithAssertionOpts is the shared body of the §7.2 negative tests: a valid
// manifest and credential, with exactly one assertion property moved away from valid.
func sigTestVerifyWithAssertionOpts(t *testing.T, credIDText string, opts sigTestAssertionOpts) error {
	t.Helper()
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte(credIDText)
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	env, proof := sigTestWebAuthnProofOpts(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute), opts)

	return newSigTestWebAuthnVerifier(caPool).Verify(env, proof)
}

// TestWebAuthnOperatorCredentialVerifier_Verify_UserPresentFlagMissing_Rejected verifies
// an assertion produced without user interaction (UP clear) is rejected — the
// hardware-presence property this path exists to establish.
func TestWebAuthnOperatorCredentialVerifier_Verify_UserPresentFlagMissing_Rejected(t *testing.T) {
	err := sigTestVerifyWithAssertionOpts(t, "unit-cred-no-up",
		sigTestAssertionOpts{flags: sigTestFlagsUserVerified}) // UV only, UP clear
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticatorData verification failed")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_UserVerifiedFlagMissing_Rejected verifies
// an assertion produced without user verification (UV clear) is rejected — the
// controller's own ceremony demands protocol.VerificationRequired, so the steward that
// exists to check it independently must not accept less.
func TestWebAuthnOperatorCredentialVerifier_Verify_UserVerifiedFlagMissing_Rejected(t *testing.T) {
	err := sigTestVerifyWithAssertionOpts(t, "unit-cred-no-uv",
		sigTestAssertionOpts{flags: sigTestFlagsUserPresent}) // UP only, UV clear
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticatorData verification failed")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_RPIDHashMismatch_Rejected verifies an
// assertion produced for a different relying party is rejected, even though it is
// otherwise a well-formed assertion by an authorized credential.
func TestWebAuthnOperatorCredentialVerifier_Verify_RPIDHashMismatch_Rejected(t *testing.T) {
	err := sigTestVerifyWithAssertionOpts(t, "unit-cred-wrong-rp",
		sigTestAssertionOpts{rpID: "attacker.example"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticatorData verification failed")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_OriginMismatch_Rejected verifies an
// assertion collected at an origin the manifest's relying-party binding does not name is
// rejected.
func TestWebAuthnOperatorCredentialVerifier_Verify_OriginMismatch_Rejected(t *testing.T) {
	err := sigTestVerifyWithAssertionOpts(t, "unit-cred-wrong-origin",
		sigTestAssertionOpts{origin: "https://phish.example"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clientDataJSON verification failed")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_WrongCeremonyType_Rejected verifies an
// assertion whose clientDataJSON type is not "webauthn.get" is rejected — signature
// confusion between the registration and assertion ceremonies.
func TestWebAuthnOperatorCredentialVerifier_Verify_WrongCeremonyType_Rejected(t *testing.T) {
	err := sigTestVerifyWithAssertionOpts(t, "unit-cred-wrong-ceremony",
		sigTestAssertionOpts{ceremonyType: "webauthn.create"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clientDataJSON verification failed")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_UndomainSeparatedChallenge_Rejected is
// the domain-separation test: an assertion whose challenge is the bare
// sha256(CanonicalBytes(envelope)) — the value a taken-over controller could serve as
// the challenge of a routine passkey login, which an operator would sign without ever
// being shown a command — does not authorize the envelope.
func TestWebAuthnOperatorCredentialVerifier_Verify_UndomainSeparatedChallenge_Rejected(t *testing.T) {
	env := operatorpayload.Envelope{
		Content: []byte("echo hi"), Shell: "bash", Targets: []string{"steward-test"},
		Nonce: "nonce-1", ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)
	bare := sha256.Sum256(canonical)

	err = sigTestVerifyWithAssertionOpts(t, "unit-cred-bare-challenge", sigTestAssertionOpts{
		challengeOverride: base64.RawURLEncoding.EncodeToString(bare[:]),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "challenge")
}

// ---------------------------------------------------------------------------
// Authorization: roster membership is not authority.
// ---------------------------------------------------------------------------

// TestWebAuthnOperatorCredentialVerifier_Verify_CredentialWithoutGrant_Rejected verifies
// a credential present in the CA-signed roster but carrying no operator-payload signing
// grant does not authorize execution — a passkey belonging to a zero-privilege account
// must not run scripts as SYSTEM.
func TestWebAuthnOperatorCredentialVerifier_Verify_CredentialWithoutGrant_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-no-grant")

	entry := sigTestAuthorizedEntry(credID, pubKey)
	entry.Grants = nil
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{entry})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	err := newSigTestWebAuthnVerifier(caPool).Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), operatorPayloadSignGrant)
}

// TestWebAuthnOperatorCredentialVerifier_Verify_ForeignTenantCredential_Rejected verifies
// a credential owned by an account in another tenant does not authorize execution on
// this steward, even though the roster it appears in is fleet-wide.
func TestWebAuthnOperatorCredentialVerifier_Verify_ForeignTenantCredential_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-foreign-tenant")

	entry := sigTestAuthorizedEntry(credID, pubKey)
	entry.RootScope = false
	entry.TenantID = "root/msp-b"
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{entry})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	// The steward's own tenant is root/msp-a/client-1 — not covered by root/msp-b.
	err := newSigTestWebAuthnVerifier(caPool).Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_AncestorTenantCredential_Accepted verifies
// the tenant check is subtree containment, not exact equality: an operator scoped to an
// ancestor of this steward's tenant is authorized.
func TestWebAuthnOperatorCredentialVerifier_Verify_AncestorTenantCredential_Accepted(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-ancestor-tenant")

	entry := sigTestAuthorizedEntry(credID, pubKey)
	entry.RootScope = false
	entry.TenantID = "root/msp-a" // sigTestStewardTenant is root/msp-a/client-1
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{entry})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	assert.NoError(t, newSigTestWebAuthnVerifier(caPool).Verify(env, proof))
}

// TestWebAuthnOperatorCredentialVerifier_Verify_TenantScopedCredential_UnknownStewardTenant_Rejected
// verifies a steward that does not know its own tenant refuses a tenant-scoped entry
// rather than assuming the entry covers it.
func TestWebAuthnOperatorCredentialVerifier_Verify_TenantScopedCredential_UnknownStewardTenant_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-unknown-steward-tenant")

	entry := sigTestAuthorizedEntry(credID, pubKey)
	entry.RootScope = false
	entry.TenantID = "root/msp-a"
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{entry})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool, freshness: &manifestFreshnessFloor{}}
	err := v.Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_RootScopeEntryWithTenant_Rejected verifies
// a self-contradictory entry — root scope claimed alongside a tenant path — is refused
// rather than resolved in the credential's favour.
func TestWebAuthnOperatorCredentialVerifier_Verify_RootScopeEntryWithTenant_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-contradictory-scope")

	entry := sigTestAuthorizedEntry(credID, pubKey)
	entry.TenantID = "root/msp-b" // RootScope stays true
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{entry})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	err := newSigTestWebAuthnVerifier(caPool).Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant")
}

// ---------------------------------------------------------------------------
// Manifest freshness — without it, removing a compromised passkey could never
// take effect on a steward.
// ---------------------------------------------------------------------------

// TestWebAuthnOperatorCredentialVerifier_Verify_StaleManifest_Rejected verifies a
// manifest older than the freshness window is refused, so a captured manifest cannot be
// presented indefinitely as proof that a since-removed credential is still authorized.
func TestWebAuthnOperatorCredentialVerifier_Verify_StaleManifest_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-stale-manifest")

	stale := time.Now().Add(-webauthnManifestMaxAge - time.Minute).UTC().Truncate(time.Second)
	manifestJSON := sigTestSignManifestAt(t, signingCert,
		[]authorizedWebAuthnCredential{sigTestAuthorizedEntry(credID, pubKey)}, stale,
		&webauthnRelyingParty{ID: sigTestRPID, Origins: []string{sigTestAssertionOrigin}})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	err := newSigTestWebAuthnVerifier(caPool).Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "freshness window")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_FutureDatedManifest_Rejected verifies a
// manifest issued implausibly far in this steward's future is refused, so a forged
// issuance instant cannot push the freshness floor forward and lock out every
// subsequent legitimate manifest.
func TestWebAuthnOperatorCredentialVerifier_Verify_FutureDatedManifest_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-future-manifest")

	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	manifestJSON := sigTestSignManifestAt(t, signingCert,
		[]authorizedWebAuthnCredential{sigTestAuthorizedEntry(credID, pubKey)}, future,
		&webauthnRelyingParty{ID: sigTestRPID, Origins: []string{sigTestAssertionOrigin}})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	err := newSigTestWebAuthnVerifier(caPool).Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "future")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_ManifestRollback_Rejected is the
// revocation-enforceability test: once a newer manifest has been accepted, an older one
// — the copy that still lists a credential the newer one dropped — is refused, so
// removing a compromised passkey cannot be undone by replaying a captured manifest.
func TestWebAuthnOperatorCredentialVerifier_Verify_ManifestRollback_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	revokedCredID := []byte("unit-cred-rollback-removed")
	keptPriv, keptPubKey := sigTestWebAuthnKeypair(t)
	keptCredID := []byte("unit-cred-rollback-kept")

	rp := &webauthnRelyingParty{ID: sigTestRPID, Origins: []string{sigTestAssertionOrigin}}
	older := time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Second)
	newer := time.Now().UTC().Truncate(time.Second)

	// The old manifest still lists the credential that has since been de-registered.
	oldManifest := sigTestSignManifestAt(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(revokedCredID, pubKey),
		sigTestAuthorizedEntry(keptCredID, keptPubKey),
	}, older, rp)
	// The current manifest no longer carries it.
	newManifest := sigTestSignManifestAt(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(keptCredID, keptPubKey),
	}, newer, rp)

	v := newSigTestWebAuthnVerifier(caPool)

	// Accept the current manifest first — this establishes the freshness floor.
	envKept, proofKept := sigTestWebAuthnProof(t, keptPriv, keptCredID, newManifest, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-kept", time.Now().Add(5*time.Minute))
	require.NoError(t, v.Verify(envKept, proofKept))

	// Replaying the older manifest to resurrect the removed credential must fail.
	envOld, proofOld := sigTestWebAuthnProof(t, priv, revokedCredID, oldManifest, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-old", time.Now().Add(5*time.Minute))
	err := v.Verify(envOld, proofOld)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already accepted")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_ManifestWithoutIssuedAt_Rejected verifies
// a manifest with no issuance instant is refused rather than treated as always fresh.
func TestWebAuthnOperatorCredentialVerifier_Verify_ManifestWithoutIssuedAt_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-no-issued-at")

	manifestJSON := sigTestSignManifestAt(t, signingCert,
		[]authorizedWebAuthnCredential{sigTestAuthorizedEntry(credID, pubKey)}, time.Time{},
		&webauthnRelyingParty{ID: sigTestRPID, Origins: []string{sigTestAssertionOrigin}})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	err := newSigTestWebAuthnVerifier(caPool).Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuance time")
}

// TestWebAuthnOperatorCredentialVerifier_Verify_ManifestWithoutRelyingParty_Rejected
// verifies a manifest carrying no relying-party binding is refused: without it there is
// no trustworthy value to check rpIdHash and origin against, and guessing one would
// silently drop both §7.2 checks.
func TestWebAuthnOperatorCredentialVerifier_Verify_ManifestWithoutRelyingParty_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-no-rp")

	manifestJSON := sigTestSignManifestAt(t, signingCert,
		[]authorizedWebAuthnCredential{sigTestAuthorizedEntry(credID, pubKey)},
		time.Now().UTC().Truncate(time.Second), nil)

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	err := newSigTestWebAuthnVerifier(caPool).Verify(env, proof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "relying-party binding")
}
