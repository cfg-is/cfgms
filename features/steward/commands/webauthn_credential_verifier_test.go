// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3697: unit tests for webauthnOperatorCredentialVerifier in isolation — direct
// calls to Verify()/resolvePublicKey(), as opposed to execute_script_test.go's coverage
// of the full dispatch path (h.HandleCommand). Real cryptographic material throughout —
// no mocks, matching the [REQUIRED TEST] end-to-end tests' own discipline.
package commands

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// sigTestWebAuthnProof builds a real ECDSA P-256 assertion over
// authenticatorData||sha256(clientDataJSON) whose clientDataJSON.challenge equals
// sha256(operatorpayload.CanonicalBytes(envelope)) — the same bytes and algorithm
// production verification uses — and returns the envelope alongside the marshaled
// webauthnAssertionProof JSON bytes. Shared by this file's unit tests and
// execute_script_test.go's sigTestWebAuthnAssertionParams (dispatch-path tests).
func sigTestWebAuthnProof(t *testing.T, priv *ecdsa.PrivateKey, credID, manifestJSON, content []byte, shell string, targets []string, nonce string, expiresAt time.Time) (operatorpayload.Envelope, []byte) {
	t.Helper()
	env := operatorpayload.Envelope{
		Content:   content,
		Shell:     shell,
		Targets:   targets,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)
	challengeHash := sha256.Sum256(canonical)
	challengeB64 := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// authenticatorData: 32-byte rpIDHash (arbitrary — this verifier does not check RP
	// binding, only that authenticatorData||sha256(clientDataJSON) is what was signed)
	// + 1 flags byte (UP|UV) + 4-byte sign count.
	authData := make([]byte, 37)
	rpIDHash := sha256.Sum256([]byte("cfgms-steward-test"))
	copy(authData[:32], rpIDHash[:])
	authData[32] = 0x05

	clientData := struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}{Type: "webauthn.get", Challenge: challengeB64, Origin: "https://controller.test"}
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

// TestWebAuthnOperatorCredentialVerifier_Verify_Success is the positive baseline every
// negative test below mutates one field away from.
func TestWebAuthnOperatorCredentialVerifier_Verify_Success(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("unit-cred-success")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		{Kind: authorizedWebAuthnCredentialKind, CredentialID: credID, PublicKey: pubKey},
	})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
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
		{Kind: authorizedWebAuthnCredentialKind, CredentialID: credID, PublicKey: pubKey},
	})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	// Verify against a DIFFERENT envelope than the one the assertion was built for —
	// the recomputed challenge will not match clientDataJSON.challenge.
	tampered := env
	tampered.Content = []byte("echo something-else")

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
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
		{Kind: authorizedWebAuthnCredentialKind, CredentialID: credID, PublicKey: pubKey},
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

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
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

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
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
		{Kind: authorizedWebAuthnCredentialKind, CredentialID: credID, PublicKey: pubKey},
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

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
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

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
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
		{Kind: authorizedWebAuthnCredentialKind, CredentialID: credID, PublicKey: pubKey},
	})

	env, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, []byte("echo hi"), "bash",
		[]string{"steward-test"}, "nonce-1", time.Now().Add(5*time.Minute))

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
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

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
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

	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
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
	v := &webauthnOperatorCredentialVerifier{caRoots: caPool}
	err := v.Verify(env, []byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid webauthn assertion proof")
}
