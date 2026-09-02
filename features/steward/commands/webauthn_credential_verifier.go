// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3697: steward-side verification of a WebAuthn-signed operator payload — the
// browser-only-operator counterpart to x509OperatorCredentialVerifier (execute_script.go).
//
// A WebAuthn assertion has no certificate chain: the only place its public key can come
// from is the CA-signed revocation manifest (features/controller/api/handlers_revocation_manifest.go,
// extended by this story with an authorized-WebAuthn-credentials roster) — never an
// unsigned, live controller claim. This package (features/steward/commands) cannot import
// features/controller/api (controller-only), so the wire shapes this file verifies are
// duplicated here field-for-field, matching json tag and field order exactly so
// encoding/json produces byte-identical output to what the controller signed.
package commands

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// revocationManifestKind mirrors RevocationManifestKind in
// features/controller/api/handlers_revocation_manifest.go.
const revocationManifestKind = "operator-cert-revocation"

// authorizedWebAuthnCredentialKind mirrors AuthorizedWebAuthnCredentialKind.
const authorizedWebAuthnCredentialKind = "webauthn-credential"

// authorizedWebAuthnCredential mirrors
// features/controller/api.AuthorizedWebAuthnCredential field-for-field.
type authorizedWebAuthnCredential struct {
	Kind         string `json:"kind"`
	CredentialID []byte `json:"credential_id"`
	PublicKey    []byte `json:"public_key"`
}

// revocationManifestPayload mirrors features/controller/api.RevocationManifest
// field-for-field (name, order, json tags) — required so json.Marshal of this struct
// reproduces the exact bytes the controller signed.
type revocationManifestPayload struct {
	Kind                          string                         `json:"kind"`
	Version                       int64                          `json:"version"`
	RevokedSerials                []string                       `json:"revoked_serials"`
	AuthorizedWebAuthnCredentials []authorizedWebAuthnCredential `json:"authorized_webauthn_credentials,omitempty"`
}

// signedRevocationManifest mirrors features/controller/api.SignedRevocationManifest.
type signedRevocationManifest struct {
	Manifest             revocationManifestPayload  `json:"manifest"`
	Signature            *signature.ConfigSignature `json:"signature"`
	SignerCertificatePEM string                     `json:"signer_certificate_pem"`
}

// webauthnAssertionProof bundles everything webauthnOperatorCredentialVerifier.Verify
// needs into the single []byte OperatorCredentialVerifier.Verify's proof parameter
// accepts, without changing that interface (Issue #3694's seam, unchanged by this story).
type webauthnAssertionProof struct {
	AuthenticatorData  []byte `json:"authenticator_data"`
	ClientDataJSON     []byte `json:"client_data_json"`
	Signature          []byte `json:"signature"`
	CredentialID       []byte `json:"credential_id"`
	SignedManifestJSON string `json:"signed_manifest_json"`
}

// webauthnOperatorCredentialVerifier is the OperatorCredentialVerifier implementation
// (execute_script.go) for a WebAuthn-signed operator envelope. Unlike
// x509OperatorCredentialVerifier, there is no "any_valid, no CA roots configured"
// relaxation: a WebAuthn credential's public key has no source other than the
// CA-verified manifest, so verification fails closed when caRoots is nil — the caller
// (preflightScriptSignature) enforces this before ever constructing this verifier.
type webauthnOperatorCredentialVerifier struct {
	caRoots *x509.CertPool
}

// Verify implements OperatorCredentialVerifier. It performs, in order:
//  1. Recompute the expected challenge: sha256(operatorpayload.CanonicalBytes(envelope)).
//  2. Confirm the assertion's clientDataJSON.challenge equals that recomputed hash — this
//     is what binds the assertion to this exact envelope (content, shell, targets, nonce,
//     expiry), not merely to "the operator was present" at some unrelated moment.
//  3. Resolve the credential's public key from the CA-signed manifest embedded in proof —
//     never from a client-declared key.
//  4. Reconstruct authenticatorData || SHA-256(clientDataJSON) and verify the assertion
//     signature against the resolved public key.
func (v *webauthnOperatorCredentialVerifier) Verify(envelope operatorpayload.Envelope, proof []byte) error {
	var p webauthnAssertionProof
	if err := json.Unmarshal(proof, &p); err != nil {
		return fmt.Errorf("invalid webauthn assertion proof: %w", err)
	}
	if len(p.AuthenticatorData) == 0 || len(p.ClientDataJSON) == 0 || len(p.Signature) == 0 || len(p.CredentialID) == 0 {
		return fmt.Errorf("incomplete webauthn assertion proof")
	}

	canonical, err := operatorpayload.CanonicalBytes(envelope)
	if err != nil {
		return fmt.Errorf("invalid operator envelope: %w", err)
	}
	expectedHash := sha256.Sum256(canonical)

	var clientData struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(p.ClientDataJSON, &clientData); err != nil {
		return fmt.Errorf("invalid webauthn clientDataJSON: %w", err)
	}
	wantChallenge := base64.RawURLEncoding.EncodeToString(expectedHash[:])
	if clientData.Challenge != wantChallenge {
		return fmt.Errorf("webauthn assertion challenge does not match the signed envelope")
	}

	pubKeyBytes, err := v.resolvePublicKey([]byte(p.SignedManifestJSON), p.CredentialID)
	if err != nil {
		return fmt.Errorf("webauthn credential not independently verifiable: %w", err)
	}

	clientDataHash := sha256.Sum256(p.ClientDataJSON)
	sigData := make([]byte, 0, len(p.AuthenticatorData)+len(clientDataHash))
	sigData = append(sigData, p.AuthenticatorData...)
	sigData = append(sigData, clientDataHash[:]...)

	key, err := webauthncose.ParsePublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("parse webauthn credential public key: %w", err)
	}
	valid, err := webauthncose.VerifySignature(key, sigData, p.Signature)
	if err != nil {
		return fmt.Errorf("webauthn assertion signature verification failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("webauthn assertion signature is invalid")
	}
	return nil
}

// resolvePublicKey verifies manifestJSON's embedded signer certificate chains to
// v.caRoots with the CodeSigning EKU (the PurposeSigning certificate shape —
// pkg/cert.GenerateSigningCertificate), verifies the manifest's own signature against
// that certificate, confirms it really is a revocation manifest (not a payload signed
// for a different purpose reused here), and returns credentialID's public key — or an
// error if the manifest does not independently authorize it.
func (v *webauthnOperatorCredentialVerifier) resolvePublicKey(manifestJSON, credentialID []byte) ([]byte, error) {
	var manifest signedRevocationManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return nil, fmt.Errorf("invalid signed manifest: %w", err)
	}
	if manifest.Signature == nil {
		return nil, fmt.Errorf("manifest carries no signature")
	}
	if manifest.Manifest.Kind != revocationManifestKind {
		return nil, fmt.Errorf("unexpected manifest kind %q", manifest.Manifest.Kind)
	}

	block, _ := pem.Decode([]byte(manifest.SignerCertificatePEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in manifest signer certificate")
	}
	signerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse manifest signer certificate: %w", err)
	}
	opts := x509.VerifyOptions{
		Roots:     v.caRoots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if _, err := signerCert.Verify(opts); err != nil {
		return nil, fmt.Errorf("manifest signer certificate chain verification: %w", err)
	}

	verifier, err := signature.NewVerifierFromCertificate(signerCert)
	if err != nil {
		return nil, fmt.Errorf("construct manifest verifier: %w", err)
	}
	manifestBytes, err := json.Marshal(manifest.Manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest for verification: %w", err)
	}
	if err := verifier.Verify(manifestBytes, manifest.Signature); err != nil {
		return nil, fmt.Errorf("manifest signature verification failed: %w", err)
	}

	for _, entry := range manifest.Manifest.AuthorizedWebAuthnCredentials {
		if entry.Kind == authorizedWebAuthnCredentialKind && bytes.Equal(entry.CredentialID, credentialID) {
			return entry.PublicKey, nil
		}
	}
	return nil, fmt.Errorf("credential id not found in authorized-webauthn-credentials manifest entries")
}
