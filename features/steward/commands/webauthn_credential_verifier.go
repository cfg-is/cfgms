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
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// revocationManifestKind mirrors RevocationManifestKind in
// features/controller/api/handlers_revocation_manifest.go.
const revocationManifestKind = "operator-cert-revocation"

// authorizedWebAuthnCredentialKind mirrors AuthorizedWebAuthnCredentialKind.
const authorizedWebAuthnCredentialKind = "webauthn-credential"

// operatorPayloadSignGrant mirrors OperatorPayloadSignGrant — the permission ID a roster
// entry must carry before the credential it names may authorize inline execution here.
// Presence in the roster is not authority: the controller registers a passkey so its
// owner can log in, which says nothing about whether that owner may run a script as
// SYSTEM on this steward.
const operatorPayloadSignGrant = "operator-payload:sign"

// webauthnManifestMaxAge bounds how old a signed manifest may be when it is used to
// authorize execution. Without an upper bound the manifest is a bearer artifact that
// never expires, and de-registering a compromised passkey (or disabling its account)
// could never take effect on any steward: the holder of an old manifest would keep
// presenting the copy that still lists the credential. Above the operator envelope's own
// 5-minute validity so a legitimately-signed envelope never outlives the manifest
// fetched alongside it.
const webauthnManifestMaxAge = 15 * time.Minute

// webauthnManifestClockSkew is how far a manifest's issuance instant may sit in this
// steward's future before it is refused, covering ordinary controller/steward clock
// disagreement without letting a far-future IssuedAt push the freshness floor forward
// and lock out every subsequent legitimate manifest.
const webauthnManifestClockSkew = 2 * time.Minute

// authorizedWebAuthnCredential mirrors
// features/controller/api.AuthorizedWebAuthnCredential field-for-field.
type authorizedWebAuthnCredential struct {
	Kind         string   `json:"kind"`
	CredentialID []byte   `json:"credential_id"`
	PublicKey    []byte   `json:"public_key"`
	TenantID     string   `json:"tenant_id"`
	RootScope    bool     `json:"root_scope"`
	Grants       []string `json:"grants"`
}

// webauthnRelyingParty mirrors features/controller/api.WebAuthnRelyingParty — the
// relying-party binding the W3C WebAuthn §7.2 rpIdHash and origin checks are made
// against. It arrives inside the CA-signed manifest because a steward has no other
// trustworthy source for it.
type webauthnRelyingParty struct {
	ID      string   `json:"id"`
	Origins []string `json:"origins"`
}

// revocationManifestPayload mirrors features/controller/api.RevocationManifest
// field-for-field (name, order, json tags) — required so json.Marshal of this struct
// reproduces the exact bytes the controller signed.
type revocationManifestPayload struct {
	Kind                          string                         `json:"kind"`
	Version                       int64                          `json:"version"`
	IssuedAt                      time.Time                      `json:"issued_at"`
	RevokedSerials                []string                       `json:"revoked_serials"`
	AuthorizedWebAuthnCredentials []authorizedWebAuthnCredential `json:"authorized_webauthn_credentials,omitempty"`
	WebAuthnRelyingParty          *webauthnRelyingParty          `json:"webauthn_relying_party,omitempty"`
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

// manifestFreshnessFloor is the high-water mark of manifest issuance instants this
// steward has already accepted. Held on the Handler and shared by every verification, so
// a manifest older than the newest one already honoured is refused: an attacker holding
// a captured manifest that still lists a since-removed credential cannot roll this
// steward back to it, even inside webauthnManifestMaxAge.
//
// The floor is process-scoped. A restarted steward re-learns it from the first manifest
// it accepts, so the window in which a captured manifest could still be presented after
// a restart is bounded by webauthnManifestMaxAge rather than by the floor.
type manifestFreshnessFloor struct {
	mu     sync.Mutex
	newest time.Time
}

// admit reports whether issuedAt is at least as new as every manifest already accepted,
// advancing the floor when it is. Called only after the manifest's signature, chain and
// kind have been verified, so an unverifiable manifest can never move the floor.
func (f *manifestFreshnessFloor) admit(issuedAt time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if issuedAt.Before(f.newest) {
		return false
	}
	f.newest = issuedAt
	return true
}

// webauthnOperatorCredentialVerifier is the OperatorCredentialVerifier implementation
// (execute_script.go) for a WebAuthn-signed operator envelope. Unlike
// x509OperatorCredentialVerifier, there is no "any_valid, no CA roots configured"
// relaxation: a WebAuthn credential's public key has no source other than the
// CA-verified manifest, so verification fails closed when caRoots is nil — the caller
// (preflightScriptSignature) enforces this before ever constructing this verifier.
//
// stewardTenant is this steward's own tenant path, used to confine a fleet-wide roster
// entry to the tenant subtree its owning account belongs to. An empty value means the
// steward does not know its tenant (standalone, or not yet registered); only a
// root-scope entry is accepted then, because there is nothing to compare a
// tenant-scoped entry against.
type webauthnOperatorCredentialVerifier struct {
	caRoots       *x509.CertPool
	stewardTenant string
	freshness     *manifestFreshnessFloor
}

// Verify implements OperatorCredentialVerifier. It performs, in order:
//  1. Recompute the expected challenge: operatorpayload.ChallengeHash(envelope) — sha256
//     over a domain-separated preimage, so an assertion collected during any other
//     ceremony at this relying party cannot be replayed as an operator authorization.
//  2. Resolve the credential's public key from the CA-signed manifest embedded in proof —
//     never from a client-declared key — enforcing manifest freshness, the entry's
//     operator-payload-signing grant, and its tenant against this steward's own.
//  3. Verify clientDataJSON per W3C WebAuthn §7.2 steps 7-9: ceremony type is
//     "webauthn.get", the challenge equals the recomputed hash (what binds the assertion
//     to this exact envelope — content, shell, targets, nonce, expiry — rather than to
//     "the operator was present" at some unrelated moment), and the origin is one the
//     manifest's relying-party binding names.
//  4. Verify authenticatorData per §7.2 steps 11-15: rpIdHash equals sha256(rpID), and
//     both the User Present and User Verified flags are set — the hardware-presence and
//     operator-approval property this path exists to establish, and the same
//     protocol.VerificationRequired discipline the controller's own ceremony applies.
//  5. Reconstruct authenticatorData || SHA-256(clientDataJSON) and verify the assertion
//     signature against the resolved public key.
func (v *webauthnOperatorCredentialVerifier) Verify(envelope operatorpayload.Envelope, proof []byte) error {
	var p webauthnAssertionProof
	if err := json.Unmarshal(proof, &p); err != nil {
		return fmt.Errorf("invalid webauthn assertion proof: %w", err)
	}
	if len(p.AuthenticatorData) == 0 || len(p.ClientDataJSON) == 0 || len(p.Signature) == 0 || len(p.CredentialID) == 0 {
		return fmt.Errorf("incomplete webauthn assertion proof")
	}

	expectedHash, err := operatorpayload.ChallengeHash(envelope)
	if err != nil {
		return fmt.Errorf("invalid operator envelope: %w", err)
	}

	entry, relyingParty, err := v.resolveCredential([]byte(p.SignedManifestJSON), p.CredentialID)
	if err != nil {
		return fmt.Errorf("webauthn credential not independently verifiable: %w", err)
	}

	wantChallenge := base64.RawURLEncoding.EncodeToString(expectedHash[:])
	if err := verifyAssertionClientData(p.ClientDataJSON, wantChallenge, relyingParty.Origins); err != nil {
		return err
	}
	if err := verifyAssertionAuthenticatorData(p.AuthenticatorData, relyingParty.ID); err != nil {
		return err
	}

	clientDataHash := sha256.Sum256(p.ClientDataJSON)
	sigData := make([]byte, 0, len(p.AuthenticatorData)+len(clientDataHash))
	sigData = append(sigData, p.AuthenticatorData...)
	sigData = append(sigData, clientDataHash[:]...)

	key, err := webauthncose.ParsePublicKey(entry.PublicKey)
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

// verifyAssertionClientData applies W3C WebAuthn §7.2 steps 7-9 to the raw
// clientDataJSON: ceremony type, challenge, and origin. It delegates to
// protocol.CollectedClientData.Verify rather than re-implementing the comparisons, so
// this verifier and the controller's own ceremony agree on what those steps mean.
// Cross-origin assertions are refused outright (allowCrossOrigin false): an
// operator-payload authorization collected from an embedded frame is not a shape this
// path has any reason to accept.
func verifyAssertionClientData(clientDataJSON []byte, wantChallenge string, rpOrigins []string) error {
	var clientData protocol.CollectedClientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		return fmt.Errorf("invalid webauthn clientDataJSON: %w", err)
	}
	// Compared here as well as inside Verify below so the most common rejection — an
	// assertion collected for some other envelope or ceremony — reports what actually
	// went wrong instead of a generic clientData failure.
	if clientData.Challenge != wantChallenge {
		return fmt.Errorf("webauthn assertion challenge does not match the signed envelope")
	}
	if err := clientData.Verify(wantChallenge, protocol.AssertCeremony, rpOrigins, nil,
		protocol.TopOriginImplicitVerificationMode, false); err != nil {
		return fmt.Errorf("webauthn clientDataJSON verification failed: %w", err)
	}
	return nil
}

// verifyAssertionAuthenticatorData applies W3C WebAuthn §7.2 steps 11-15: the assertion
// must have been produced for this relying party (rpIdHash), with the user present (UP)
// and with user verification performed (UV). Requiring UV matches the controller's own
// protocol.VerificationRequired ceremony — a steward positioned as the independent
// verifier must not apply weaker checks than the party it exists to check.
func verifyAssertionAuthenticatorData(rawAuthData []byte, rpID string) error {
	var authData protocol.AuthenticatorData
	if err := authData.Unmarshal(rawAuthData); err != nil {
		return fmt.Errorf("invalid webauthn authenticatorData: %w", err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	if err := authData.Verify(rpIDHash[:], nil, true, true); err != nil {
		return fmt.Errorf("webauthn authenticatorData verification failed: %w", err)
	}
	return nil
}

// resolveCredential verifies manifestJSON's embedded signer certificate chains to
// v.caRoots with the CodeSigning EKU (the PurposeSigning certificate shape —
// pkg/cert.GenerateSigningCertificate), verifies the manifest's own signature against
// that certificate, confirms it really is a revocation manifest (not a payload signed
// for a different purpose reused here), enforces its freshness, and returns the roster
// entry for credentialID together with the manifest's relying-party binding — or an
// error if the manifest does not independently authorize that credential on this
// steward.
func (v *webauthnOperatorCredentialVerifier) resolveCredential(manifestJSON, credentialID []byte) (*authorizedWebAuthnCredential, *webauthnRelyingParty, error) {
	var manifest signedRevocationManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return nil, nil, fmt.Errorf("invalid signed manifest: %w", err)
	}
	if manifest.Signature == nil {
		return nil, nil, fmt.Errorf("manifest carries no signature")
	}
	if manifest.Manifest.Kind != revocationManifestKind {
		return nil, nil, fmt.Errorf("unexpected manifest kind %q", manifest.Manifest.Kind)
	}

	block, _ := pem.Decode([]byte(manifest.SignerCertificatePEM))
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found in manifest signer certificate")
	}
	signerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse manifest signer certificate: %w", err)
	}
	opts := x509.VerifyOptions{
		Roots:     v.caRoots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if _, err := signerCert.Verify(opts); err != nil {
		return nil, nil, fmt.Errorf("manifest signer certificate chain verification: %w", err)
	}

	verifier, err := signature.NewVerifierFromCertificate(signerCert)
	if err != nil {
		return nil, nil, fmt.Errorf("construct manifest verifier: %w", err)
	}
	manifestBytes, err := json.Marshal(manifest.Manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal manifest for verification: %w", err)
	}
	if err := verifier.Verify(manifestBytes, manifest.Signature); err != nil {
		return nil, nil, fmt.Errorf("manifest signature verification failed: %w", err)
	}

	// Freshness before authorization: a manifest that is too old, or older than one this
	// steward has already honoured, states nothing current about who is authorized.
	if err := v.checkManifestFreshness(manifest.Manifest.IssuedAt); err != nil {
		return nil, nil, err
	}

	// The roster is fleet-wide, so one credential ID can legitimately appear more than
	// once when the same authenticator is registered to two authorized accounts in
	// different tenants. Every matching entry is examined and the first that authorizes
	// this steward wins; the rejection reason reported is the last one seen, so a
	// credential that is present but unauthorized is distinguishable from one that is
	// absent entirely.
	var matchErr error
	for i := range manifest.Manifest.AuthorizedWebAuthnCredentials {
		entry := &manifest.Manifest.AuthorizedWebAuthnCredentials[i]
		if entry.Kind != authorizedWebAuthnCredentialKind || !bytes.Equal(entry.CredentialID, credentialID) {
			continue
		}
		if !entryGrantsOperatorPayloadSigning(entry) {
			matchErr = fmt.Errorf("credential is not granted %s", operatorPayloadSignGrant)
			continue
		}
		if !v.entryAuthorizedForTenant(entry) {
			matchErr = fmt.Errorf("credential is scoped to a tenant that does not cover this steward")
			continue
		}
		if len(entry.PublicKey) == 0 {
			matchErr = fmt.Errorf("credential entry carries no public key")
			continue
		}
		if manifest.Manifest.WebAuthnRelyingParty == nil ||
			manifest.Manifest.WebAuthnRelyingParty.ID == "" ||
			len(manifest.Manifest.WebAuthnRelyingParty.Origins) == 0 {
			return nil, nil, fmt.Errorf("manifest carries no webauthn relying-party binding")
		}
		return entry, manifest.Manifest.WebAuthnRelyingParty, nil
	}
	if matchErr != nil {
		return nil, nil, matchErr
	}
	return nil, nil, fmt.Errorf("credential id not found in authorized-webauthn-credentials manifest entries")
}

// checkManifestFreshness bounds the manifest's age, refuses one issued implausibly far
// in this steward's future, and refuses one older than the newest already accepted.
func (v *webauthnOperatorCredentialVerifier) checkManifestFreshness(issuedAt time.Time) error {
	if issuedAt.IsZero() {
		return fmt.Errorf("manifest carries no issuance time")
	}
	now := time.Now()
	if issuedAt.After(now.Add(webauthnManifestClockSkew)) {
		return fmt.Errorf("manifest issuance time is in the future")
	}
	if now.Sub(issuedAt) > webauthnManifestMaxAge {
		return fmt.Errorf("manifest is older than the %s freshness window", webauthnManifestMaxAge)
	}
	if v.freshness != nil && !v.freshness.admit(issuedAt) {
		return fmt.Errorf("manifest is older than one already accepted by this steward")
	}
	return nil
}

// entryGrantsOperatorPayloadSigning reports whether the roster entry states that its
// owning account holds operator-payload signing authority.
func entryGrantsOperatorPayloadSigning(entry *authorizedWebAuthnCredential) bool {
	for _, grant := range entry.Grants {
		if grant == operatorPayloadSignGrant {
			return true
		}
	}
	return false
}

// entryAuthorizedForTenant reports whether entry's owning tenant covers this steward.
// A root-scope entry (an unscoped platform administrator) covers the whole fleet; any
// other entry covers only its own tenant path and that path's descendants, matching how
// the controller scopes a tenant-bound principal's reach.
func (v *webauthnOperatorCredentialVerifier) entryAuthorizedForTenant(entry *authorizedWebAuthnCredential) bool {
	if entry.RootScope {
		return entry.TenantID == ""
	}
	if entry.TenantID == "" || v.stewardTenant == "" {
		return false
	}
	return v.stewardTenant == entry.TenantID || strings.HasPrefix(v.stewardTenant, entry.TenantID+"/")
}
