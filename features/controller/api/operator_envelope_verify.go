// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// OperatorX509Proof is the X.509 credential block of an operator-signed envelope: the
// signature over operatorpayload.CanonicalBytes and the signing certificate (PEM).
type OperatorX509Proof struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	PublicKey string `json:"public_key"`
}

// OperatorWebAuthnProof is the WebAuthn credential block of an operator-signed envelope:
// the raw assertion fields handleOperatorPayloadSignFinish returns.
type OperatorWebAuthnProof struct {
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
	CredentialID      []byte `json:"credential_id"`
}

// OperatorProof carries exactly one credential block. The envelope is verified under
// whichever is present; presenting both, or neither, is refused so the credential the
// controller verified is unambiguously the one forwarded to the steward.
type OperatorProof struct {
	X509     *OperatorX509Proof     `json:"x509,omitempty"`
	WebAuthn *OperatorWebAuthnProof `json:"webauthn,omitempty"`
}

// verifyOperatorActionEnvelope is the one controller-side verification entry point for
// an operator-signed steward-action envelope, under either credential type. It returns
// the identifier of the credential that authorized the envelope: the signing
// certificate's serial for X.509, the hex-encoded credential ID for WebAuthn (the form the
// sign ceremony audits).
//
// The envelope is reconstructed from action (operatorpayload.ActionContent with
// operatorpayload.ActionShell), targets, nonce and expiresAt. Admission window, shared
// by both credential types: expiresAt must not be past nor further than
// operatorpayload.ActionEnvelopeMaxTTL from now, and the signed targets must be exactly
// the one steward the request addresses (stewardID). Nonce single-use is the steward's
// job and is not tracked here.
//
// The WebAuthn branch is stateless. handleOperatorPayloadSignFinish has already run
// ValidateLogin, checked the sign count and persisted the advanced count, so this
// branch neither checks nor updates it — repeating the check would reject every valid
// assertion. The caller is the authenticated principal in ctx, never a client-supplied
// account, and the credential must be one of that account's own.
//
// Callers report a failure to the client as "invalid operator signature" without
// detail, and log the returned error through logging.SanitizeLogValue.
func (s *Server) verifyOperatorActionEnvelope(ctx context.Context, stewardID string, action operatorpayload.Action, targets []string, nonce string, expiresAt time.Time, proof OperatorProof) (string, error) {
	if (proof.X509 == nil) == (proof.WebAuthn == nil) {
		return "", fmt.Errorf("operator proof must carry exactly one credential type")
	}
	now := time.Now()
	if !expiresAt.After(now) {
		return "", fmt.Errorf("operator envelope has expired")
	}
	if expiresAt.After(now.Add(operatorpayload.ActionEnvelopeMaxTTL)) {
		return "", fmt.Errorf("operator envelope expiry exceeds the %s maximum", operatorpayload.ActionEnvelopeMaxTTL)
	}
	if stewardID == "" || len(targets) != 1 || targets[0] != stewardID {
		return "", fmt.Errorf("operator envelope targets must be exactly the addressed steward")
	}

	content, err := operatorpayload.ActionContent(action)
	if err != nil {
		return "", fmt.Errorf("invalid operator action: %w", err)
	}
	envelope := operatorpayload.Envelope{
		Content:   content,
		Shell:     operatorpayload.ActionShell,
		Targets:   targets,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}

	if proof.X509 != nil {
		return s.verifyActionX509(envelope, proof.X509)
	}
	return s.verifyActionWebAuthn(ctx, envelope, proof.WebAuthn)
}

func (s *Server) verifyActionX509(envelope operatorpayload.Envelope, proof *OperatorX509Proof) (string, error) {
	if proof.Algorithm == "" || proof.Value == "" || proof.PublicKey == "" {
		return "", fmt.Errorf("incomplete x509 operator proof")
	}
	canonical, err := operatorpayload.CanonicalBytes(envelope)
	if err != nil {
		return "", fmt.Errorf("invalid operator envelope: %w", err)
	}
	if err := scriptmodule.VerifyScriptSignature(canonical, &scriptmodule.ScriptSignature{
		Algorithm: proof.Algorithm,
		Signature: proof.Value,
		PublicKey: proof.PublicKey,
	}, scriptmodule.ShellType(envelope.Shell), scriptmodule.ModuleSigningConfig{TrustMode: scriptmodule.TrustModeAnyValid}); err != nil {
		return "", fmt.Errorf("invalid operator signature: %w", err)
	}
	return s.verifyOperatorSigningCertificate(proof.PublicKey)
}

func (s *Server) verifyActionWebAuthn(ctx context.Context, envelope operatorpayload.Envelope, proof *OperatorWebAuthnProof) (string, error) {
	if len(proof.AuthenticatorData) == 0 || len(proof.ClientDataJSON) == 0 || len(proof.Signature) == 0 || len(proof.CredentialID) == 0 {
		return "", fmt.Errorf("incomplete webauthn operator proof")
	}
	wa := s.getWebAuthn()
	if wa == nil || wa.Config == nil {
		return "", fmt.Errorf("webauthn is not configured")
	}
	principal, _ := ctx.Value(principalContextKey).(*Principal)
	if principal == nil {
		return "", fmt.Errorf("webauthn operator proof requires an authenticated principal")
	}
	acct, err := s.getAccount(ctx, principal.ID)
	if err != nil {
		return "", fmt.Errorf("load operator account: %w", err)
	}
	if acct == nil {
		return "", fmt.Errorf("operator account not found")
	}

	var stored *WebAuthnCredential
	for i := range acct.Credentials {
		if subtle.ConstantTimeCompare(acct.Credentials[i].ID, proof.CredentialID) == 1 {
			stored = &acct.Credentials[i]
			break
		}
	}
	if stored == nil {
		return "", fmt.Errorf("credential is not registered to the caller")
	}

	hash, err := operatorpayload.ChallengeHash(envelope)
	if err != nil {
		return "", fmt.Errorf("invalid operator envelope: %w", err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    b64(proof.CredentialID),
		"rawId": b64(proof.CredentialID),
		"type":  "public-key",
		"response": map[string]string{
			"authenticatorData": b64(proof.AuthenticatorData),
			"clientDataJSON":    b64(proof.ClientDataJSON),
			"signature":         b64(proof.Signature),
		},
	})
	if err != nil {
		return "", fmt.Errorf("encode assertion: %w", err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return "", fmt.Errorf("parse webauthn assertion: %w", err)
	}

	// Cross-origin assertions are refused outright, and opaque and top origins are not
	// widened: the same posture the steward-side verifier takes.
	if err := parsed.Verify(b64(hash[:]), wa.Config.RPID, "", wa.Config.RPOrigins, nil, nil,
		protocol.TopOriginImplicitVerificationMode, false, true, true, stored.PublicKey, wa.Config.Signature); err != nil {
		return "", fmt.Errorf("webauthn assertion verification failed: %w", err)
	}

	// Credential authority, as the steward applies it: a registered passkey says nothing
	// about whether its owner may sign an operator payload.
	if !accountHoldsOperatorPayloadSigning(acct) {
		return "", fmt.Errorf("credential owner does not hold %s", OperatorPayloadSignGrant)
	}
	return hex.EncodeToString(stored.ID), nil
}
