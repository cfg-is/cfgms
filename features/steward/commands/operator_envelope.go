// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package commands

import (
	"fmt"
	"time"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// verifyOperatorEnvelope is the one steward-side routine that verifies an
// operator-signed envelope, for every privileged command that carries one
// (execute_script inline commands and steward actions).
//
// The signed envelope is reconstructed from content and shell plus the command's
// targets, nonce and expires_at params. It is verified under either credential type —
// X.509 (signature_algorithm, signature_value, signature_public_key) or WebAuthn
// (webauthn_authenticator_data, webauthn_client_data_json, webauthn_signature,
// webauthn_credential_id, webauthn_manifest) — through verifyX509OperatorSignature or
// verifyWebAuthnOperatorSignature. It then enforces that this steward's ID is in the
// signed targets, that the envelope has not expired, and single use of the nonce via
// envelopeNonceCache.
//
// shell is part of the signed canonical bytes, so an envelope signed for one purpose
// (a script shell, or operatorpayload.ActionShell) does not verify under another.
// Every failure wraps ErrUnauthenticatedCommand.
func (h *Handler) verifyOperatorEnvelope(cmd *cpTypes.Command, content []byte, shell string) error {
	sigAlgorithm, _ := cmd.Params["signature_algorithm"].(string)
	sigValue, _ := cmd.Params["signature_value"].(string)
	sigPublicKey, _ := cmd.Params["signature_public_key"].(string)
	hasSig := sigAlgorithm != "" && sigValue != "" && sigPublicKey != ""

	webauthnAuthDataB64, _ := cmd.Params["webauthn_authenticator_data"].(string)
	webauthnClientDataB64, _ := cmd.Params["webauthn_client_data_json"].(string)
	webauthnSigB64, _ := cmd.Params["webauthn_signature"].(string)
	webauthnCredIDB64, _ := cmd.Params["webauthn_credential_id"].(string)
	webauthnManifestJSON, _ := cmd.Params["webauthn_manifest"].(string)
	hasWebAuthn := webauthnAuthDataB64 != "" && webauthnClientDataB64 != "" && webauthnSigB64 != "" && webauthnCredIDB64 != ""

	if !hasSig && !hasWebAuthn {
		return ErrUnauthenticatedCommand
	}

	targets := extractStringSlice(cmd.Params["targets"])
	nonce, _ := cmd.Params["nonce"].(string)
	expiresAtStr, _ := cmd.Params["expires_at"].(string)
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return fmt.Errorf("%w: missing or invalid operator envelope expiry", ErrUnauthenticatedCommand)
	}

	envelope := operatorpayload.Envelope{
		Content:   content,
		Shell:     shell,
		Targets:   targets,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}

	if hasSig {
		if err := h.verifyX509OperatorSignature(envelope, shell, sigAlgorithm, sigValue, sigPublicKey); err != nil {
			return err
		}
	} else {
		if err := h.verifyWebAuthnOperatorSignature(envelope,
			webauthnAuthDataB64, webauthnClientDataB64, webauthnSigB64, webauthnCredIDB64, webauthnManifestJSON); err != nil {
			return err
		}
	}

	// Target-set binding (Issue #3694): this steward's own ID must be among the
	// resolved, signed target list — a legitimately-signed envelope re-addressed to a
	// different target set in transit does not authorize execution here.
	targeted := false
	for _, target := range targets {
		if target == h.stewardID {
			targeted = true
			break
		}
	}
	if !targeted {
		return fmt.Errorf("%w: steward is not in the signed target list", ErrUnauthenticatedCommand)
	}

	// Expiry (Issue #3694): reject an envelope past its bound validity window.
	if time.Now().After(expiresAt) {
		return fmt.Errorf("%w: operator envelope has expired", ErrUnauthenticatedCommand)
	}

	// Nonce replay (Issue #3694): single-use, independent of the outer SignedCommand's
	// own replay window (handler.go's replayCache, keyed by cmd.ID) — a captured
	// operator-signed envelope re-wrapped in a fresh outer command (new ID, new
	// timestamp) is still caught here because the nonce is bound into what the
	// operator actually signed.
	if !h.envelopeNonceCache.Add(nonce) {
		return fmt.Errorf("%w: operator envelope nonce already used", ErrUnauthenticatedCommand)
	}

	return nil
}
