// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package commands

import (
	"fmt"
	"slices"
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
// The execution context is part of the signed bytes too: it is rebuilt from the
// command's execution_context param (a string; absent means empty), so a delivered
// run-as context the operator did not sign fails signature verification, and a
// non-string value is refused. steward_action and open_terminal carry none and verify
// with an empty context.
//
// Every failure wraps ErrUnauthenticatedCommand.
func (h *Handler) verifyOperatorEnvelope(cmd *cpTypes.Command, content []byte, shell string) error {
	proof, err := readOperatorProof(cmd)
	if err != nil {
		return err
	}
	envelope, err := proof.envelope(cmd, content, shell)
	if err != nil {
		return err
	}

	roots, intermediates, revocation, err := h.operatorTrust(cmd)
	if err != nil {
		return err
	}
	if proof.hasSig {
		err = h.verifyX509OperatorSignature(roots, intermediates, revocation, envelope, shell,
			proof.sigAlgorithm, proof.sigValue, proof.sigPublicKey)
	} else {
		err = h.verifyWebAuthnOperatorSignature(roots, intermediates, envelope,
			proof.webauthnAuthDataB64, proof.webauthnClientDataB64, proof.webauthnSigB64, proof.webauthnCredIDB64, proof.webauthnManifestJSON)
	}
	if err != nil {
		return err
	}
	return h.checkEnvelopeBinding(envelope)
}

// operatorProof is the credential half of an operator envelope as it arrives in
// command params.
type operatorProof struct {
	sigAlgorithm, sigValue, sigPublicKey string
	hasSig                               bool

	webauthnAuthDataB64, webauthnClientDataB64, webauthnSigB64, webauthnCredIDB64, webauthnManifestJSON string
}

// readOperatorProof extracts the X.509 or WebAuthn proof params; neither present
// is an unauthenticated command.
func readOperatorProof(cmd *cpTypes.Command) (*operatorProof, error) {
	p := &operatorProof{
		sigAlgorithm:          stringParam(cmd, "signature_algorithm"),
		sigValue:              stringParam(cmd, "signature_value"),
		sigPublicKey:          stringParam(cmd, "signature_public_key"),
		webauthnAuthDataB64:   stringParam(cmd, "webauthn_authenticator_data"),
		webauthnClientDataB64: stringParam(cmd, "webauthn_client_data_json"),
		webauthnSigB64:        stringParam(cmd, "webauthn_signature"),
		webauthnCredIDB64:     stringParam(cmd, "webauthn_credential_id"),
		webauthnManifestJSON:  stringParam(cmd, "webauthn_manifest"),
	}
	p.hasSig = hasX509Proof(cmd)
	if !p.hasSig && !hasWebAuthnProof(cmd) {
		return nil, ErrUnauthenticatedCommand
	}
	return p, nil
}

// envelope rebuilds the signed envelope from content, shell and the command's
// targets, nonce, expires_at and execution_context params.
func (p *operatorProof) envelope(cmd *cpTypes.Command, content []byte, shell string) (operatorpayload.Envelope, error) {
	expiresAt, err := time.Parse(time.RFC3339, stringParam(cmd, "expires_at"))
	if err != nil {
		return operatorpayload.Envelope{}, fmt.Errorf("%w: missing or invalid operator envelope expiry", ErrUnauthenticatedCommand)
	}
	executionContext := ""
	if v, present := cmd.Params["execution_context"]; present {
		s, ok := v.(string)
		if !ok {
			return operatorpayload.Envelope{}, fmt.Errorf("%w: execution_context must be a string", ErrUnauthenticatedCommand)
		}
		executionContext = s
	}
	return operatorpayload.Envelope{
		Content:          content,
		Shell:            shell,
		Targets:          extractStringSlice(cmd.Params["targets"]),
		Nonce:            stringParam(cmd, "nonce"),
		ExpiresAt:        expiresAt,
		ExecutionContext: executionContext,
	}, nil
}

// checkEnvelopeBinding applies, after the signature verified:
//   - target-set binding (Issue #3694): this steward's own ID must be among the
//     resolved, signed target list, so a legitimately-signed envelope re-addressed
//     to a different target set in transit does not authorize execution here;
//   - expiry (Issue #3694): an envelope past its bound validity window is rejected;
//   - nonce replay (Issue #3694): single-use, independent of the outer
//     SignedCommand's own replay window (handler.go's replayCache, keyed by
//     cmd.ID). A captured operator-signed envelope re-wrapped in a fresh outer
//     command (new ID, new timestamp) is still caught here because the nonce is
//     bound into what the operator actually signed.
func (h *Handler) checkEnvelopeBinding(envelope operatorpayload.Envelope) error {
	if !slices.Contains(envelope.Targets, h.stewardID) {
		return fmt.Errorf("%w: steward is not in the signed target list", ErrUnauthenticatedCommand)
	}
	if time.Now().After(envelope.ExpiresAt) {
		return fmt.Errorf("%w: operator envelope has expired", ErrUnauthenticatedCommand)
	}
	if !h.envelopeNonceCache.Add(envelope.Nonce) {
		return fmt.Errorf("%w: operator envelope nonce already used", ErrUnauthenticatedCommand)
	}
	return nil
}
