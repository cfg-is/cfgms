// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cfgis/cfgms/pkg/cert"
)

// buildWebAuthnManifestForSteward returns the CA-signed WebAuthn roster manifest JSON
// (a SignedRevocationManifest) a steward needs to independently re-verify a
// WebAuthn-signed operator envelope, for attaching to the forwarded command as
// "webauthn_manifest". The roster is narrowed to the operators whose tenant scope covers
// the steward, exactly as handleGetStewardRevocationManifest does.
//
// It is built at API enqueue time; the steward's webauthnManifestMaxAge (15 minutes)
// comfortably covers the queue dwell. The controller signs the manifest only; the
// operator's assertion is forwarded intact and never re-signed or stripped.
func (s *Server) buildWebAuthnManifestForSteward(ctx context.Context, stewardID string) (string, error) {
	if s.certManager == nil {
		return "", fmt.Errorf("certificate manager not available")
	}
	if s.controllerService == nil {
		return "", fmt.Errorf("steward registry not available")
	}
	info, known := s.controllerService.GetStewardInfo(stewardID)
	if !known {
		return "", fmt.Errorf("steward is not registered")
	}
	if _, terminal := terminalStewardManifestStatuses[info.Status]; terminal {
		return "", fmt.Errorf("steward is in a terminal status")
	}

	manifest, err := buildRevocationManifest(s.certManager)
	if err != nil {
		return "", err
	}
	creds, err := s.buildAuthorizedWebAuthnCredentials(ctx)
	if err != nil {
		return "", err
	}
	manifest.AuthorizedWebAuthnCredentials = s.filterWebAuthnCredentialsForSteward(ctx, creds, info.TenantID)
	manifest.WebAuthnRelyingParty = s.webAuthnRelyingPartyBinding()

	sig, err := signRevocationManifest(s.certManager, manifest)
	if err != nil {
		return "", err
	}
	signingCert, err := s.certManager.GetCurrentCertForPurpose(cert.PurposeSigning)
	if err != nil {
		return "", fmt.Errorf("get signing certificate: %w", err)
	}
	out, err := json.Marshal(SignedRevocationManifest{
		Manifest:             *manifest,
		Signature:            sig,
		SignerCertificatePEM: string(signingCert.CertificatePEM),
	})
	if err != nil {
		return "", fmt.Errorf("marshal manifest: %w", err)
	}
	return string(out), nil
}
