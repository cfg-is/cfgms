// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Package operatorroster provides the steward-side consumer of the controller's
// signed operator-certificate revocation manifest (Issue #3699, layering onto the
// manifest introduced by Issue #3691).
//
// Prior to this package, a steward's operator-certificate verification
// (execute_script.go's verifyOperatorCert, hardened by Issues #3694/#3696) checks
// the certificate's CA chain, client-auth EKU, expiry, and payload-signing marker —
// but has no way to detect that a certificate, while still cryptographically valid,
// has since been revoked. Checking that live against the controller on every
// command would make execution availability depend on a live controller round trip
// for a case (assessed threat: a leaked/stolen operator credential) that is exactly
// when the controller may be unreachable or the connection compromised. Instead, a
// steward independently fetches and verifies the controller's signed manifest
// (features/controller/api/handlers_revocation_manifest.go) against its own pinned
// CA root — the same controllerCARoots chain-of-trust verifyOperatorCert already
// uses — and answers IsRevoked from the last manifest it verified for itself, never
// from an unsigned, live controller claim.
//
// This package cannot import features/controller/api (controller-only), so the wire
// shapes it verifies are duplicated here field-for-field, matching json tag and
// field order exactly, mirroring the same constraint and pattern already
// established by features/steward/commands/webauthn_credential_verifier.go (Issue
// #3697) for the same manifest.
package operatorroster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"crypto/x509"
	"encoding/pem"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
)

// revocationManifestKind mirrors RevocationManifestKind in
// features/controller/api/handlers_revocation_manifest.go.
const revocationManifestKind = "operator-cert-revocation"

// maxManifestBytes bounds how much of the HTTP response FetchAndVerify reads before
// giving up, so a misbehaving or compromised controller cannot force this steward to
// buffer an unbounded body in memory.
const maxManifestBytes = 4 * 1024 * 1024

// revocationManifest mirrors RevocationManifest field-for-field. Only the fields
// this package actually consumes are duplicated; AuthorizedWebAuthnCredentials and
// WebAuthnRelyingParty (Issue #3697) are that story's own concern
// (webauthn_credential_verifier.go carries its own copy) and are intentionally
// omitted here — encoding/json ignores JSON fields with no matching struct field, so
// their presence in the real payload is harmless to unmarshal.
type revocationManifest struct {
	Kind           string    `json:"kind"`
	Version        int64     `json:"version"`
	IssuedAt       time.Time `json:"issued_at"`
	RevokedSerials []string  `json:"revoked_serials"`
}

// signedRevocationManifest mirrors SignedRevocationManifest.
type signedRevocationManifest struct {
	Manifest             revocationManifest         `json:"manifest"`
	Signature            *signature.ConfigSignature `json:"signature"`
	SignerCertificatePEM string                     `json:"signer_certificate_pem"`
}

// RevocationVerifier independently verifies a controller-signed revocation manifest
// and answers IsRevoked from the last manifest it accepted for itself. It holds no
// network client of its own — FetchAndVerify takes the caller's already-configured
// mTLS *http.Client, so this package neither builds TLS material nor depends on
// features/steward/client.
type RevocationVerifier struct {
	caRoots *x509.CertPool

	mu          sync.RWMutex
	hasVerified bool
	lastVersion int64
	revoked     map[string]struct{}
}

// NewRevocationVerifier returns a RevocationVerifier that chain-verifies a
// manifest's signer against caRoots in strict mode. caRoots should be the same
// controller CA pool verifyOperatorCert already verifies operator certificates
// against — a manifest and the certificates it revokes come from the same issuing
// authority. A nil caRoots is accepted (strict-mode verification then always fails
// closed on the chain check, matching x509 verification against an empty pool)
// rather than panicking, so a steward not yet holding a usable CA bundle can still
// construct the verifier and have IsRevoked answer false until one is available.
func NewRevocationVerifier(caRoots *x509.CertPool) *RevocationVerifier {
	return &RevocationVerifier{caRoots: caRoots}
}

// VerifyManifest parses raw as a signedRevocationManifest and, depending on mode,
// independently verifies its authenticity before applying it — mirroring
// stewardtrust.StewardTrustEnforcer.VerifyForLoad's mode-dispatch structure:
//
//   - strict: the manifest's SignerCertificatePEM must chain to caRoots with a
//     CodeSigning EKU (the same purpose the controller's signing certificate is
//     issued for — features/controller/api/handlers_revocation_manifest.go's
//     signRevocationManifest), and Signature must verify against it. A manifest
//     signed by a key that does not chain to the pinned root is rejected even if
//     the controller serving it claims validity — this steward never takes the
//     controller's live word for it.
//   - controller: the manifest is applied without independently verifying its
//     signature — this steward has already decided (module_trust.mode: controller)
//     to trust the controller's own judgment for other artifacts, so it does the
//     same here. Anti-rollback still applies.
//   - bypass: a genuine no-op, matching StewardTrustEnforcer's bypass mode
//     (development use only) — the manifest is not applied and IsRevoked is
//     unaffected.
//
// In strict and controller mode, a manifest whose Version is lower than the last
// one this verifier accepted is rejected (anti-rollback): RevokedSerials only ever
// grows (features/controller/api's Manager.Revoke has no un-revoke primitive), so
// an attacker replaying an older, still-validly-signed manifest is presenting one
// that is missing revocations the steward has already learned about.
func (v *RevocationVerifier) VerifyManifest(raw []byte, mode stewardtrust.TrustMode) error {
	switch mode {
	case stewardtypes.ModuleTrustModeBypass:
		return nil
	case stewardtypes.ModuleTrustModeController, stewardtypes.ModuleTrustModeStrict:
		// fall through to the shared parse/apply path below.
	default:
		return fmt.Errorf("unknown module trust mode: %q", mode)
	}

	var manifest signedRevocationManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("invalid signed revocation manifest: %w", err)
	}
	if manifest.Manifest.Kind != revocationManifestKind {
		return fmt.Errorf("unexpected manifest kind %q", manifest.Manifest.Kind)
	}

	if mode == stewardtypes.ModuleTrustModeStrict {
		if manifest.Signature == nil {
			return fmt.Errorf("manifest carries no signature")
		}
		block, _ := pem.Decode([]byte(manifest.SignerCertificatePEM))
		if block == nil {
			return fmt.Errorf("no PEM block found in manifest signer certificate")
		}
		signerCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse manifest signer certificate: %w", err)
		}
		opts := x509.VerifyOptions{
			Roots:     v.caRoots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		if _, err := signerCert.Verify(opts); err != nil {
			return fmt.Errorf("manifest signer certificate chain verification: %w", err)
		}
		verifier, err := signature.NewVerifierFromCertificate(signerCert)
		if err != nil {
			return fmt.Errorf("construct manifest verifier: %w", err)
		}
		manifestBytes, err := json.Marshal(manifest.Manifest)
		if err != nil {
			return fmt.Errorf("marshal manifest for verification: %w", err)
		}
		if err := verifier.Verify(manifestBytes, manifest.Signature); err != nil {
			return fmt.Errorf("manifest signature verification failed: %w", err)
		}
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.hasVerified && manifest.Manifest.Version < v.lastVersion {
		return fmt.Errorf("manifest version %d is older than last-verified version %d (anti-rollback)",
			manifest.Manifest.Version, v.lastVersion)
	}
	revoked := make(map[string]struct{}, len(manifest.Manifest.RevokedSerials))
	for _, serial := range manifest.Manifest.RevokedSerials {
		revoked[serial] = struct{}{}
	}
	v.revoked = revoked
	v.lastVersion = manifest.Manifest.Version
	v.hasVerified = true
	return nil
}

// IsRevoked reports whether serial (an x509 certificate serial number in the same
// decimal string form as (*big.Int).String() — the form
// pkg/cert.Manager.Revoke/ListRevoked and x509.Certificate.SerialNumber both
// produce) appears in the last manifest this verifier successfully verified. It
// answers false, not an error, when no manifest has been verified yet — the same
// graceful-degradation choice execute_script.go's x509OperatorCredentialVerifier
// already makes when no CA roots are configured at all: this is an additional,
// defense-in-depth check layered onto verification that already independently
// confirms the certificate's chain, EKU, expiry, and payload-signing marker, not
// the only check standing between an attacker and execution.
func (v *RevocationVerifier) IsRevoked(serial string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.hasVerified {
		return false
	}
	_, revoked := v.revoked[serial]
	return revoked
}

// FetchAndVerify fetches the signed revocation manifest from manifestURL using
// httpClient (the caller's already-configured mTLS client — this package builds no
// TLS material of its own) and verifies it via VerifyManifest.
func (v *RevocationVerifier) FetchAndVerify(ctx context.Context, httpClient *http.Client, manifestURL string, mode stewardtrust.TrustMode) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return fmt.Errorf("build revocation manifest request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch revocation manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch revocation manifest: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return fmt.Errorf("read revocation manifest response: %w", err)
	}
	if len(body) > maxManifestBytes {
		return fmt.Errorf("revocation manifest response exceeds maximum allowed size")
	}
	return v.VerifyManifest(body, mode)
}

// RunPeriodicRefresh calls FetchAndVerify once immediately (fetch-on-startup) and
// then every interval until ctx is cancelled. A fetch failure is logged via logFn
// (never fatal — the steward keeps operating on whatever manifest, if any, it last
// verified) and does not stop the loop; the exact refresh interval is an
// implementation detail, not an acceptance criterion (Issue #3699). logFn may be
// nil to discard fetch errors silently.
func (v *RevocationVerifier) RunPeriodicRefresh(ctx context.Context, httpClient *http.Client, manifestURL string, mode stewardtrust.TrustMode, interval time.Duration, logFn func(err error)) {
	report := func(err error) {
		if err != nil && logFn != nil {
			logFn(err)
		}
	}
	report(v.FetchAndVerify(ctx, httpClient, manifestURL, mode))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report(v.FetchAndVerify(ctx, httpClient, manifestURL, mode))
		}
	}
}
