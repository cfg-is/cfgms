// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package osquery

import (
	"fmt"
	goruntime "runtime"

	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// PreExecVerifier re-verifies the installed osquery bundle before every osquery
// invocation, rather than only at bundle-pull time.
//
// It owns no trust scheme of its own. Verification is delegated to the ADR-006
// surfaces:
//
//  1. stewardtrust.StewardTrustEnforcer.VerifyForLoad — the steward-side pre-load
//     gate. It honours steward.cfg module_trust.mode (strict/controller/bypass)
//     and, in strict mode, checks the bundle's Ed25519 publisher signatures
//     against the trust store via pkg/modules/trust.VerifyBundleSignature. This
//     establishes that the bundle's ContentHash — the ADR-006
//     (publisher, name, version, content_hash) tuple — is publisher-signed.
//  2. bundle.VerifyInstalledContent — recomputes the content hash from the files
//     currently on disk and compares it to that signed ContentHash.
//
// Step 1 makes the expected hash a signed value instead of an unsigned local
// anchor; step 2 binds the bytes on disk to it. A binary modified after bundle
// installation therefore fails to reproduce the signed hash and is refused.
type PreExecVerifier struct {
	enforcer *stewardtrust.StewardTrustEnforcer
}

// NewPreExecVerifier returns a PreExecVerifier using the production steward
// trust enforcer (baked-in CFGMS publisher identity).
func NewPreExecVerifier() *PreExecVerifier {
	return &PreExecVerifier{enforcer: stewardtrust.NewStewardTrustEnforcer()}
}

// NewPreExecVerifierWithEnforcer returns a PreExecVerifier backed by the given
// enforcer. Tests use this with NewStewardTrustEnforcerWithIdentity to inject a
// known publisher key pair; production code uses NewPreExecVerifier.
func NewPreExecVerifierWithEnforcer(enforcer *stewardtrust.StewardTrustEnforcer) *PreExecVerifier {
	return &PreExecVerifier{enforcer: enforcer}
}

// VerifyBeforeExec verifies the osquery bundle installed at root and returns the
// on-disk path of the osquery binary for the current platform.
//
// The returned path is only ever produced after both the trust gate and the
// on-disk content re-check have passed, so a caller that invokes only the
// returned path cannot execute an unverified binary.
func (v *PreExecVerifier) VerifyBeforeExec(
	b *bundle.Bundle,
	root string,
	mode stewardtrust.TrustMode,
	additionalPublishers []stewardtrust.PublisherIdentity,
) (string, error) {
	if b == nil {
		return "", fmt.Errorf("osquery pre-exec verification: nil bundle")
	}

	// 1. Trust gate — honours module_trust.mode and the publisher trust store.
	if err := v.enforcer.VerifyForLoad(b, mode, additionalPublishers); err != nil {
		return "", fmt.Errorf("osquery bundle trust verification failed: %w", err)
	}

	// 2. On-disk content re-check — binds the installed bytes to the signed
	// ContentHash. Runs in every trust mode: even where the controller has
	// already approved the bundle, tampering after installation must be caught
	// before the binary executes.
	if err := bundle.VerifyInstalledContent(b, root); err != nil {
		return "", fmt.Errorf("osquery binary refused: %w", err)
	}

	// 3. Resolve the platform binary only after verification has succeeded.
	osArch := goruntime.GOOS + "-" + goruntime.GOARCH
	relPath, ok := b.Binaries[osArch]
	if !ok {
		return "", fmt.Errorf("osquery bundle has no binary for platform %q", osArch)
	}

	return bundle.InstalledBinaryPath(root, relPath)
}
