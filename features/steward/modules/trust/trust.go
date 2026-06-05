// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package trust enforces module trust policy on behalf of the steward runtime.
// It bridges steward.cfg ModuleTrustMode settings with the cryptographic
// verification primitives in pkg/modules/trust.
package trust

import (
	"fmt"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
)

// TrustMode aliases stewardtypes.ModuleTrustMode for use in the runtime API.
type TrustMode = stewardtypes.ModuleTrustMode

// PublisherIdentity aliases the pkg-level type for use in the runtime API.
type PublisherIdentity = pkgtrust.PublisherIdentity

// StewardTrustEnforcer enforces module trust policy before the steward runtime
// fork/execs a module binary.
//
// In strict mode, the bundle must carry at least one signature verifiable
// against the set of trusted publishers: CFGMSPublisherIdentity() (baked-in at
// build time) plus any additional publishers supplied by the caller.
//
// In controller or bypass mode, no verification is performed.
type StewardTrustEnforcer struct {
	// getCFGMSIdentity returns the CFGMS publisher identity used in strict mode.
	// Production code uses pkgtrust.CFGMSPublisherIdentity(); tests inject a
	// known key pair via NewStewardTrustEnforcerWithIdentity.
	getCFGMSIdentity func() pkgtrust.PublisherIdentity
}

// NewStewardTrustEnforcer returns a production-ready StewardTrustEnforcer that
// uses the baked-in CFGMS publisher identity from the build pipeline.
func NewStewardTrustEnforcer() *StewardTrustEnforcer {
	return &StewardTrustEnforcer{
		getCFGMSIdentity: pkgtrust.CFGMSPublisherIdentity,
	}
}

// NewStewardTrustEnforcerWithIdentity returns a StewardTrustEnforcer that calls
// identityFn to obtain the CFGMS publisher identity. Use in tests to inject a
// known key pair; use NewStewardTrustEnforcer in production code.
func NewStewardTrustEnforcerWithIdentity(identityFn func() pkgtrust.PublisherIdentity) *StewardTrustEnforcer {
	return &StewardTrustEnforcer{
		getCFGMSIdentity: identityFn,
	}
}

// VerifyForLoad checks whether bundle b may be loaded under the given trust mode.
//
//   - strict: the bundle must carry at least one Ed25519 signature that
//     verifies against the CFGMS publisher identity or any additionalPublishers.
//   - controller: no-op (the controller has already approved the bundle).
//   - bypass: no-op (development use only).
func (e *StewardTrustEnforcer) VerifyForLoad(b *bundle.Bundle, mode TrustMode, additionalPublishers []PublisherIdentity) error {
	switch mode {
	case stewardtypes.ModuleTrustModeController, stewardtypes.ModuleTrustModeBypass:
		return nil
	case stewardtypes.ModuleTrustModeStrict:
		return e.verifyStrict(b, additionalPublishers)
	default:
		return fmt.Errorf("unknown module trust mode: %q", mode)
	}
}

// verifyStrict verifies that at least one bundle signature matches a trusted
// publisher (CFGMS identity or additionalPublishers).
func (e *StewardTrustEnforcer) verifyStrict(b *bundle.Bundle, additionalPublishers []PublisherIdentity) error {
	store := pkgtrust.NewInMemoryTrustStore()

	// Always include the baked-in CFGMS publisher identity.
	_ = store.AddPublisher(e.getCFGMSIdentity())

	// TODO: v2 — resolve additional_publishers names to key material from trust store
	for _, pub := range additionalPublishers {
		_ = store.AddPublisher(pub)
	}

	bundleName := ""
	if b.Manifest != nil {
		bundleName = b.Manifest.Name
	}

	if len(b.Signatures) == 0 {
		return fmt.Errorf("%w: bundle %q has no signatures", pkgtrust.ErrPublisherNotTrusted, bundleName)
	}

	var lastErr error
	for _, sig := range b.Signatures {
		if err := pkgtrust.VerifyBundleSignature(b, sig, store); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}
