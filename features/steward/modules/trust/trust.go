// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package trust enforces module trust policy on behalf of the steward runtime.
// It bridges steward.cfg ModuleTrustMode settings with the cryptographic
// verification primitives in pkg/modules/trust.
package trust

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
)

// TrustMode aliases stewardtypes.ModuleTrustMode for use in the runtime API.
type TrustMode = stewardtypes.ModuleTrustMode

// PublisherIdentity aliases the pkg-level type for use in the runtime API.
type PublisherIdentity = pkgtrust.PublisherIdentity

// ed25519PublicKeySize duplicates crypto/ed25519.PublicKeySize to avoid pulling
// in the crypto/ed25519 import solely for a size constant.
const ed25519PublicKeySize = 32

// additionalPublisherKeyMaterial is a compiled-in registry of third-party
// publisher name -> base64-encoded Ed25519 public key pairs, injected by the
// release pipeline via -ldflags:
//
//	go build -ldflags "-X .../trust.additionalPublisherKeyMaterial=name1=<b64key1>,name2=<b64key2>"
//
// mirroring pkg/modules/trust.cfgmsPublisherPublicKey. Per ADR-006, publisher
// key material is baked into the steward binary at build time and never
// injected via steward.cfg or any other runtime configuration path — this
// variable, not the config file, is additional_publishers' only legitimate
// source of key material. Empty by default: an unconfigured build has no known
// additional publishers, so any additional_publishers entry fails resolution
// with a named error rather than silently granting no trust.
var additionalPublisherKeyMaterial = ""

// ErrAdditionalPublisherUnresolvable is returned by ResolveAdditionalPublishers
// when a configured additional_publishers name has no known key material.
// Dropping the name silently, or falling through to the compiled-in CFGMS
// publisher only, would narrow trust without telling the operator — the exact
// bug this resolution step exists to close (Issue #4398).
var ErrAdditionalPublisherUnresolvable = errors.New("additional_publishers entry could not be resolved to key material")

// defaultResolveKnownPublisher resolves name against the compiled-in
// additionalPublisherKeyMaterial registry described above.
func defaultResolveKnownPublisher(name string) (pkgtrust.PublisherIdentity, bool) {
	// An empty name is never resolvable: without this guard a malformed registry
	// entry whose name half is empty ("=<b64key>") would match an empty
	// additional_publishers entry and grant trust to key material the operator
	// never named.
	if name == "" || additionalPublisherKeyMaterial == "" {
		return pkgtrust.PublisherIdentity{}, false
	}
	for _, entry := range strings.Split(additionalPublisherKeyMaterial, ",") {
		entryName, b64Key, ok := strings.Cut(entry, "=")
		if !ok || entryName != name {
			continue
		}
		keyBytes, err := base64.StdEncoding.DecodeString(b64Key)
		if err != nil || len(keyBytes) != ed25519PublicKeySize {
			return pkgtrust.PublisherIdentity{}, false
		}
		return pkgtrust.PublisherIdentity{Name: name, PublicKey: keyBytes, Algorithm: "ed25519"}, true
	}
	return pkgtrust.PublisherIdentity{}, false
}

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

	// resolveKnownPublisher resolves an additional_publishers name to key
	// material. Production code walks the compiled-in
	// additionalPublisherKeyMaterial registry; tests inject a known set via
	// NewStewardTrustEnforcerWithKnownPublishers.
	resolveKnownPublisher func(name string) (pkgtrust.PublisherIdentity, bool)
}

// NewStewardTrustEnforcer returns a production-ready StewardTrustEnforcer that
// uses the baked-in CFGMS publisher identity from the build pipeline.
func NewStewardTrustEnforcer() *StewardTrustEnforcer {
	return &StewardTrustEnforcer{
		getCFGMSIdentity:      pkgtrust.CFGMSPublisherIdentity,
		resolveKnownPublisher: defaultResolveKnownPublisher,
	}
}

// NewStewardTrustEnforcerWithIdentity returns a StewardTrustEnforcer that calls
// identityFn to obtain the CFGMS publisher identity. Use in tests to inject a
// known key pair; use NewStewardTrustEnforcer in production code.
func NewStewardTrustEnforcerWithIdentity(identityFn func() pkgtrust.PublisherIdentity) *StewardTrustEnforcer {
	return &StewardTrustEnforcer{
		getCFGMSIdentity:      identityFn,
		resolveKnownPublisher: defaultResolveKnownPublisher,
	}
}

// NewStewardTrustEnforcerWithKnownPublishers returns a StewardTrustEnforcer
// that resolves additional_publishers names against knownPublishers instead of
// the compiled-in registry. Tests use this to inject known key material for a
// given publisher name without an ldflags-injected build; production code uses
// NewStewardTrustEnforcer or NewStewardTrustEnforcerWithIdentity.
func NewStewardTrustEnforcerWithKnownPublishers(
	identityFn func() pkgtrust.PublisherIdentity,
	knownPublishers map[string]pkgtrust.PublisherIdentity,
) *StewardTrustEnforcer {
	return &StewardTrustEnforcer{
		getCFGMSIdentity: identityFn,
		resolveKnownPublisher: func(name string) (pkgtrust.PublisherIdentity, bool) {
			id, ok := knownPublishers[name]
			return id, ok
		},
	}
}

// ResolveAdditionalPublishers converts steward.cfg's additional_publishers name
// list into PublisherIdentity values carrying key material, using the
// enforcer's known-publisher registry (compiled-in for production; injected for
// tests). Callers must invoke this only for module_trust.mode: strict — the
// only mode that consults additional_publishers.
//
// A name with no matching entry refuses resolution, naming the offending entry
// in the returned error. It must never be dropped silently or fall through to
// "compiled-in CFGMS publisher only": either behavior would silently narrow
// trust instead of honoring what the operator configured, which is the bug
// this resolution step exists to fix (Issue #4398).
func (e *StewardTrustEnforcer) ResolveAdditionalPublishers(names []string) ([]PublisherIdentity, error) {
	if len(names) == 0 {
		return nil, nil
	}
	resolved := make([]PublisherIdentity, 0, len(names))
	for _, name := range names {
		id, ok := e.resolveKnownPublisher(name)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrAdditionalPublisherUnresolvable, name)
		}
		resolved = append(resolved, id)
	}
	return resolved, nil
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

	// The baked-in CFGMS publisher identity is registered first and can never
	// be displaced: AddPublisher rejects any later registration under the same
	// name, so a supplied additional publisher sharing that name is dropped
	// below rather than silently overwriting the trust anchor (Issue #4324).
	cfgmsIdentity := e.getCFGMSIdentity()
	if err := store.AddPublisher(cfgmsIdentity); err != nil {
		return fmt.Errorf("register baked-in CFGMS publisher identity: %w", err)
	}

	for _, pub := range additionalPublishers {
		if err := store.AddPublisher(pub); err != nil {
			// A colliding or duplicate publisher name must not abort strict
			// verification for every other bundle — the baked-in identity
			// registered above stays authoritative for that name; only the
			// colliding entry is dropped.
			continue
		}
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
