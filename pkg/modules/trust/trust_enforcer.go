// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package trust

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// TrustMode aliases stewardtypes.ModuleTrustMode for use in the runtime API.
type TrustMode = stewardtypes.ModuleTrustMode

// ed25519PublicKeySize duplicates crypto/ed25519.PublicKeySize to avoid pulling
// in the crypto/ed25519 import solely for a size constant.
const ed25519PublicKeySize = 32

// additionalPublisherKeyMaterial is a compiled-in registry of third-party
// publisher name -> base64-encoded Ed25519 public key pairs, injected by the
// release pipeline via -ldflags:
//
//	go build -ldflags "-X github.com/cfgis/cfgms/pkg/modules/trust.additionalPublisherKeyMaterial=name1=<b64key1>,name2=<b64key2>"
//
// mirroring cfgmsPublisherPublicKey. The Makefile variable
// STEWARD_ADDITIONAL_PUBLISHER_KEYS supplies this value. Per ADR-006, publisher
// key material is baked into the steward binary at build time and never
// injected via steward.cfg or any other runtime configuration path — this
// variable, not the config file, is additional_publishers' only legitimate
// source of key material. Empty by default: an unconfigured build has no known
// additional publishers, so any additional_publishers entry fails resolution
// with a named error rather than silently granting no trust.
var additionalPublisherKeyMaterial = ""

// reservedPublisherName is the name of the baked-in CFGMS publisher; an
// additional publisher may not claim it.
const reservedPublisherName = "cfgms"

// ErrAdditionalPublisherUnresolvable is returned by ResolveAdditionalPublishers
// when a configured additional_publishers name has no known key material.
// Dropping the name silently, or falling through to the compiled-in CFGMS
// publisher only, would narrow trust without telling the operator — the exact
// bug this resolution step exists to close (Issue #4398).
var ErrAdditionalPublisherUnresolvable = errors.New("additional_publishers entry could not be resolved to key material")

// registryEntryKey parses one "name=base64key" registry entry. named reports
// whether the entry's name half equals name; keyBytes is the decoded key, or nil
// when the entry is named but its key is not valid base64 or not an Ed25519
// public key size.
func registryEntryKey(entry, name string) (keyBytes []byte, named bool) {
	entryName, b64Key, ok := strings.Cut(entry, "=")
	if !ok || entryName != name {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil || len(decoded) != ed25519PublicKeySize {
		return nil, true
	}
	return decoded, true
}

// defaultResolveKnownPublisher resolves name against the compiled-in
// additionalPublisherKeyMaterial registry described above.
func defaultResolveKnownPublisher(name string) (PublisherIdentity, bool) {
	// An empty name is never resolvable: without this guard a malformed registry
	// entry whose name half is empty ("=<b64key>") would match an empty
	// additional_publishers entry and grant trust to key material the operator
	// never named. The reserved name "cfgms" belongs to the baked-in CFGMS key.
	if name == "" || name == reservedPublisherName || additionalPublisherKeyMaterial == "" {
		return PublisherIdentity{}, false
	}
	var found PublisherIdentity
	matches := 0
	for _, entry := range strings.Split(additionalPublisherKeyMaterial, ",") {
		keyBytes, named := registryEntryKey(entry, name)
		if !named {
			continue
		}
		matches++
		if keyBytes == nil {
			continue
		}
		found = PublisherIdentity{Name: name, PublicKey: keyBytes, Algorithm: "ed25519"}
	}
	// A name listed more than once is ambiguous: which key anchors trust would
	// depend on list order, so it never resolves. A key that is a small-order
	// point (including the all-zero placeholder) would accept forged signatures,
	// so it never anchors trust either.
	if matches != 1 || !IsUsableIdentityKey(found) {
		return PublisherIdentity{}, false
	}
	return found, true
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
	// Production code uses CFGMSPublisherIdentity(); tests inject a
	// known key pair via NewStewardTrustEnforcerWithIdentity.
	getCFGMSIdentity func() PublisherIdentity

	// resolveKnownPublisher resolves an additional_publishers name to key
	// material. Production code walks the compiled-in
	// additionalPublisherKeyMaterial registry; tests inject a known set via
	// NewStewardTrustEnforcerWithKnownPublishers.
	resolveKnownPublisher func(name string) (PublisherIdentity, bool)
}

// NewStewardTrustEnforcer returns a production-ready StewardTrustEnforcer that
// uses the baked-in CFGMS publisher identity from the build pipeline.
func NewStewardTrustEnforcer() *StewardTrustEnforcer {
	return &StewardTrustEnforcer{
		getCFGMSIdentity:      CFGMSPublisherIdentity,
		resolveKnownPublisher: defaultResolveKnownPublisher,
	}
}

// NewStewardTrustEnforcerWithIdentity returns a StewardTrustEnforcer that calls
// identityFn to obtain the CFGMS publisher identity. Use in tests to inject a
// known key pair; use NewStewardTrustEnforcer in production code.
func NewStewardTrustEnforcerWithIdentity(identityFn func() PublisherIdentity) *StewardTrustEnforcer {
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
	identityFn func() PublisherIdentity,
	knownPublishers map[string]PublisherIdentity,
) *StewardTrustEnforcer {
	return &StewardTrustEnforcer{
		getCFGMSIdentity: identityFn,
		resolveKnownPublisher: func(name string) (PublisherIdentity, bool) {
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
//   - bypass: no-op in a cfgms_dev_bypass build (development use only); an
//     error in every other build.
func (e *StewardTrustEnforcer) VerifyForLoad(b *bundle.Bundle, mode TrustMode, additionalPublishers []PublisherIdentity) error {
	switch mode {
	case stewardtypes.ModuleTrustModeController:
		return nil
	case stewardtypes.ModuleTrustModeBypass:
		if !stewardtypes.ModuleTrustBypassAllowed() {
			return fmt.Errorf("module trust mode %q is unavailable in a release build", mode)
		}
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
	store := NewInMemoryTrustStore()

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
		return fmt.Errorf("%w: bundle %q has no signatures", ErrPublisherNotTrusted, bundleName)
	}

	var lastErr error
	for _, sig := range b.Signatures {
		if err := VerifyBundleSignature(b, sig, store); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}
