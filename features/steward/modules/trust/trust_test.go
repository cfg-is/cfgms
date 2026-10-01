// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	featuremodules "github.com/cfgis/cfgms/features/modules"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
)

// testEnforcer returns a StewardTrustEnforcer whose CFGMS identity uses the
// provided public key, so tests can sign bundles with the matching private key.
func testEnforcer(cfgmsPub ed25519.PublicKey) *stewardtrust.StewardTrustEnforcer {
	return stewardtrust.NewStewardTrustEnforcerWithIdentity(func() pkgtrust.PublisherIdentity {
		return pkgtrust.PublisherIdentity{
			Name:      "cfgms",
			PublicKey: []byte(cfgmsPub),
			Algorithm: "ed25519",
		}
	})
}

// signBundle signs b.ContentHash with priv and appends the signature to b.Signatures.
func signBundle(b *bundle.Bundle, publisherName string, priv ed25519.PrivateKey) {
	sig := ed25519.Sign(priv, []byte(b.ContentHash))
	b.Signatures = append(b.Signatures, bundle.BundleSignature{
		Publisher: publisherName,
		Algorithm: "ed25519",
		Signature: sig,
	})
}

func makeTestBundle() *bundle.Bundle {
	return &bundle.Bundle{
		Manifest: &featuremodules.ModuleMetadata{
			Name:      "test-module",
			Version:   "1.0.0",
			Executors: []string{"steward"},
			Kind:      "steward",
			Publisher: "test",
		},
		ContentHash: "sha256-test-content-hash-for-signing",
	}
}

// TestStrictModeAcceptsCFGMSSignedBundle: bundle signed by CFGMSPublisherIdentity
// key passes VerifyForLoad in strict mode.
func TestStrictModeAcceptsCFGMSSignedBundle(t *testing.T) {
	cfgmsPub, cfgmsPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeTestBundle()
	signBundle(b, "cfgms", cfgmsPriv)

	enforcer := testEnforcer(cfgmsPub)
	assert.NoError(t, enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeStrict, nil))
}

// TestStrictModeRejectsUnsignedBundle: bundle with no signatures fails in strict mode.
func TestStrictModeRejectsUnsignedBundle(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeTestBundle()

	enforcer := testEnforcer(cfgmsPub)
	err = enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeStrict, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, pkgtrust.ErrPublisherNotTrusted)
}

// TestStrictModeRejectsUnknownPublisher: bundle signed by an unknown publisher
// is rejected with ErrPublisherNotTrusted.
func TestStrictModeRejectsUnknownPublisher(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, unknownPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeTestBundle()
	signBundle(b, "unknown-vendor", unknownPriv)

	enforcer := testEnforcer(cfgmsPub)
	err = enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeStrict, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, pkgtrust.ErrPublisherNotTrusted)
}

// TestControllerModePassesUnsignedBundle: controller mode is a no-op.
func TestControllerModePassesUnsignedBundle(t *testing.T) {
	b := makeTestBundle()
	enforcer := stewardtrust.NewStewardTrustEnforcer()
	assert.NoError(t, enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeController, nil))
}

// TestBypassModePassesUnsignedBundle: bypass mode is a no-op.
func TestBypassModePassesUnsignedBundle(t *testing.T) {
	b := makeTestBundle()
	enforcer := stewardtrust.NewStewardTrustEnforcer()
	assert.NoError(t, enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeBypass, nil))
}

// TestStrictModeAcceptsAdditionalPublisher: bundle signed by a publisher in
// additionalPublishers passes in strict mode.
func TestStrictModeAcceptsAdditionalPublisher(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	extraPub, extraPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeTestBundle()
	signBundle(b, "extra-vendor", extraPriv)

	enforcer := testEnforcer(cfgmsPub)
	additional := []stewardtrust.PublisherIdentity{
		{Name: "extra-vendor", PublicKey: []byte(extraPub), Algorithm: "ed25519"},
	}
	assert.NoError(t, enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeStrict, additional))
}

// [REQUIRED TEST] TestStrictModeAdditionalPublisherCannotDisplaceCFGMSIdentity
// verifies Issue #4324 item 3: an additional publisher named the same as the
// baked-in CFGMS identity ("cfgms") must not change the key a bundle is
// verified against. Before the fix, verifyStrict added the baked-in identity
// first and then looped additionalPublishers into the same map-backed store,
// discarding AddPublisher's return value — a same-named additional publisher
// silently overwrote the baked-in entry.
func TestStrictModeAdditionalPublisherCannotDisplaceCFGMSIdentity(t *testing.T) {
	cfgmsPub, cfgmsPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// The attacker controls a distinct keypair but registers it under the
	// baked-in publisher's own name.
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NotEqual(t, []byte(cfgmsPub), []byte(attackerPub))

	colliding := []stewardtrust.PublisherIdentity{
		{Name: "cfgms", PublicKey: []byte(attackerPub), Algorithm: "ed25519"},
	}
	enforcer := testEnforcer(cfgmsPub)

	// A bundle signed by the real CFGMS key must still verify: the colliding
	// additional publisher did not displace the baked-in identity.
	genuine := makeTestBundle()
	signBundle(genuine, "cfgms", cfgmsPriv)
	assert.NoError(t, enforcer.VerifyForLoad(genuine, stewardtypes.ModuleTrustModeStrict, colliding),
		"a bundle signed by the real baked-in CFGMS key must still verify")

	// A bundle signed by the attacker's colliding key must NOT verify — if the
	// attacker's key had displaced the baked-in identity, this would pass
	// (store.GetPublisher("cfgms") would return the attacker's key instead of
	// rejecting the signature as invalid against the real one).
	forged := makeTestBundle()
	signBundle(forged, "cfgms", attackerPriv)
	err = enforcer.VerifyForLoad(forged, stewardtypes.ModuleTrustModeStrict, colliding)
	require.Error(t, err, "a bundle signed by the colliding additional publisher's key must not verify")
	assert.ErrorIs(t, err, pkgtrust.ErrInvalidSignature)
}

// [REQUIRED TEST] TestResolveAdditionalPublishers_KnownNameLoadsUnderStrict:
// a bundle signed by a publisher listed in additional_publishers, whose key
// material is present in the enforcer's known-publisher registry, resolves and
// then loads under module_trust.mode: strict (Issue #4398).
func TestResolveAdditionalPublishers_KnownNameLoadsUnderStrict(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	extraPub, extraPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	enforcer := stewardtrust.NewStewardTrustEnforcerWithKnownPublishers(
		func() pkgtrust.PublisherIdentity {
			return pkgtrust.PublisherIdentity{Name: "cfgms", PublicKey: []byte(cfgmsPub), Algorithm: "ed25519"}
		},
		map[string]pkgtrust.PublisherIdentity{
			"extra-vendor": {Name: "extra-vendor", PublicKey: []byte(extraPub), Algorithm: "ed25519"},
		},
	)

	resolved, err := enforcer.ResolveAdditionalPublishers([]string{"extra-vendor"})
	require.NoError(t, err)

	b := makeTestBundle()
	signBundle(b, "extra-vendor", extraPriv)
	assert.NoError(t, enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeStrict, resolved))
}

// [REQUIRED TEST] TestResolveAdditionalPublishers_NotListedNameIsRejected: the
// same bundle/publisher as above is refused under strict mode when the
// publisher's name is NOT included in the additional_publishers list passed to
// ResolveAdditionalPublishers — the registry knowing about a publisher is not
// enough; the config must actually list it.
func TestResolveAdditionalPublishers_NotListedNameIsRejected(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	extraPub, extraPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	enforcer := stewardtrust.NewStewardTrustEnforcerWithKnownPublishers(
		func() pkgtrust.PublisherIdentity {
			return pkgtrust.PublisherIdentity{Name: "cfgms", PublicKey: []byte(cfgmsPub), Algorithm: "ed25519"}
		},
		map[string]pkgtrust.PublisherIdentity{
			"extra-vendor": {Name: "extra-vendor", PublicKey: []byte(extraPub), Algorithm: "ed25519"},
		},
	)

	// additional_publishers is empty: "extra-vendor" is known to the registry
	// but never named by the operator.
	resolved, err := enforcer.ResolveAdditionalPublishers(nil)
	require.NoError(t, err)

	b := makeTestBundle()
	signBundle(b, "extra-vendor", extraPriv)
	err = enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeStrict, resolved)
	require.Error(t, err)
	assert.ErrorIs(t, err, pkgtrust.ErrPublisherNotTrusted)
}

// [REQUIRED TEST] TestResolveAdditionalPublishers_UnresolvableNameNamesEntryInError:
// an additional_publishers entry with no resolvable key material refuses
// resolution, naming the entry in the error, rather than being dropped or
// falling through to the compiled-in CFGMS publisher only.
func TestResolveAdditionalPublishers_UnresolvableNameNamesEntryInError(t *testing.T) {
	// The production resolver (no known-publishers override) has an empty
	// compiled-in registry, so every name is unresolvable.
	enforcer := stewardtrust.NewStewardTrustEnforcer()

	_, err := enforcer.ResolveAdditionalPublishers([]string{"never-heard-of-this-vendor"})
	require.Error(t, err)
	assert.ErrorIs(t, err, stewardtrust.ErrAdditionalPublisherUnresolvable)
	assert.Contains(t, err.Error(), "never-heard-of-this-vendor")
}

// [REQUIRED TEST] TestResolveAdditionalPublishers_CollidingNameCannotDisplaceCFGMSIdentity
// pins Issue #4324's protection against the new resolution path introduced by
// #4398: an additional_publishers name that resolves to key material under the
// baked-in CFGMS identity's own name ("cfgms") must not let that resolved
// identity displace the real one during verification.
func TestResolveAdditionalPublishers_CollidingNameCannotDisplaceCFGMSIdentity(t *testing.T) {
	cfgmsPub, cfgmsPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NotEqual(t, []byte(cfgmsPub), []byte(attackerPub))

	enforcer := stewardtrust.NewStewardTrustEnforcerWithKnownPublishers(
		func() pkgtrust.PublisherIdentity {
			return pkgtrust.PublisherIdentity{Name: "cfgms", PublicKey: []byte(cfgmsPub), Algorithm: "ed25519"}
		},
		map[string]pkgtrust.PublisherIdentity{
			// The registry itself resolves "cfgms" to the attacker's key — as if
			// an operator mistakenly (or maliciously) listed "cfgms" in
			// additional_publishers and a colliding entry existed to resolve it.
			"cfgms": {Name: "cfgms", PublicKey: []byte(attackerPub), Algorithm: "ed25519"},
		},
	)

	resolved, err := enforcer.ResolveAdditionalPublishers([]string{"cfgms"})
	require.NoError(t, err)

	genuine := makeTestBundle()
	signBundle(genuine, "cfgms", cfgmsPriv)
	assert.NoError(t, enforcer.VerifyForLoad(genuine, stewardtypes.ModuleTrustModeStrict, resolved),
		"a bundle signed by the real baked-in CFGMS key must still verify")

	forged := makeTestBundle()
	signBundle(forged, "cfgms", attackerPriv)
	err = enforcer.VerifyForLoad(forged, stewardtypes.ModuleTrustModeStrict, resolved)
	require.Error(t, err, "a bundle signed by the colliding resolved publisher's key must not verify")
	assert.ErrorIs(t, err, pkgtrust.ErrInvalidSignature)
}

// TestUnknownModeReturnsError: an unrecognised mode string returns an error.
func TestUnknownModeReturnsError(t *testing.T) {
	b := makeTestBundle()
	enforcer := stewardtrust.NewStewardTrustEnforcer()
	err := enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustMode("unsupported"), nil)
	require.Error(t, err)
}

// [REQUIRED TEST] TestVerifyForLoad_UnknownModeRefusedOutright pins the second
// of the two gates an unrecognised module_trust.mode must be refused at
// (Issue #4426 AC): ValidateModuleTrustConfig refuses it at config load
// (features/config/stewardtypes/validation_test.go pins that gate), and
// VerifyForLoad's default arm must independently refuse it at load time too —
// so a future config path that skips validation still fails closed here,
// rather than an unrecognised value silently falling through to the
// bypass/controller no-op arm. The error must name the offending value so an
// operator can act on it, and must not be pkgtrust.ErrPublisherNotTrusted (a
// strict-mode verification failure) — a distinct failure mode.
func TestVerifyForLoad_UnknownModeRefusedOutright(t *testing.T) {
	b := makeTestBundle()
	enforcer := stewardtrust.NewStewardTrustEnforcer()

	err := enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustMode("bogus"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown module trust mode")
	assert.Contains(t, err.Error(), "bogus")
	assert.NotErrorIs(t, err, pkgtrust.ErrPublisherNotTrusted)
}
