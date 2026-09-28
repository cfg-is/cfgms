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

// TestUnknownModeReturnsError: an unrecognised mode string returns an error.
func TestUnknownModeReturnsError(t *testing.T) {
	b := makeTestBundle()
	enforcer := stewardtrust.NewStewardTrustEnforcer()
	err := enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustMode("unsupported"), nil)
	require.Error(t, err)
}
