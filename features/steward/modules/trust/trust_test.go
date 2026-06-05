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

// TestUnknownModeReturnsError: an unrecognised mode string returns an error.
func TestUnknownModeReturnsError(t *testing.T) {
	b := makeTestBundle()
	enforcer := stewardtrust.NewStewardTrustEnforcer()
	err := enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustMode("unsupported"), nil)
	require.Error(t, err)
}
