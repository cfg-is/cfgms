// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

// This file is kept separate from runtime_test.go (Issue #4393 owns that file
// for an unrelated Windows transport fix) so the two stories' changes never
// touch the same file.
package runtime_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/modules/runtime"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
)

// testEnforcerRuntimeWithKnownPublishers returns a ModuleRuntime whose trust
// enforcer uses cfgmsPub as the CFGMS identity and resolves
// additional_publishers names against knownPublishers, standing in for the
// ldflags-injected compiled-in registry that production builds carry.
func testEnforcerRuntimeWithKnownPublishers(
	t *testing.T,
	cfgmsPub ed25519.PublicKey,
	knownPublishers map[string]pkgtrust.PublisherIdentity,
) *runtime.ModuleRuntime {
	t.Helper()
	return runtime.NewModuleRuntimeWithEnforcer(
		shortBaseDir(t),
		stewardtrust.NewStewardTrustEnforcerWithKnownPublishers(
			func() pkgtrust.PublisherIdentity {
				return pkgtrust.PublisherIdentity{
					Name:      "cfgms",
					PublicKey: []byte(cfgmsPub),
					Algorithm: "ed25519",
				}
			},
			knownPublishers,
		),
	)
}

// TestStrictModeAcceptsBundleSignedByResolvedAdditionalPublisher exercises the
// success path of Start's additional_publishers resolution branch: a strict-mode
// steward configured with a resolvable additional_publishers name must load a
// bundle signed by that publisher alone (no CFGMS signature present), and the
// module must reach a working gRPC session.
func TestStrictModeAcceptsBundleSignedByResolvedAdditionalPublisher(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	vendorPub, vendorPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeBypassBundle(echoModuleBin)
	b.Manifest.Publisher = "vendor-a"
	sig := ed25519.Sign(vendorPriv, []byte(b.ContentHash))
	b.Signatures = []bundle.BundleSignature{
		{Publisher: "vendor-a", Algorithm: "ed25519", Signature: sig},
	}

	rt := testEnforcerRuntimeWithKnownPublishers(t, cfgmsPub, map[string]pkgtrust.PublisherIdentity{
		"vendor-a": {Name: "vendor-a", PublicKey: []byte(vendorPub), Algorithm: "ed25519"},
	})

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeStrict, []string{"vendor-a"})
	require.NoError(t, err, "a resolvable additional publisher must be trusted in strict mode")
	require.NotNil(t, handle)
	assert.Equal(t, runtime.StateRunning, handle.GetState())

	resp, err := handle.Client.Get(context.Background(), &proto.GetRequest{ResourceId: "vendor-signed"})
	require.NoError(t, err)
	assert.Equal(t, "echo:vendor-signed", resp.ConfigData)

	require.NoError(t, rt.Stop(handle))
}

// TestStrictModeRejectsUnresolvableAdditionalPublisher exercises the failure
// path of Start's resolution branch. The bundle is signed by the CFGMS identity,
// so VerifyForLoad would accept it; Start must still fail with
// ErrAdditionalPublisherUnresolvable — naming the offending entry — because an
// additional_publishers name has no key material. Silently dropping the name
// would narrow trust without telling the operator (Issue #4398).
func TestStrictModeRejectsUnresolvableAdditionalPublisher(t *testing.T) {
	cfgmsPub, cfgmsPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeBypassBundle(echoModuleBin)
	sig := ed25519.Sign(cfgmsPriv, []byte(b.ContentHash))
	b.Signatures = []bundle.BundleSignature{
		{Publisher: "cfgms", Algorithm: "ed25519", Signature: sig},
	}

	// Registry holds a different name, so "vendor-missing" cannot be resolved.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rt := testEnforcerRuntimeWithKnownPublishers(t, cfgmsPub, map[string]pkgtrust.PublisherIdentity{
		"vendor-a": {Name: "vendor-a", PublicKey: []byte(otherPub), Algorithm: "ed25519"},
	})

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeStrict, []string{"vendor-missing"})
	require.Error(t, err)
	assert.ErrorIs(t, err, stewardtrust.ErrAdditionalPublisherUnresolvable)
	assert.Contains(t, err.Error(), "vendor-missing", "error must name the unresolvable entry")
	assert.Nil(t, handle, "no module process may be started when resolution fails")
}

// TestStrictModeUnresolvableAdditionalPublisherPrecedesPublisherNotTrusted pins
// the error precedence documented on Start: resolution runs before
// VerifyForLoad, so an unresolvable additional_publishers entry surfaces as
// ErrAdditionalPublisherUnresolvable even when the bundle's signature would
// also have failed trust verification.
func TestStrictModeUnresolvableAdditionalPublisherPrecedesPublisherNotTrusted(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, unknownPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeBypassBundle(echoModuleBin)
	b.Manifest.Publisher = "unknown-vendor"
	sig := ed25519.Sign(unknownPriv, []byte(b.ContentHash))
	b.Signatures = []bundle.BundleSignature{
		{Publisher: "unknown-vendor", Algorithm: "ed25519", Signature: sig},
	}

	rt := testEnforcerRuntimeWithKnownPublishers(t, cfgmsPub, nil)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeStrict, []string{"vendor-missing"})
	require.Error(t, err)
	assert.ErrorIs(t, err, stewardtrust.ErrAdditionalPublisherUnresolvable)
	assert.NotErrorIs(t, err, pkgtrust.ErrPublisherNotTrusted,
		"resolution failure must be reported before signature verification runs")
	assert.Nil(t, handle)
}

// TestWrongModuleKindPrecedesUnresolvableAdditionalPublisher pins the first step
// of Start's documented error precedence: the kind gate runs before
// additional_publishers resolution.
func TestWrongModuleKindPrecedesUnresolvableAdditionalPublisher(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeBypassBundle(echoModuleBin)
	b.Manifest.Kind = "outpost"

	rt := testEnforcerRuntimeWithKnownPublishers(t, cfgmsPub, nil)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeStrict, []string{"vendor-missing"})
	require.Error(t, err)
	assert.ErrorIs(t, err, runtime.ErrWrongModuleKind)
	assert.NotErrorIs(t, err, stewardtrust.ErrAdditionalPublisherUnresolvable)
	assert.Nil(t, handle)
}

// TestNonStrictModesIgnoreUnresolvableAdditionalPublishers verifies that
// controller and bypass modes never consult additional_publishers: an
// unresolvable name must not block a load that would not have looked at the
// list anyway.
func TestNonStrictModesIgnoreUnresolvableAdditionalPublishers(t *testing.T) {
	cases := []struct {
		name string
		mode stewardtypes.ModuleTrustMode
	}{
		{"controller mode", stewardtypes.ModuleTrustModeController},
		{"bypass mode", stewardtypes.ModuleTrustModeBypass},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			rt := testEnforcerRuntimeWithKnownPublishers(t, cfgmsPub, nil)
			b := makeBypassBundle(echoModuleBin)

			handle, err := rt.Start(b, tc.mode, []string{"vendor-missing"})
			require.NoError(t, err,
				"%s must not resolve additional_publishers", tc.mode)
			require.NotNil(t, handle)
			require.NoError(t, rt.Stop(handle))
		})
	}
}
