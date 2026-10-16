//go:build cfgms_dev_bypass

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package runtime_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/modules/runtime"
)

// A cfgms_dev_bypass build honours module_trust.mode: bypass, so the
// every-mode install-integrity tests cover it too.
func init() {
	allTrustModes = append(allTrustModes, trustCase{"bypass", stewardtypes.ModuleTrustModeBypass})
}

// TestBypassModePassesUnsignedBundle verifies that, in a cfgms_dev_bypass
// build, bypass mode skips signature verification.
func TestBypassModePassesUnsignedBundle(t *testing.T) {
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	b := makeUnsignedBundle(t, echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
	require.NoError(t, err)
	require.NoError(t, rt.Stop(handle))
}

// TestBypassModeIgnoresUnresolvableAdditionalPublishers: bypass never consults
// additional_publishers, so an unresolvable name must not block the load.
func TestBypassModeIgnoresUnresolvableAdditionalPublishers(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rt := testEnforcerRuntimeWithKnownPublishers(t, cfgmsPub, nil)
	b := makeUnsignedBundle(t, echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, []string{"vendor-missing"})
	require.NoError(t, err, "bypass must not resolve additional_publishers")
	require.NotNil(t, handle)
	require.NoError(t, rt.Stop(handle))
}
