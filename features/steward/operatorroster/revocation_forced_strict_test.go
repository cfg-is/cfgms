// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package operatorroster

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
)

func TestRevocationVerifier_ForcedStrict_IgnoresTheModeAndChainVerifies(t *testing.T) {
	ca, pool := revTestCA(t)
	_, plantedPool := revTestCA(t)
	signer := revTestSigningCert(t, ca)
	manifest := revTestSignManifest(t, signer, 1, []string{"42"})

	for _, mode := range []stewardtypes.ModuleTrustMode{
		stewardtypes.ModuleTrustModeController, stewardtypes.ModuleTrustModeBypass, stewardtypes.ModuleTrustModeStrict,
	} {
		// Against a root that did not sign it, no mode accepts the manifest.
		v := NewRevocationVerifier(plantedPool, WithForcedStrict())
		assert.Error(t, v.VerifyManifest(manifest, mode), "mode %q", mode)
		_, ok := v.NewestIssuedAt()
		assert.False(t, ok)
		assert.False(t, v.IsRevoked("42"))

		// Against its own root every mode verifies it, bypass included.
		v = NewRevocationVerifier(pool, WithForcedStrict())
		require.NoError(t, v.VerifyManifest(manifest, mode), "mode %q", mode)
		assert.True(t, v.IsRevoked("42"))
	}

	// Without the option, controller mode still skips the chain check.
	assert.NoError(t, NewRevocationVerifier(plantedPool).VerifyManifest(manifest, stewardtypes.ModuleTrustModeController))
}

func TestRevocationVerifier_SetTrust_AndNewestIssuedAt(t *testing.T) {
	ca, pool := revTestCA(t)
	signer := revTestSigningCert(t, ca)
	manifest := revTestSignManifest(t, signer, 1, nil)

	v := NewRevocationVerifier(nil, WithForcedStrict())
	assert.Error(t, v.VerifyManifest(manifest, stewardtypes.ModuleTrustModeStrict), "no roots yet")
	_, ok := v.NewestIssuedAt()
	assert.False(t, ok)

	v.SetTrust(pool, nil)
	require.NoError(t, v.VerifyManifest(manifest, stewardtypes.ModuleTrustModeStrict))
	issued, ok := v.NewestIssuedAt()
	require.True(t, ok)
	assert.False(t, issued.IsZero())
}
