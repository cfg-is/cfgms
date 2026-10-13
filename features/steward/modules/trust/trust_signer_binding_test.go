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
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
)

// TestStrictMode_RefusesAdditionalPublisherSigningCFGMSNamedBundle: a trusted
// additional publisher's signature does not count over a bundle whose manifest names
// the cfgms publisher.
func TestStrictMode_RefusesAdditionalPublisherSigningCFGMSNamedBundle(t *testing.T) {
	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	extraPub, extraPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeTestBundleFor("cfgms")
	signBundle(b, "extra-vendor", extraPriv)

	additional := []stewardtrust.PublisherIdentity{
		{Name: "extra-vendor", PublicKey: []byte(extraPub), Algorithm: "ed25519"},
	}
	err = testEnforcer(cfgmsPub).VerifyForLoad(b, stewardtypes.ModuleTrustModeStrict, additional)
	require.Error(t, err)
	assert.ErrorIs(t, err, pkgtrust.ErrPublisherManifestMismatch)
}

// TestStrictMode_StdlibStyleBundleStillVerifies: a bundle whose manifest names cfgms
// and is signed as cfgms verifies in strict mode.
func TestStrictMode_StdlibStyleBundleStillVerifies(t *testing.T) {
	cfgmsPub, cfgmsPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeTestBundleFor("cfgms")
	signBundle(b, "cfgms", cfgmsPriv)

	assert.NoError(t, testEnforcer(cfgmsPub).VerifyForLoad(b, stewardtypes.ModuleTrustModeStrict, nil))
}
