//go:build cfgms_dev_bypass

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package operatorroster

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
)

func TestRevocationVerifier_VerifyManifest_BypassMode_NoOp(t *testing.T) {
	ca, caPool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	raw := revTestSignManifest(t, signingCert, 1, []string{"12345"})

	v := NewRevocationVerifier(caPool)
	require.NoError(t, v.VerifyManifest(raw, stewardtypes.ModuleTrustModeBypass))
	assert.False(t, v.IsRevoked("12345"), "bypass mode must not apply the manifest at all")
}
