//go:build cfgms_dev_bypass

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// TestBypassModePassesUnsignedBundle: in a cfgms_dev_bypass build, bypass mode is a no-op.
func TestBypassModePassesUnsignedBundle(t *testing.T) {
	b := makeTestBundle()
	enforcer := trust.NewStewardTrustEnforcer()
	assert.NoError(t, enforcer.VerifyForLoad(b, stewardtypes.ModuleTrustModeBypass, nil))
}
