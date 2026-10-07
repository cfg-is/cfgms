//go:build cfgms_dev_bypass

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package stewardtypes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateModuleTrustConfig_Bypass_AllowedWithDevTag verifies the other
// side of Issue #4324 item 1: a binary deliberately built with
// -tags cfgms_dev_bypass still accepts module_trust.mode: bypass, so the
// development workflow the mode exists for keeps working. Run with:
//
//	go test -tags cfgms_dev_bypass ./features/config/stewardtypes/...
func TestValidateModuleTrustConfig_Bypass_AllowedWithDevTag(t *testing.T) {
	assert.NoError(t, ValidateModuleTrustConfig(ModuleTrustConfig{Mode: ModuleTrustModeBypass}))
}
