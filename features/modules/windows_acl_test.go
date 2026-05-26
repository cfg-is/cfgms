// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package modules_test

import (
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

// TestValidateACLAccess covers the ValidateACLAccess cross-platform validation helper.
// This exercises the same logic that the Windows accessStringToMask functions use,
// allowing error-path coverage without a Windows runner.
func TestValidateACLAccess(t *testing.T) {
	valid := []string{"FullControl", "ReadAndExecute", "Modify", "Write", "Read"}
	for _, v := range valid {
		if err := modules.ValidateACLAccess(v); err != nil {
			t.Errorf("ValidateACLAccess(%q) = %v, want nil", v, err)
		}
	}

	invalid := []string{"", "AllAccess", "ReadWrite", "fullcontrol", "GENERIC_ALL", "FullControl "}
	for _, v := range invalid {
		if err := modules.ValidateACLAccess(v); err == nil {
			t.Errorf("ValidateACLAccess(%q) = nil, want error", v)
		}
	}
}
