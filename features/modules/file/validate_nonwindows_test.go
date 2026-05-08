//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package file

import (
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

// TestFileConfig_Validate_WindowsACL_NonWindows verifies that specifying windows_acl
// on a non-Windows platform returns a clear error. Compiled only on !windows so the
// test is never skipped — it always runs on Linux/macOS CI.
func TestFileConfig_Validate_WindowsACL_NonWindows(t *testing.T) {
	cfg := &FileConfig{
		State:           "present",
		Content:         "test",
		AllowedBasePath: "/tmp",
		WindowsACL: &modules.WindowsACL{
			Entries: []modules.ACLEntry{
				{Principal: `BUILTIN\Administrators`, Access: "FullControl"},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with windows_acl on non-Windows should return an error")
	}
}
