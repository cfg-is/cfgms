//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package directory

import (
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

// TestDirectoryConfig_Validate_WindowsACL_NonWindows verifies that specifying windows_acl
// on a non-Windows platform returns a clear error. Compiled only on !windows so the
// test is never skipped — it always runs on Linux/macOS CI.
func TestDirectoryConfig_Validate_WindowsACL_NonWindows(t *testing.T) {
	cfg := &directoryConfig{
		AllowedBasePath: "/tmp",
		Path:            "/tmp/testdir",
		WindowsACL: &modules.WindowsACL{
			Entries: []modules.ACLEntry{
				{Principal: `BUILTIN\Administrators`, Access: "FullControl"},
			},
		},
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("validate() with windows_acl on non-Windows should return an error")
	}
}
