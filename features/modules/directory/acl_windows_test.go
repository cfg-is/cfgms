//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package directory

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/features/modules"
)

// TestMaskToAccessString verifies that both the generic Windows constants and the
// file-specific expanded constants (stored by Windows in ACEs) map to the correct
// access level strings. This directly tests the fix for the read-back mismatch where
// Windows stores 0x001F01FF instead of GENERIC_ALL after SetNamedSecurityInfo.
func TestMaskToAccessString(t *testing.T) {
	cases := []struct {
		mask windows.ACCESS_MASK
		want string
	}{
		// Generic constants — used when setting ACEs
		{windows.GENERIC_ALL, "FullControl"},
		{windows.GENERIC_READ | windows.GENERIC_EXECUTE, "ReadAndExecute"},
		{windows.GENERIC_WRITE | windows.GENERIC_READ | windows.GENERIC_EXECUTE, "Modify"},
		{windows.GENERIC_WRITE, "Write"},
		{windows.GENERIC_READ, "Read"},
		// File-specific expanded constants — stored by Windows, returned by GetNamedSecurityInfo
		{dirACLFullControl, "FullControl"},      // 0x001F01FF (FILE_ALL_ACCESS)
		{dirACLReadAndExecute, "ReadAndExecute"}, // 0x001200A9
		{dirACLModify, "Modify"},                 // 0x001201BF
		{dirACLWrite, "Write"},                   // 0x00120116
		{dirACLRead, "Read"},                     // 0x00120089
		// Unknown mask falls through to hex format
		{0xDEADBEEF, "0xDEADBEEF"},
	}
	for _, c := range cases {
		got := maskToAccessString(c.mask)
		if got != c.want {
			t.Errorf("maskToAccessString(0x%08X) = %q, want %q", uint32(c.mask), got, c.want)
		}
	}
}

// TestGetSetDirectoryACL_RoundTrip applies a known ACL to a real directory, reads it back,
// and asserts the returned ACL matches the configured entries for all access levels.
//
// Requires a Windows runner with advapi32 available (standard on all Windows versions).
// This test is excluded from Linux CI via the //go:build windows constraint.
func TestGetSetDirectoryACL_RoundTrip(t *testing.T) {
	base := t.TempDir()

	accessLevels := []string{"FullControl", "ReadAndExecute", "Modify", "Write", "Read"}

	for _, access := range accessLevels {
		access := access
		t.Run(access, func(t *testing.T) {
			path := filepath.Join(base, "acl_testdir_"+access)

			if err := os.Mkdir(path, 0777); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}

			desired := &modules.WindowsACL{
				Entries: []modules.ACLEntry{
					{Principal: `BUILTIN\Administrators`, Access: access},
				},
			}

			if err := setDirectoryACL(path, desired); err != nil {
				t.Fatalf("setDirectoryACL: %v", err)
			}

			got, err := getDirectoryACL(path)
			if err != nil {
				t.Fatalf("getDirectoryACL: %v", err)
			}
			if got == nil {
				t.Fatal("getDirectoryACL returned nil")
			}

			for _, want := range desired.Entries {
				found := false
				for _, have := range got.Entries {
					if have.Principal == want.Principal && have.Access == want.Access {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ACL entry {%s %s} not found in read-back ACL: %+v", want.Principal, want.Access, got.Entries)
				}
			}
		})
	}
}
