//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package directory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

// TestGetSetDirectoryACL_RoundTrip applies a known ACL to a real directory, reads it back,
// and asserts the returned ACL matches the configured entries.
//
// Requires a Windows runner with advapi32 available (standard on all Windows versions).
// This test is excluded from Linux CI via the //go:build windows constraint.
func TestGetSetDirectoryACL_RoundTrip(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "acl_testdir")

	if err := os.Mkdir(path, 0777); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	desired := &modules.WindowsACL{
		Entries: []modules.ACLEntry{
			{Principal: `BUILTIN\Administrators`, Access: "FullControl"},
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

	// Verify every desired entry is present in the read-back ACL.
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
}
