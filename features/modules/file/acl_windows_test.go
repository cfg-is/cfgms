//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

// TestGetSetFileACL_RoundTrip applies a known ACL to a real file, reads it back,
// and asserts the returned ACL matches the configured entries.
//
// Requires a Windows runner with advapi32 available (standard on all Windows versions).
// This test is excluded from Linux CI via the //go:build windows constraint.
func TestGetSetFileACL_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acl_test.txt")

	// Create the file so ACL operations have a target.
	if err := os.WriteFile(path, []byte("acl test"), 0666); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	desired := &modules.WindowsACL{
		Entries: []modules.ACLEntry{
			{Principal: `BUILTIN\Administrators`, Access: "FullControl"},
		},
	}

	if err := setFileACL(path, desired); err != nil {
		t.Fatalf("setFileACL: %v", err)
	}

	got, err := getFileACL(path)
	if err != nil {
		t.Fatalf("getFileACL: %v", err)
	}
	if got == nil {
		t.Fatal("getFileACL returned nil")
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
