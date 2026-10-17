// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	sidUsers          = "S-1-5-32-545"
	sidAuthenticated  = "S-1-5-11"
	sidEveryone       = "S-1-1-0"
)

// daclSIDs returns the SIDs named by the ACEs of path's DACL and whether the
// DACL is protected from inheritance.
func daclSIDs(t *testing.T, path string) (sids []string, protected bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	ctrl, _, err := sd.Control()
	require.NoError(t, err)
	protected = ctrl&windows.SE_DACL_PROTECTED != 0
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, acl)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sids = append(sids, sid.String())
	}
	return sids, protected
}

func TestEnsureAdminOnlyDir_FreshDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, EnsureAdminOnlyDir(dir))

	sids, protected := daclSIDs(t, dir)
	assert.True(t, protected, "DACL must be protected from inheritance")
	assert.ElementsMatch(t, []string{sidSystem, sidAdministrators}, sids)

	file := filepath.Join(dir, "secret.bin")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	fileSIDs, _ := daclSIDs(t, file)
	for _, denied := range []string{sidUsers, sidAuthenticated, sidEveryone} {
		assert.NotContains(t, fileSIDs, denied)
	}
	assert.Contains(t, fileSIDs, sidSystem)
	assert.Contains(t, fileSIDs, sidAdministrators)
}

func TestEnsureAdminOnlyDir_CorrectsExistingTreeInPlace(t *testing.T) {
	dir := t.TempDir() // admin-owned in CI; inherits a permissive DACL
	child := filepath.Join(dir, "child")
	require.NoError(t, os.Mkdir(child, 0755))
	file := filepath.Join(child, "old.bin")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))

	require.NoError(t, EnsureAdminOnlyDir(dir))

	fileSIDs, _ := daclSIDs(t, file)
	for _, denied := range []string{sidUsers, sidAuthenticated, sidEveryone} {
		assert.NotContains(t, fileSIDs, denied, "existing child must pick up the new DACL")
	}
}

func TestEnsureAdminOnlyDir_RefusesFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	assert.Error(t, EnsureAdminOnlyDir(file))
}

func TestOwnerIsTrusted(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		trusted bool
	}{
		{"builtin users refused", "O:BUG:BUD:(A;;FA;;;BU)", false},
		{"administrators accepted", "O:BAG:BAD:(A;;FA;;;BA)", true},
		{"system accepted", "O:SYG:SYD:(A;;FA;;;SY)", true},
		{"everyone refused", "O:WDG:WDD:(A;;FA;;;WD)", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			require.NoError(t, err)
			got, err := ownerIsTrusted(sd)
			require.NoError(t, err)
			assert.Equal(t, tc.trusted, got)
		})
	}
}
