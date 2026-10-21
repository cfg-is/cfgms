// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build windows

package package_module

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// adminTree creates dir/choco.exe owned by Administrators with a DACL that
// grants SYSTEM and Administrators full control and Users the given mask
// (0 = no Users entry). Inheritance is blocked so the temp parent's ACL does
// not leak in.
func adminTree(t *testing.T, usersMask windows.ACCESS_MASK) (dir, exe string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "chocolatey")
	require.NoError(t, os.Mkdir(dir, 0o755))
	exe = filepath.Join(dir, "choco.exe")
	require.NoError(t, os.WriteFile(exe, []byte("x"), 0o600))

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err)
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err)
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	require.NoError(t, err)

	entries := []windows.EXPLICIT_ACCESS{
		{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_GROUP, TrusteeValue: windows.TrusteeValueFromSID(admins)}},
		{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(system)}},
	}
	if usersMask != 0 {
		entries = append(entries, windows.EXPLICIT_ACCESS{AccessPermissions: usersMask, AccessMode: windows.GRANT_ACCESS,
			Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee:     windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_GROUP, TrusteeValue: windows.TrusteeValueFromSID(users)}})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	require.NoError(t, err)
	for _, p := range []string{exe, dir} {
		require.NoError(t, windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			admins, nil, acl, nil))
	}
	return dir, exe
}

func TestChocoTrusted(t *testing.T) {
	const readExec = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE

	t.Run("admin-owned tree with Users read-only passes", func(t *testing.T) {
		_, exe := adminTree(t, readExec)
		assert.NoError(t, chocoTrusted(exe))
	})

	t.Run("Users write access is refused", func(t *testing.T) {
		_, exe := adminTree(t, readExec|windows.FILE_WRITE_DATA)
		err := chocoTrusted(exe)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "write access")
	})

	t.Run("Users write on the parent directory is refused", func(t *testing.T) {
		dir, exe := adminTree(t, readExec)
		// Rewrite only the parent's DACL to let Users create entries.
		users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
		require.NoError(t, err)
		admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		require.NoError(t, err)
		acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
			{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS,
				Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_GROUP, TrusteeValue: windows.TrusteeValueFromSID(admins)}},
			{AccessPermissions: windows.FILE_GENERIC_READ | windows.FILE_APPEND_DATA, AccessMode: windows.GRANT_ACCESS,
				Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_GROUP, TrusteeValue: windows.TrusteeValueFromSID(users)}},
		}, nil)
		require.NoError(t, err)
		require.NoError(t, windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil))
		assert.Error(t, chocoTrusted(exe))
	})

	t.Run("reparse point is refused", func(t *testing.T) {
		dir, exe := adminTree(t, readExec)
		link := filepath.Join(dir, "link.exe")
		if err := os.Symlink(exe, link); err != nil {
			t.Skipf("symlink creation not permitted: %v", err)
		}
		err := chocoTrusted(link)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reparse point")
	})

	t.Run("missing path is refused", func(t *testing.T) {
		assert.Error(t, chocoTrusted(filepath.Join(t.TempDir(), "nope", "choco.exe")))
	})
}

// With chocoExePath failing chocoTrusted, neither probe may execute anything.
func TestChocoProbes_RunNothingWhenUntrusted(t *testing.T) {
	origExists, origTrusted, origRun := chocoProbeExists, chocoProbeTrusted, chocoProbeRun
	t.Cleanup(func() { chocoProbeExists, chocoProbeTrusted, chocoProbeRun = origExists, origTrusted, origRun })

	var ran []string
	chocoProbeExists = func() bool { return true }
	chocoProbeTrusted = func(string) error { return fmt.Errorf("untrusted") }
	chocoProbeRun = func(_ context.Context, exe string, args ...string) error {
		ran = append(ran, exe)
		return nil
	}

	assert.False(t, defaultProviderRegistry["choco"].probe(context.Background()))
	// NewPackageManager may still resolve winget; it must never run choco.
	_, _ = NewPackageManager(context.Background())
	assert.Empty(t, ran, "no choco invocation (bare or absolute) before the trust check passes")

	chocoProbeTrusted = func(string) error { return nil }
	assert.True(t, defaultProviderRegistry["choco"].probe(context.Background()))
	assert.Equal(t, []string{chocoExePath}, ran, "trusted probe runs only the absolute path")
}
