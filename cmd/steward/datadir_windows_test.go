// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/security"
)

// dataDirLocalAccountSID returns the well-known local account sidType (the
// built-in Administrator or Guest) in this machine's account domain.
func dataDirLocalAccountSID(t *testing.T, sidType windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	name, err := windows.ComputerName()
	require.NoError(t, err)
	domain, _, accType, err := windows.LookupSID("", name)
	require.NoError(t, err)
	require.Equal(t, uint32(windows.SidTypeDomain), accType, "%s must name the local account domain", name)
	sid, err := windows.CreateWellKnownDomainSid(sidType, domain)
	require.NoError(t, err)
	return sid
}

// dataDirSetOwner makes sid the owner of path. Assigning an owner other than
// oneself needs SeRestorePrivilege, which an elevated administrator holds but
// has disabled; it is enabled only for this call.
func dataDirSetOwner(t *testing.T, path string, sid *windows.SID) {
	t.Helper()
	var luid windows.LUID
	require.NoError(t, windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeRestorePrivilege"), &luid))
	var token windows.Token
	require.NoError(t, windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token))
	defer func() { _ = token.Close() }()
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	require.NoError(t, windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil))
	defer func() {
		tp.Privileges[0].Attributes = 0
		_ = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	}()
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil))
}

func dataDirOwner(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	return owner.String()
}

// useStewardDataDir points the start-up lockdown at a fresh data directory
// owned by Administrators, with a certs child and a file in it.
func useStewardDataDir(t *testing.T) (dir, child, file string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755))
	child = filepath.Join(dir, "certs")
	require.NoError(t, os.Mkdir(child, 0755))
	file = filepath.Join(child, "ca.crt")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err)
	dataDirSetOwner(t, dir, admins)

	prev := stewardDataDirResolver
	stewardDataDirResolver = func() string { return dir }
	t.Cleanup(func() { stewardDataDirResolver = prev })
	return dir, child, file
}

func TestSecureStewardDataDir_TakesOverEntriesOwnedByAnotherAdministratorsMember(t *testing.T) {
	// The built-in Administrator is always in BUILTIN\Administrators and is not
	// the account running the test, like files an administrator wrote on a host
	// that is upgraded to this steward.
	admin := dataDirLocalAccountSID(t, windows.WinAccountAdministratorSid)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	if user.User.Sid.Equals(admin) {
		t.Skip("the test runs as the built-in Administrator, so it has no other Administrators member to own the tree")
	}
	dir, child, file := useStewardDataDir(t)
	dataDirSetOwner(t, child, admin)
	dataDirSetOwner(t, file, admin)

	logger := logging.NewCapturingLogger()
	require.NoError(t, secureStewardDataDir(logger))

	for _, p := range []string{child, file} {
		assert.Equal(t, "S-1-5-32-544", dataDirOwner(t, p), "%s must be handed to Administrators", p)
	}
	summary, ok := logger.FindInfo("Assigned steward data entries to BUILTIN\\Administrators")
	require.True(t, ok, "the takeover must be logged at Info")
	assert.Equal(t, 2, summary["count"])
	assert.Equal(t, logging.SanitizeLogValue(dir), summary["path"])
	_, ok = logger.FindInfo("Took over steward data entry owned by a member of Administrators")
	assert.True(t, ok, "each taken-over entry must be logged at Info")
	require.NoError(t, security.EnsureAdminOnlyDir(dir), "the taken-over tree must pass the strict check")
}

func TestSecureStewardDataDir_RefusesEntryOwnedByStandardUser(t *testing.T) {
	guest := dataDirLocalAccountSID(t, windows.WinAccountGuestSid)
	_, _, file := useStewardDataDir(t)
	dataDirSetOwner(t, file, guest)

	err := secureStewardDataDir(logging.NewCapturingLogger())
	assert.ErrorIs(t, err, security.ErrUntrustedDirOwner, "the steward must refuse to start")
	assert.Equal(t, guest.String(), dataDirOwner(t, file), "a standard user's entry must never be adopted")
}
