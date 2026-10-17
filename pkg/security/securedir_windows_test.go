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

// setOwnerAdministrators makes BUILTIN\Administrators the owner of path.
func setOwnerAdministrators(t *testing.T, path string) {
	t.Helper()
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil))
	require.Equal(t, sidAdministrators, ownerSID(t, path))
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
	// A t.TempDir() tree inherits a permissive DACL but is owned by the test
	// user, which EnsureAdminOnlyDir refuses; hand it to Administrators (an
	// elevated member may assign that group as owner) so only the DACL differs.
	dir := t.TempDir()
	child := filepath.Join(dir, "child")
	require.NoError(t, os.Mkdir(child, 0755))
	file := filepath.Join(child, "old.bin")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	for _, p := range []string{dir, child, file} {
		setOwnerAdministrators(t, p)
	}

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

// ownerSID returns the SID string of path's owner.
func ownerSID(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	require.NotNil(t, owner)
	return owner.String()
}

func TestEnsureAdminOnlyDir_CreatesWithTrustedOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "cfgms")
	require.NoError(t, EnsureAdminOnlyDir(dir))

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	require.NoError(t, err)
	trusted, err := ownerIsTrusted(sd)
	require.NoError(t, err)
	assert.True(t, trusted, "created directory owner %s must be trusted", ownerSID(t, dir))
}

func TestCreateAdminOnlyDir_ExistingDirectoryIsNotCreated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755)) // e.g. planted between checks

	created, err := createAdminOnlyDir(dir)
	require.NoError(t, err)
	assert.False(t, created, "an existing directory must go through the owner check, never be treated as created")
}

func TestCreateAdminOnlyDir_NewDirectoryHasAdminOnlyDACLFromBirth(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfgms")

	created, err := createAdminOnlyDir(dir)
	require.NoError(t, err)
	assert.True(t, created)

	sids, protected := daclSIDs(t, dir)
	assert.True(t, protected, "DACL must be protected at creation")
	assert.ElementsMatch(t, []string{sidSystem, sidAdministrators}, sids)
}

func TestEnsureAdminOnlyDir_RefusesRootSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	require.NoError(t, os.Mkdir(target, 0755))
	link := filepath.Join(base, "cfgms")
	require.NoError(t, os.Symlink(target, link))

	err := EnsureAdminOnlyDir(link)
	require.Error(t, err)
	sids, _ := daclSIDs(t, target)
	assert.NotElementsMatch(t, []string{sidSystem, sidAdministrators}, sids, "link target must be left untouched")
}

func TestEnsureAdminOnlyDir_RefusesChildReparsePoint(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(outside, 0755))
	dir := filepath.Join(base, "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "certs")))

	err := EnsureAdminOnlyDir(dir)
	require.ErrorIs(t, err, ErrUntrustedDirEntry)
	_, protected := daclSIDs(t, dir)
	assert.False(t, protected, "a refused directory must be left unchanged")
}

func TestEnsureAdminOnlyDir_RefusesChildWithExplicitNonAdminACE(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "steward", "certs")
	require.NoError(t, os.MkdirAll(child, 0755))
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(child, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil))

	err = EnsureAdminOnlyDir(dir)
	require.ErrorIs(t, err, ErrUntrustedDirEntry)
}

func TestDACLIsAdminOnly(t *testing.T) {
	tests := []struct {
		name string
		sddl string
		ok   bool
	}{
		{"admin only", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true},
		{"inherited admin only", "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)", true},
		{"deny users accepted", "D:P(D;;FA;;;BU)(A;;FA;;;BA)", true},
		{"users read refused", "D:P(A;;FA;;;BA)(A;;FR;;;BU)", false},
		{"creator owner refused", "D:P(A;;FA;;;BA)(A;OICIIO;FA;;;CO)", false},
		{"everyone refused", "D:P(A;;FA;;;SY)(A;;FA;;;WD)", false},
		{"null dacl refused", "D:NO_ACCESS_CONTROL", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			require.NoError(t, err)
			got, err := daclIsAdminOnly(sd)
			require.NoError(t, err)
			assert.Equal(t, tc.ok, got)
		})
	}
}

// setOwnerWithRestorePrivilege makes the principal sidString the owner of path.
// Assigning an owner other than oneself needs SeRestorePrivilege, which an
// elevated administrator holds but has disabled; it is enabled only for this
// call.
func setOwnerWithRestorePrivilege(t *testing.T, path, sidString string) {
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
	sid, err := windows.StringToSid(sidString)
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil))
	require.Equal(t, sidString, ownerSID(t, path))
}

func TestAdoptAdminOnlyDir_AdoptsCallerOwnedTree(t *testing.T) {
	// Everything under t.TempDir() is owned by the (elevated) test user, as an
	// installer's files are; the SYSTEM steward's check would refuse them.
	dir := t.TempDir()
	child := filepath.Join(dir, "certs")
	require.NoError(t, os.Mkdir(child, 0755))
	file := filepath.Join(child, "ca.crt")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))

	require.NoError(t, AdoptAdminOnlyDir(dir))

	for _, p := range []string{dir, child, file} {
		assert.Equal(t, sidAdministrators, ownerSID(t, p), "%s must be handed to Administrators", p)
	}
	sids, protected := daclSIDs(t, dir)
	assert.True(t, protected)
	assert.ElementsMatch(t, []string{sidSystem, sidAdministrators}, sids)
}

func TestAdoptAdminOnlyDir_RefusesEntryOwnedByAnotherPrincipal(t *testing.T) {
	dir := t.TempDir()
	planted := filepath.Join(dir, "planted.crt")
	require.NoError(t, os.WriteFile(planted, []byte("x"), 0600))
	setOwnerWithRestorePrivilege(t, planted, sidUsers)

	assert.ErrorIs(t, AdoptAdminOnlyDir(dir), ErrUntrustedDirOwner)
	assert.Equal(t, sidUsers, ownerSID(t, planted), "an entry another principal owns must never be adopted")
}

func TestAdoptAdminOnlyDir_RefusesRootOwnedByAnotherPrincipal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755))
	setOwnerWithRestorePrivilege(t, dir, sidUsers)

	assert.ErrorIs(t, AdoptAdminOnlyDir(dir), ErrUntrustedDirOwner)
	assert.Equal(t, sidUsers, ownerSID(t, dir))
}
