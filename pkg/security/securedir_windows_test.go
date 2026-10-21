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

	"github.com/cfgis/cfgms/pkg/testutil/winacct"
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

	_, err := AdoptAdminOnlyDir(dir)
	require.NoError(t, err)

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

	_, err := AdoptAdminOnlyDir(dir)
	assert.ErrorIs(t, err, ErrUntrustedDirOwner)
	assert.Equal(t, sidUsers, ownerSID(t, planted), "an entry another principal owns must never be adopted")
}

func TestAdoptAdminOnlyDir_RefusesRootOwnedByAnotherPrincipal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755))
	setOwnerWithRestorePrivilege(t, dir, sidUsers)

	_, err := AdoptAdminOnlyDir(dir)
	assert.ErrorIs(t, err, ErrUntrustedDirOwner)
	assert.Equal(t, sidUsers, ownerSID(t, dir))
}

func TestIsAdministratorsMember(t *testing.T) {
	admin := winacct.LocalAccountSID(t, windows.WinAccountAdministratorSid)
	member, err := isAdministratorsMember(admin)
	require.NoError(t, err)
	assert.True(t, member, "the built-in Administrator is always a member of Administrators")

	member, err = isAdministratorsMember(winacct.LocalAccountSID(t, windows.WinAccountGuestSid))
	require.NoError(t, err)
	assert.False(t, member, "Guest is not a member of Administrators")

	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	require.NoError(t, err)
	member, _ = isAdministratorsMember(users)
	assert.False(t, member, "a group is not an account whose membership can be granted")
}

func TestAdoptAdminOnlyDir_AdoptsTreeOwnedByAnotherAdministratorsMember(t *testing.T) {
	// An upgraded host: files an administrator (not the account running the
	// steward) wrote under the data directory.
	adminMember := winacct.OtherAdministratorsMember(t).String()
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755))
	child := filepath.Join(dir, "certs")
	require.NoError(t, os.Mkdir(child, 0755))
	file := filepath.Join(child, "ca.crt")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	setOwnerAdministrators(t, dir)
	for _, p := range []string{child, file} {
		setOwnerWithRestorePrivilege(t, p, adminMember)
	}

	adopted, err := AdoptAdminOnlyDir(dir)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{child, file}, adopted, "every taken-over entry must be reported")
	for _, p := range []string{child, file} {
		assert.Equal(t, sidAdministrators, ownerSID(t, p), "%s must be handed to Administrators", p)
		sids, protected := daclSIDs(t, p)
		assert.True(t, protected, "%s must get a protected DACL", p)
		assert.ElementsMatch(t, []string{sidSystem, sidAdministrators}, sids, p)
	}
	require.NoError(t, EnsureAdminOnlyDir(dir), "the taken-over tree must pass the strict check")
}

func TestAdoptAdminOnlyDir_RefusesEntryOwnedByStandardUser(t *testing.T) {
	user := winacct.StandardUser(t).String()
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755))
	setOwnerAdministrators(t, dir)
	planted := filepath.Join(dir, "planted.crt")
	require.NoError(t, os.WriteFile(planted, []byte("x"), 0600))
	setOwnerWithRestorePrivilege(t, planted, user)

	adopted, err := AdoptAdminOnlyDir(dir)
	assert.ErrorIs(t, err, ErrUntrustedDirOwner)
	assert.Empty(t, adopted)
	assert.Equal(t, user, ownerSID(t, planted), "an entry a standard user owns must never be adopted")
}

func TestAdoptAdminOnlyDir_RefusesRootOwnedByStandardUser(t *testing.T) {
	user := winacct.StandardUser(t).String()
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755))
	setOwnerWithRestorePrivilege(t, dir, user)

	_, err := AdoptAdminOnlyDir(dir)
	assert.ErrorIs(t, err, ErrUntrustedDirOwner)
	assert.Equal(t, user, ownerSID(t, dir))
}

// securitySnapshot returns path's owner and DACL as SDDL, to show that a
// read-only check changed neither.
func securitySnapshot(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	return sd.String()
}

// setProtectedDACL replaces path's DACL with the protected DACL of sddl.
func setProtectedDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil))
}

// fileInLockedTree returns a file written inside a directory locked with
// EnsureAdminOnlyDir.
func fileInLockedTree(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, EnsureAdminOnlyDir(dir))
	file := filepath.Join(dir, "controller.cfg")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	return file
}

// assertVerify runs check on path and asserts its result (nil when want is
// nil, an error wrapping want otherwise) and that it left the owner and DACL
// of path and of its parent unchanged.
func assertVerify(t *testing.T, check func(string) error, path string, want error) {
	t.Helper()
	before, parentBefore := securitySnapshot(t, path), securitySnapshot(t, filepath.Dir(path))
	err := check(path)
	if want == nil {
		assert.NoError(t, err)
	} else {
		assert.ErrorIs(t, err, want)
	}
	assert.Equal(t, before, securitySnapshot(t, path), "the check must not change the owner or DACL")
	assert.Equal(t, parentBefore, securitySnapshot(t, filepath.Dir(path)), "the check must not change the parent")
}

func TestVerifyAdminOnlyPath_FileInLockedTreeVerifies(t *testing.T) {
	file := fileInLockedTree(t)
	assertVerify(t, VerifyAdminOnlyPath, file, nil)
	assertVerify(t, VerifyAdminOnlyWritablePath, file, nil)
	assertVerify(t, VerifyAdminOnlyPath, filepath.Dir(file), nil)
}

func TestVerifyAdminOnlyPath_RefusesUsersACE(t *testing.T) {
	file := fileInLockedTree(t)
	setProtectedDACL(t, file, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")

	assertVerify(t, VerifyAdminOnlyPath, file, ErrUntrustedDirEntry)
}

func TestVerifyAdminOnlyPath_RefusesStandardUserOwner(t *testing.T) {
	file := fileInLockedTree(t)
	setOwnerWithRestorePrivilege(t, file, winacct.StandardUser(t).String())

	assertVerify(t, VerifyAdminOnlyPath, file, ErrUntrustedDirOwner)
	assertVerify(t, VerifyAdminOnlyWritablePath, file, ErrUntrustedDirOwner)
}

func TestVerifyAdminOnlyPath_AcceptsAdministratorsMemberOwner(t *testing.T) {
	file := fileInLockedTree(t)
	setOwnerWithRestorePrivilege(t, file, winacct.OtherAdministratorsMember(t).String())

	assertVerify(t, VerifyAdminOnlyPath, file, nil)
	assertVerify(t, VerifyAdminOnlyWritablePath, file, nil)
}

func TestVerifyAdminOnlyPath_RefusesReparsePoint(t *testing.T) {
	file := fileInLockedTree(t)
	link := filepath.Join(filepath.Dir(file), "link.cfg")
	if err := os.Symlink(file, link); err != nil {
		t.Skipf("creating a symbolic link needs SeCreateSymbolicLinkPrivilege, which this runner lacks: %v", err)
	}

	assert.ErrorIs(t, VerifyAdminOnlyPath(link), ErrUntrustedDirEntry)
	assert.ErrorIs(t, VerifyAdminOnlyWritablePath(link), ErrUntrustedDirEntry)
}

func TestVerifyAdminOnlyPath_MissingPathIsError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.cfg")

	assert.Error(t, VerifyAdminOnlyPath(missing))
	assert.Error(t, VerifyAdminOnlyWritablePath(missing))
}

func TestVerifyAdminOnlyWritablePath_AllowsUsersReadExecute(t *testing.T) {
	file := fileInLockedTree(t)
	setProtectedDACL(t, file, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)")

	assertVerify(t, VerifyAdminOnlyWritablePath, file, nil)
	assertVerify(t, VerifyAdminOnlyPath, file, ErrUntrustedDirEntry)
}

func TestVerifyAdminOnlyWritablePath_RefusesUsersModify(t *testing.T) {
	file := fileInLockedTree(t)
	setProtectedDACL(t, file, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;BU)")

	assertVerify(t, VerifyAdminOnlyWritablePath, file, ErrUntrustedDirEntry)
}

func TestVerifyAdminOnlyWritablePath_RefusesParentGrantingUsersAddFile(t *testing.T) {
	file := fileInLockedTree(t)
	// The Users ACE is not inheritable, so the file itself stays admin-only;
	// the directory still lets Users add files beside it.
	setProtectedDACL(t, filepath.Dir(file), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x100002;;;BU)")

	assertVerify(t, VerifyAdminOnlyPath, file, ErrUntrustedDirEntry)
	assertVerify(t, VerifyAdminOnlyWritablePath, file, ErrUntrustedDirEntry)
}

func TestVerifyAdminOnlyWritablePath_IgnoresInheritOnlyACEs(t *testing.T) {
	file := fileInLockedTree(t)
	// An inherit-only Users ACE that applies only to new subdirectories does
	// not grant anything on the directory itself.
	setProtectedDACL(t, filepath.Dir(file), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;CIIO;FA;;;BU)")

	assertVerify(t, VerifyAdminOnlyWritablePath, file, nil)
}

func TestVerifyAdminOnlyWritablePath_RefusesEachModifyRight(t *testing.T) {
	for name, mask := range map[string]string{
		"write data":    "0x120002",
		"append":        "0x120004",
		"delete":        "0x130000",
		"write dac":     "0x160000",
		"write owner":   "0x1a0000",
		"generic all":   "GA",
		"generic write": "GW",
	} {
		t.Run(name, func(t *testing.T) {
			file := fileInLockedTree(t)
			setProtectedDACL(t, file, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;"+mask+";;;BU)")

			assertVerify(t, VerifyAdminOnlyWritablePath, file, ErrUntrustedDirEntry)
		})
	}
}

func TestVerifyAdminOnlyWritablePath_RefusesEachParentModifyRight(t *testing.T) {
	for name, mask := range map[string]string{
		"add file":         "0x120002",
		"add subdirectory": "0x120004",
		"delete child":     "0x120040",
		"write dac":        "0x160000",
	} {
		t.Run(name, func(t *testing.T) {
			file := fileInLockedTree(t)
			setProtectedDACL(t, filepath.Dir(file), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;"+mask+";;;BU)")

			assertVerify(t, VerifyAdminOnlyWritablePath, file, ErrUntrustedDirEntry)
		})
	}
}

func TestVerifyAdminOnlyPath_RefusesNullDACL(t *testing.T) {
	file := fileInLockedTree(t)
	// A NULL DACL grants everyone full access.
	require.NoError(t, windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil))

	assertVerify(t, VerifyAdminOnlyPath, file, ErrUntrustedDirEntry)
	assertVerify(t, VerifyAdminOnlyWritablePath, file, ErrUntrustedDirEntry)
}

func TestVerifyAdminOnlyPath_AcceptsDenyACE(t *testing.T) {
	file := fileInLockedTree(t)
	// A deny ACE only removes access.
	setProtectedDACL(t, file, "D:P(D;;FA;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)")

	assertVerify(t, VerifyAdminOnlyPath, file, nil)
	assertVerify(t, VerifyAdminOnlyWritablePath, file, nil)
}

func TestVerifyAdminOnlyWritablePath_RefusesParentOwnedByStandardUser(t *testing.T) {
	file := fileInLockedTree(t)
	setOwnerWithRestorePrivilege(t, filepath.Dir(file), winacct.StandardUser(t).String())

	assertVerify(t, VerifyAdminOnlyWritablePath, file, ErrUntrustedDirOwner)
}

func TestVerifyAdminOnlyPath_RefusesGrandparentThatLetsUsersRenameParent(t *testing.T) {
	file := fileInLockedTree(t)
	grandparent := filepath.Dir(filepath.Dir(file))
	// Delete-child on the grandparent lets Users rename the parent and put
	// another directory in its place.
	setProtectedDACL(t, grandparent, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x120040;;;BU)")

	assertVerify(t, VerifyAdminOnlyPath, file, ErrUntrustedDirEntry)
	assertVerify(t, VerifyAdminOnlyWritablePath, file, ErrUntrustedDirEntry)
}

func TestVerifyAdminOnlyPath_AcceptsGrandparentGrantingUsersAddFile(t *testing.T) {
	file := fileInLockedTree(t)
	grandparent := filepath.Dir(filepath.Dir(file))
	// Creating new entries in the grandparent cannot replace the parent.
	setProtectedDACL(t, grandparent, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x120006;;;BU)")

	assertVerify(t, VerifyAdminOnlyPath, file, nil)
	assertVerify(t, VerifyAdminOnlyWritablePath, file, nil)
}

func TestVerifyAdminOnlyPath_RefusesParentGrantingUsersDeleteChild(t *testing.T) {
	file := fileInLockedTree(t)
	setProtectedDACL(t, filepath.Dir(file), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x120040;;;BU)")

	assertVerify(t, VerifyAdminOnlyPath, file, ErrUntrustedDirEntry)
}

func TestVerifyAdminOnlyPath_RefusesRelativePath(t *testing.T) {
	assert.Error(t, VerifyAdminOnlyPath(`cfgms\controller.cfg`))
	assert.Error(t, VerifyAdminOnlyWritablePath(`cfgms-steward.exe`))
}
