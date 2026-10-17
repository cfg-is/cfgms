// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package winacct

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	modnetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd              = modnetapi32.NewProc("NetUserAdd")
	procNetUserDel              = modnetapi32.NewProc("NetUserDel")
	procNetLocalGroupAddMembers = modnetapi32.NewProc("NetLocalGroupAddMembers")
)

// userInfo1 is USER_INFO_1.
type userInfo1 struct {
	name        *uint16
	password    *uint16
	passwordAge uint32
	priv        uint32
	homeDir     *uint16
	comment     *uint16
	flags       uint32
	scriptPath  *uint16
}

// localGroupMembersInfo0 is LOCALGROUP_MEMBERS_INFO_0.
type localGroupMembersInfo0 struct {
	sid *windows.SID
}

const (
	userPrivUser       = 1      // USER_PRIV_USER
	ufScript           = 0x0001 // UF_SCRIPT, required by NetUserAdd
	ufAccountDisable   = 0x0002 // UF_ACCOUNTDISABLE
	ufDontExpirePasswd = 0x10000
)

// LocalAccountSID returns the well-known local account sidType (such as
// windows.WinAccountAdministratorSid or windows.WinAccountGuestSid) in this
// machine's account domain.
func LocalAccountSID(t testing.TB, sidType windows.WELL_KNOWN_SID_TYPE) *windows.SID {
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

// StandardUser returns the built-in local Guest account: a real user account
// that is not a member of Administrators.
func StandardUser(t testing.TB) *windows.SID {
	t.Helper()
	return LocalAccountSID(t, windows.WinAccountGuestSid)
}

// OtherAdministratorsMember returns a member of BUILTIN\Administrators that is
// not the account running the test. That is the built-in Administrator, which
// Windows keeps in Administrators, unless the test runs as it (as CI runners
// do); then a disabled local account is created, added to Administrators and
// deleted when the test ends.
func OtherAdministratorsMember(t testing.TB) *windows.SID {
	t.Helper()
	admin := LocalAccountSID(t, windows.WinAccountAdministratorSid)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	if !user.User.Sid.Equals(admin) {
		return admin
	}
	return createLocalAdmin(t)
}

func createLocalAdmin(t testing.TB) *windows.SID {
	t.Helper()
	raw := make([]byte, 6)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	name := "cfgmst" + hex.EncodeToString(raw)
	// The account is disabled and never logs on; the password only has to
	// satisfy the local password policy.
	pw := make([]byte, 24)
	_, err = rand.Read(pw)
	require.NoError(t, err)
	password := "Aa1!" + hex.EncodeToString(pw)

	info := userInfo1{
		name:     windows.StringToUTF16Ptr(name),
		password: windows.StringToUTF16Ptr(password),
		priv:     userPrivUser,
		flags:    ufScript | ufAccountDisable | ufDontExpirePasswd,
	}
	if r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), 0); r != 0 {
		t.Fatalf("NetUserAdd %s: %v", name, windows.Errno(r))
	}
	t.Cleanup(func() {
		_, _, _ = procNetUserDel.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))))
	})

	sid, _, _, err := windows.LookupSID("", name)
	require.NoError(t, err)
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err)
	group, _, _, err := admins.LookupAccount("")
	require.NoError(t, err)
	member := localGroupMembersInfo0{sid: sid}
	if r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(group))), 0, uintptr(unsafe.Pointer(&member)), 1); r != 0 {
		t.Fatalf("add %s to Administrators: %v", name, windows.Errno(r))
	}
	return sid
}

// SetOwner makes sid the owner of path. Assigning an owner other than oneself
// needs SeRestorePrivilege, which an elevated administrator holds but has
// disabled; it is enabled only for this call.
func SetOwner(t testing.TB, path string, sid *windows.SID) {
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

// Owner returns the SID string of path's owner.
func Owner(t testing.TB, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	return owner.String()
}
