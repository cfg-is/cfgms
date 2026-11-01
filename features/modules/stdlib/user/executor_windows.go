// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package user

import (
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsExecutor manages local user accounts on Windows. State is read and
// group membership is changed through the in-process NetUser*/NetLocalGroup*
// APIs, which are locale-independent; account creation, deletion, full name
// and enabled state are written with net.exe. All write operations require
// Administrator privileges.
type windowsExecutor struct{}

func newExecutor() userExecutor {
	return &windowsExecutor{}
}

// netapi32 procedures that golang.org/x/sys/windows does not export.
// NewLazySystemDLL resolves the DLL from %SystemRoot%\System32.
var (
	modnetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserGetLocalGroups   = modnetapi32.NewProc("NetUserGetLocalGroups")
	procNetLocalGroupAddMembers = modnetapi32.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDelMembers = modnetapi32.NewProc("NetLocalGroupDelMembers")
)

const (
	nerrSuccess          = 0
	nerrUserNotFound     = 2221       // NERR_UserNotFound
	errorMemberNotInLG   = 1377       // ERROR_MEMBER_NOT_IN_ALIAS
	errorMemberInLG      = 1378       // ERROR_MEMBER_IN_ALIAS
	maxPreferredLength   = 0xFFFFFFFF // MAX_PREFERRED_LENGTH
	ufAccountDisable     = 0x0002     // UF_ACCOUNTDISABLE
	ufPasswdNotRequired  = 0x0020     // UF_PASSWD_NOTREQD
	userInfoLevelWithSID = 23
)

// userInfo23 is USER_INFO_23.
type userInfo23 struct {
	name     *uint16
	fullName *uint16
	comment  *uint16
	flags    uint32
	sid      *windows.SID
}

// localGroupUsersInfo0 is LOCALGROUP_USERS_INFO_0.
type localGroupUsersInfo0 struct {
	name *uint16
}

// localGroupMembersInfo0 is LOCALGROUP_MEMBERS_INFO_0.
type localGroupMembersInfo0 struct {
	sid *windows.SID
}

// account is what getState reads about a local account, plus its SID for
// group membership changes.
type account struct {
	state userState
	sid   *windows.SID
}

// getState reads the local account username with NetUserGetInfo and its direct
// local group memberships with NetUserGetLocalGroups. A user that does not
// exist (NERR_UserNotFound) is a zero userState with Exists=false; any other
// failure is an error.
func (e *windowsExecutor) getState(username string) (userState, error) {
	acct, err := readAccount(username)
	return acct.state, err
}

func readAccount(username string) (account, error) {
	name, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return account{}, fmt.Errorf("invalid user name %q: %w", username, err)
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, name, userInfoLevelWithSID, &buf); err != nil {
		if errors.Is(err, windows.Errno(nerrUserNotFound)) {
			return account{}, nil
		}
		return account{}, fmt.Errorf("read local user %s: %w", username, err)
	}
	defer func() { _ = windows.NetApiBufferFree(buf) }()
	info := (*userInfo23)(unsafe.Pointer(buf))

	sid, err := info.sid.Copy()
	if err != nil {
		return account{}, fmt.Errorf("read SID of local user %s: %w", username, err)
	}
	groups, err := readLocalGroups(name)
	if err != nil {
		return account{}, fmt.Errorf("read local groups of %s: %w", username, err)
	}
	return account{
		state: userState{
			Exists:        true,
			FullName:      windows.UTF16PtrToString(info.fullName),
			Groups:        groups,
			Locked:        info.flags&ufAccountDisable != 0,
			HasCredential: info.flags&ufPasswdNotRequired == 0,
		},
		sid: sid,
	}, nil
}

// readLocalGroups returns the sorted names of the local groups the user is a
// direct member of. Memberships through nested or domain groups are not
// included (no LG_INCLUDE_INDIRECT).
func readLocalGroups(username *uint16) ([]string, error) {
	var (
		buf            *byte
		entries, total uint32
	)
	r, _, _ := procNetUserGetLocalGroups.Call(0, uintptr(unsafe.Pointer(username)), 0, 0,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&total)))
	if buf != nil {
		defer func() { _ = windows.NetApiBufferFree(buf) }()
	}
	if r != nerrSuccess {
		return nil, windows.Errno(r)
	}
	if entries != total {
		return nil, fmt.Errorf("read %d of %d local groups", entries, total)
	}
	groups := make([]string, 0, entries)
	if entries > 0 {
		for _, g := range unsafe.Slice((*localGroupUsersInfo0)(unsafe.Pointer(buf)), entries) {
			groups = append(groups, windows.UTF16PtrToString(g.name))
		}
	}
	sort.Strings(groups)
	return groups, nil
}

// builtinUsersGroupName returns the local name of the built-in Users group
// (S-1-5-32-545), which differs between system languages.
func builtinUsersGroupName() (string, error) {
	return wellKnownGroupName(windows.WinBuiltinUsersSid)
}

// setState creates, modifies, or deletes the local user account to match desired.
// All write operations require Administrator privileges. HasCredential in desired
// is always ignored — this module never manages password material.
//
// Direct local group membership converges to desired.Groups: declared groups
// are added and every other direct group is removed, except the built-in Users
// group, which is never removed. The state is then read again, and a group
// list that still differs is an error.
func (e *windowsExecutor) setState(username string, desired userState) error {
	current, err := e.getState(username)
	if err != nil {
		return err
	}

	if !desired.Exists {
		if current.Exists {
			if out, err := exec.Command("net", "user", username, "/delete").CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
				return fmt.Errorf("net user %s /delete: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
			}
		}
		return nil
	}

	if !current.Exists {
		// Create account with no password (password management is out of scope).
		args := []string{"user", username, "/add", "/active:yes"}
		if desired.FullName != "" {
			args = append(args, "/fullname:"+desired.FullName)
		}
		if out, err := exec.Command("net", args...).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("net user %s /add: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
		}
		current.Exists = true
		current.FullName = desired.FullName
		current.Locked = false
	} else if desired.FullName != current.FullName {
		if out, err := exec.Command("net", "user", username, "/fullname:"+desired.FullName).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("net user %s /fullname: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
		}
	}

	// Apply active/locked state.
	if desired.Locked != current.Locked {
		activeVal := "yes"
		if desired.Locked {
			activeVal = "no"
		}
		if out, err := exec.Command("net", "user", username, "/active:"+activeVal).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("net user %s /active:%s: %w (output: %s)", username, activeVal, err, strings.TrimSpace(string(out)))
		}
	}

	manageGroups := len(desired.Groups) > 0
	var usersGroup string
	if manageGroups {
		if usersGroup, err = builtinUsersGroupName(); err != nil {
			return fmt.Errorf("resolve the built-in Users group: %w", err)
		}
		if err := convergeGroups(username, desired.Groups, usersGroup); err != nil {
			return err
		}
	}

	// Verify what was applied: a write that reported success but did not
	// take effect must not read as success.
	after, err := e.getState(username)
	if err != nil {
		return fmt.Errorf("verify local user %s: %w", username, err)
	}
	if !after.Exists {
		return fmt.Errorf("local user %s does not exist after it was applied", username)
	}
	if after.Locked != desired.Locked {
		return fmt.Errorf("local user %s: disabled state did not converge (want %v)", username, desired.Locked)
	}
	if after.FullName != desired.FullName {
		return fmt.Errorf("local user %s: full name did not converge", username)
	}
	if manageGroups {
		if missing, extra := groupChanges(after.Groups, desired.Groups, usersGroup); len(missing) > 0 || len(extra) > 0 {
			return fmt.Errorf("local groups of %s did not converge: missing %v, not declared %v", username, missing, extra)
		}
	}
	return nil
}

// convergeGroups adds username to every declared local group and removes it
// from every other direct group except the built-in Users group. Removal from
// BUILTIN\Administrators is refused when no other member would keep the group
// administered (see requireOtherAdministrator).
func convergeGroups(username string, declared []string, usersGroup string) error {
	// Read the account again: creation adds it to Users, and its SID is needed.
	acct, err := readAccount(username)
	if err != nil {
		return err
	}
	if !acct.state.Exists {
		return fmt.Errorf("local user %s does not exist after it was created", username)
	}
	add, remove := groupChanges(acct.state.Groups, declared, usersGroup)
	for _, g := range add {
		if err := changeLocalGroupMember(procNetLocalGroupAddMembers, g, acct.sid, errorMemberInLG); err != nil {
			return fmt.Errorf("add %s to local group %s: %w", username, g, err)
		}
	}
	if len(remove) == 0 {
		return nil
	}
	adminsGroup, err := wellKnownGroupName(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("resolve the built-in Administrators group: %w", err)
	}
	for _, g := range remove {
		if strings.EqualFold(g, adminsGroup) {
			if err := requireOtherAdministrator(adminsGroup, acct.sid); err != nil {
				return fmt.Errorf("remove %s from %s: %w", username, adminsGroup, err)
			}
		}
		if err := changeLocalGroupMember(procNetLocalGroupDelMembers, g, acct.sid, errorMemberNotInLG); err != nil {
			return fmt.Errorf("remove %s from local group %s: %w", username, g, err)
		}
	}
	return nil
}

// localGroupMembersInfo2 is LOCALGROUP_MEMBERS_INFO_2.
type localGroupMembersInfo2 struct {
	sid           *windows.SID
	sidUsage      uint32
	domainAndName *uint16
}

var procNetLocalGroupGetMembers = modnetapi32.NewProc("NetLocalGroupGetMembers")

// errLastAdministrator is returned when removing a user from
// BUILTIN\Administrators would leave the group without another member that
// can administer the host.
var errLastAdministrator = errors.New("refusing to remove the last enabled member of the Administrators group")

// requireOtherAdministrator returns errLastAdministrator unless the local
// Administrators group has a direct member other than user that keeps it
// administered: a group, a domain account, or an enabled local account.
func requireOtherAdministrator(adminsGroup string, user *windows.SID) error {
	g, err := windows.UTF16PtrFromString(adminsGroup)
	if err != nil {
		return err
	}
	var (
		buf            *byte
		entries, total uint32
	)
	r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(g)), 2,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&total)), 0)
	if buf != nil {
		defer func() { _ = windows.NetApiBufferFree(buf) }()
	}
	if r != nerrSuccess {
		return fmt.Errorf("read members of %s: %w", adminsGroup, windows.Errno(r))
	}
	if entries != total {
		return fmt.Errorf("read %d of %d members of %s", entries, total, adminsGroup)
	}
	if entries == 0 {
		return errLastAdministrator
	}
	computer, err := windows.ComputerName()
	if err != nil {
		return err
	}
	for _, m := range unsafe.Slice((*localGroupMembersInfo2)(unsafe.Pointer(buf)), entries) {
		if m.sid == nil || m.sid.Equals(user) {
			continue
		}
		if memberKeepsAdministered(m.sidUsage, windows.UTF16PtrToString(m.domainAndName), computer, localAccountEnabled) {
			return nil
		}
	}
	return errLastAdministrator
}

// memberKeepsAdministered reports whether a member of the Administrators
// group, of SID type sidUsage named domainAndName, keeps the host
// administered: a group, a domain user account, or an enabled local user
// account (localEnabled). Deleted, invalid and unknown SIDs, which orphaned
// entries commonly are, do not count.
func memberKeepsAdministered(sidUsage uint32, domainAndName, computer string, localEnabled func(name string) bool) bool {
	switch sidUsage {
	case uint32(windows.SidTypeGroup), uint32(windows.SidTypeWellKnownGroup), uint32(windows.SidTypeAlias):
		return true
	case uint32(windows.SidTypeUser):
		domain, name, found := strings.Cut(domainAndName, `\`)
		if found && strings.EqualFold(domain, computer) {
			return localEnabled(name)
		}
		return found // a domain account
	default:
		return false
	}
}

// localAccountEnabled reports whether the local account name exists and is
// not disabled. A failed read counts as not enabled.
func localAccountEnabled(name string) bool {
	acct, err := readAccount(name)
	return err == nil && acct.state.Exists && !acct.state.Locked
}

// wellKnownGroupName returns the local name of a well-known group, which
// differs between system languages.
func wellKnownGroupName(sidType windows.WELL_KNOWN_SID_TYPE) (string, error) {
	sid, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		return "", err
	}
	name, _, _, err := sid.LookupAccount("")
	return name, err
}

// groupChanges compares the direct groups current with the declared groups
// and returns the declared groups to add and the undeclared groups to remove.
// Names compare case-insensitively, as Windows group names do. The built-in
// Users group (named usersGroup on this system) is never removed.
func groupChanges(current, declared []string, usersGroup string) (add, remove []string) {
	for _, d := range declared {
		if !containsFold(current, d) {
			add = append(add, d)
		}
	}
	for _, c := range current {
		if !containsFold(declared, c) && !strings.EqualFold(c, usersGroup) {
			remove = append(remove, c)
		}
	}
	return add, remove
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// changeLocalGroupMember adds the account sid to, or removes it from, the
// local group (NetLocalGroupAddMembers / NetLocalGroupDelMembers, level 0).
// The status already, meaning the change is already in place, is success.
func changeLocalGroupMember(proc *windows.LazyProc, group string, sid *windows.SID, already uintptr) error {
	g, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return err
	}
	member := localGroupMembersInfo0{sid: sid}
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(g)), 0, uintptr(unsafe.Pointer(&member)), 1)
	if r != nerrSuccess && r != already {
		return windows.Errno(r)
	}
	return nil
}
