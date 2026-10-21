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
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return "", err
	}
	name, _, _, err := sid.LookupAccount("")
	return name, err
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

	usersGroup, err := builtinUsersGroupName()
	if err != nil {
		return fmt.Errorf("resolve the built-in Users group: %w", err)
	}
	// Read the account again: creation adds it to Users, and its SID is needed.
	acct, err := readAccount(username)
	if err != nil {
		return err
	}
	if !acct.state.Exists {
		return fmt.Errorf("local user %s does not exist after it was created", username)
	}
	add, remove := groupChanges(acct.state.Groups, desired.Groups, usersGroup)
	for _, g := range add {
		if err := changeLocalGroupMember(procNetLocalGroupAddMembers, g, acct.sid, errorMemberInLG); err != nil {
			return fmt.Errorf("add %s to local group %s: %w", username, g, err)
		}
	}
	for _, g := range remove {
		if err := changeLocalGroupMember(procNetLocalGroupDelMembers, g, acct.sid, errorMemberNotInLG); err != nil {
			return fmt.Errorf("remove %s from local group %s: %w", username, g, err)
		}
	}

	after, err := e.getState(username)
	if err != nil {
		return fmt.Errorf("verify local groups of %s: %w", username, err)
	}
	if missing, extra := groupChanges(after.Groups, desired.Groups, usersGroup); len(missing) > 0 || len(extra) > 0 {
		return fmt.Errorf("local groups of %s did not converge: missing %v, not declared %v", username, missing, extra)
	}
	return nil
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
