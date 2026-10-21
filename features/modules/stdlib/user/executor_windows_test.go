// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package user

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	procNetLocalGroupAdd = modnetapi32.NewProc("NetLocalGroupAdd")
	procNetLocalGroupDel = modnetapi32.NewProc("NetLocalGroupDel")
)

// requireElevated skips t unless the test runs elevated: creating local users
// and groups needs an administrator, as the steward (SYSTEM) and the native
// Windows CI runners are.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator to create local users and groups")
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// createLocalGroup creates a local group named name (NetLocalGroupAdd, level
// 0) and deletes it when the test ends.
func createLocalGroup(t *testing.T, name string) string {
	t.Helper()
	p, err := windows.UTF16PtrFromString(name)
	require.NoError(t, err)
	info := struct{ name *uint16 }{name: p}
	r, _, _ := procNetLocalGroupAdd.Call(0, 0, uintptr(unsafe.Pointer(&info)), 0)
	require.Zero(t, r, "NetLocalGroupAdd %s: %v", name, windows.Errno(r))
	t.Cleanup(func() { _, _, _ = procNetLocalGroupDel.Call(0, uintptr(unsafe.Pointer(p))) })
	return name
}

// testUser returns a fresh local user name and deletes that account when the
// test ends.
func testUser(t *testing.T, e *windowsExecutor) string {
	t.Helper()
	name := "cfgmsu" + randomSuffix(t)
	t.Cleanup(func() { _ = e.setState(name, userState{Exists: false}) })
	return name
}

func usersGroup(t *testing.T) string {
	t.Helper()
	name, err := builtinUsersGroupName()
	require.NoError(t, err)
	return name
}

func TestWindowsSetState_RemovesUndeclaredGroupButKeepsUsers(t *testing.T) {
	requireElevated(t)
	e := &windowsExecutor{}
	keep := createLocalGroup(t, "cfgmsk"+randomSuffix(t))
	drop := createLocalGroup(t, "cfgmsd"+randomSuffix(t))
	name := testUser(t, e)

	require.NoError(t, e.setState(name, userState{Exists: true, Groups: []string{keep, drop}}))
	before, err := e.getState(name)
	require.NoError(t, err)
	require.Subset(t, before.Groups, []string{keep, drop, usersGroup(t)}, "precondition: the user is in both groups and Users")

	require.NoError(t, e.setState(name, userState{Exists: true, Groups: []string{keep}}))

	after, err := e.getState(name)
	require.NoError(t, err)
	assert.Contains(t, after.Groups, keep)
	assert.NotContains(t, after.Groups, drop, "a group removed from the declared list must be left")
	assert.Contains(t, after.Groups, usersGroup(t), "the built-in Users group is never removed")
}

func TestWindowsGetState_DisabledAccountWithNonASCIIGroup(t *testing.T) {
	requireElevated(t)
	e := &windowsExecutor{}
	plain := createLocalGroup(t, "cfgmsp"+randomSuffix(t))
	nonASCII := createLocalGroup(t, "cfgms-grün-Ω"+randomSuffix(t))
	name := testUser(t, e)
	require.NoError(t, e.setState(name, userState{Exists: true, Locked: true, Groups: []string{plain, nonASCII}}))

	got, err := e.getState(name)
	require.NoError(t, err)

	want := []string{plain, nonASCII, usersGroup(t)}
	sort.Strings(want)
	assert.True(t, got.Exists)
	assert.True(t, got.Locked, "a disabled account reads as locked")
	assert.Equal(t, want, got.Groups, "the exact direct local-group list")
}

func TestWindowsGetState_BuiltinGuestReadsDisabled(t *testing.T) {
	// The built-in Guest account is disabled by default and has a localized
	// name; reading it needs no elevation.
	computer, err := windows.ComputerName()
	require.NoError(t, err)
	domain, _, _, err := windows.LookupSID("", computer)
	require.NoError(t, err)
	sid, err := windows.CreateWellKnownDomainSid(windows.WinAccountGuestSid, domain)
	require.NoError(t, err)
	guest, _, _, err := sid.LookupAccount("")
	require.NoError(t, err)

	got, err := (&windowsExecutor{}).getState(guest)
	require.NoError(t, err)
	assert.True(t, got.Exists)
	assert.True(t, got.Locked, "the built-in Guest account is disabled")
	assert.NotEmpty(t, got.Groups, "Guest is a direct member of the built-in Guests group")
}

func TestWindowsGetState_MissingAccountIsAbsentNotError(t *testing.T) {
	got, err := (&windowsExecutor{}).getState("cfgmsnone" + randomSuffix(t))
	require.NoError(t, err)
	assert.False(t, got.Exists)
}

func TestWindowsGetState_InvalidAccountNameIsError(t *testing.T) {
	// NetUserGetInfo answers a 300-character name (local account names are at
	// most 20) with ERROR_INVALID_PARAMETER, not NERR_UserNotFound.
	got, err := (&windowsExecutor{}).getState(strings.Repeat("a", 300))
	assert.Error(t, err, "a read failure other than user-not-found must not read as an absent user")
	assert.False(t, got.Exists)
}

func TestGroupChanges(t *testing.T) {
	add, remove := groupChanges([]string{"Administrators", "Users", "Backup Operators"}, []string{"administrators", "Remote Desktop Users"}, "Users")
	assert.Equal(t, []string{"Remote Desktop Users"}, add)
	assert.Equal(t, []string{"Backup Operators"}, remove, "Users is never removed; names compare case-insensitively")
}
