// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// authz.dll bindings. NewLazySystemDLL resolves from %SystemRoot%\System32.
var (
	modauthz                           = windows.NewLazySystemDLL("authz.dll")
	procAuthzInitializeResourceManager = modauthz.NewProc("AuthzInitializeResourceManager")
	procAuthzFreeResourceManager       = modauthz.NewProc("AuthzFreeResourceManager")
	procAuthzInitializeContextFromSid  = modauthz.NewProc("AuthzInitializeContextFromSid")
	procAuthzFreeContext               = modauthz.NewProc("AuthzFreeContext")
	procAuthzGetInformationFromContext = modauthz.NewProc("AuthzGetInformationFromContext")
)

const (
	authzRMFlagNoAudit         = 0x1 // AUTHZ_RM_FLAG_NO_AUDIT
	authzContextInfoGroupsSids = 2   // AuthzContextInfoGroupsSids
)

// isAdministratorsMember reports whether the account sid is a member of the
// local BUILTIN\Administrators group, directly or through nested local or
// domain groups. The group set is the one Windows would put in a token for that
// account (AuthzInitializeContextFromSid), so it matches what the account gets
// when it logs on. An account whose groups cannot be computed (a deleted or
// unresolvable account, a group SID, an unreachable domain) is reported as not a
// member, with the reason.
func isAdministratorsMember(sid *windows.SID) (bool, error) {
	var rm windows.Handle
	if r, _, err := procAuthzInitializeResourceManager.Call(authzRMFlagNoAudit, 0, 0, 0, 0, uintptr(unsafe.Pointer(&rm))); r == 0 {
		return false, fmt.Errorf("initialize authorization resource manager: %w", err)
	}
	defer func() { _, _, _ = procAuthzFreeResourceManager.Call(uintptr(rm)) }()

	// The LUID identifier argument is passed by value; it is 8 bytes and zero,
	// one register on amd64 and arm64.
	var ctx windows.Handle
	if r, _, err := procAuthzInitializeContextFromSid.Call(0, uintptr(unsafe.Pointer(sid)), uintptr(rm), 0, 0, 0, uintptr(unsafe.Pointer(&ctx))); r == 0 {
		return false, fmt.Errorf("compute groups of %s: %w", sid.String(), err)
	}
	defer func() { _, _, _ = procAuthzFreeContext.Call(uintptr(ctx)) }()

	var size uint32
	r, _, err := procAuthzGetInformationFromContext.Call(uintptr(ctx), authzContextInfoGroupsSids, 0, uintptr(unsafe.Pointer(&size)), 0)
	if r == 0 && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return false, fmt.Errorf("read groups of %s: %w", sid.String(), err)
	}
	if size == 0 {
		return false, nil
	}
	// []uint64 keeps the TOKEN_GROUPS buffer pointer-aligned.
	buf := make([]uint64, (size+7)/8)
	if r, _, err := procAuthzGetInformationFromContext.Call(uintptr(ctx), authzContextInfoGroupsSids, uintptr(size), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&buf[0]))); r == 0 {
		return false, fmt.Errorf("read groups of %s: %w", sid.String(), err)
	}
	groups := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
	for _, g := range groups.AllGroups() {
		if g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 && g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return true, nil
		}
	}
	return false, nil
}
