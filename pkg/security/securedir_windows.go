// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// adminOnlyDACLSDDL is a protected DACL (P: no inherited ACEs) granting full
// control to SYSTEM and BUILTIN\Administrators only, inheritable to all child
// files and directories (OICI).
const adminOnlyDACLSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// EnsureAdminOnlyDir ensures path exists and is readable and writable by SYSTEM
// and BUILTIN\Administrators only.
//
// An existing directory whose owner is neither SYSTEM nor BUILTIN\Administrators
// is refused with ErrUntrustedDirOwner and left untouched. Otherwise the
// directory gets a protected DACL (no inherited ACEs) with full control for
// SYSTEM and Administrators, inheritable by children; Windows propagates it to
// existing children that inherit. A directory created by this call whose owner
// is not already trusted is assigned to BUILTIN\Administrators. Uses in-process
// Win32 security APIs only.
func EnsureAdminOnlyDir(path string) error {
	created := false
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("%s is a link or reparse point, refusing to secure it", path)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", path)
		}
	case os.IsNotExist(err):
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("create directory %s: %w", path, err)
		}
		created = true
	default:
		return fmt.Errorf("stat directory %s: %w", path, err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	trusted, err := ownerIsTrusted(sd)
	if err != nil {
		return fmt.Errorf("read owner of %s: %w", path, err)
	}

	secInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var owner *windows.SID
	if !trusted {
		if !created {
			return fmt.Errorf("%s: %w", path, ErrUntrustedDirOwner)
		}
		// We just created this directory, so assigning it to Administrators
		// cannot hand control to anyone who did not already have it.
		owner, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			return fmt.Errorf("build Administrators SID: %w", err)
		}
		secInfo |= windows.OWNER_SECURITY_INFORMATION
	}

	dsd, err := windows.SecurityDescriptorFromString(adminOnlyDACLSDDL)
	if err != nil {
		return fmt.Errorf("build admin-only security descriptor: %w", err)
	}
	dacl, _, err := dsd.DACL()
	if err != nil {
		return fmt.Errorf("read admin-only DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, secInfo, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply admin-only security descriptor to %s: %w", path, err)
	}
	return nil
}

// ownerIsTrusted reports whether the descriptor's owner is SYSTEM or
// BUILTIN\Administrators.
func ownerIsTrusted(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil {
		return false, nil
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid), nil
}
