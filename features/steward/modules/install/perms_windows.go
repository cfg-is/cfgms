// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package install

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// protectedDACL is the SDDL of the DACL every protected directory gets: a
// protected (P) DACL with SYSTEM and Administrators full control and Users
// read/execute, all inheritable (OICI) so children created below keep it.
const protectedDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"

func ensureProtectedDir(path string) error {
	// #nosec G301 -- the DACL below replaces the mode.
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create protected directory: %w", os.ErrPermission)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrTreeNotProtected
	}
	sd, err := windows.SecurityDescriptorFromString(protectedDACL)
	if err != nil {
		return ErrTreeNotProtected
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return ErrTreeNotProtected
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return ErrTreeNotProtected
	}
	return nil
}

func checkProtectedDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return ErrTreeNotProtected
	}
	return checkACL(path)
}

func checkProtectedTree(root string) error {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() {
		return ErrTreeNotProtected
	}
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return ErrTreeNotProtected
		}
		// A symlink or junction is a reparse point, never a plain entry.
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 || (!d.IsDir() && !d.Type().IsRegular()) {
			return ErrTreeNotProtected
		}
		return checkACL(p)
	})
	if walkErr != nil {
		return ErrTreeNotProtected
	}
	return nil
}

// checkACL refuses a path whose DACL is absent (everyone full access), whose
// owner is neither SYSTEM, Administrators, TrustedInstaller nor the process's own
// user (an owner can always rewrite the DACL), or that has an allow entry
// granting write-class rights to any other principal.
func checkACL(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrTreeNotProtected
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return ErrTreeNotProtected
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !ownerTrusted(owner.String()) {
		return ErrTreeNotProtected
	}
	return checkSDDL(sd.String())
}

// ownerTrusted reports whether the owner SID may own a protected entry.
func ownerTrusted(sid string) bool {
	if trustedPrincipals[sid] {
		return true
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && user.User.Sid.String() == sid
}
