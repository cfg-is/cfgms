// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// adminOnlyDACLSDDL is a protected DACL (P: no inherited ACEs) granting full
// control to SYSTEM and BUILTIN\Administrators only, inheritable to all child
// files and directories (OICI).
const adminOnlyDACLSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// adminOwnedSDDL is adminOnlyDACLSDDL with BUILTIN\Administrators as owner. It
// is the descriptor a new directory is created with, so the directory never
// exists, even briefly, with the inherited (user-writable) %ProgramData% ACL.
const adminOwnedSDDL = "O:BA" + adminOnlyDACLSDDL

// openFlags opens the object itself, never the target of a junction or
// symbolic link, and allows directories to be opened.
const openFlags = windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT

// shareAll lets the security handle coexist with any other open of the object.
const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// EnsureAdminOnlyDir ensures path exists and is readable and writable by SYSTEM
// and BUILTIN\Administrators only.
//
// A missing directory is created atomically with its final security descriptor
// (owner BUILTIN\Administrators, protected admin-only DACL), so there is no
// window in which it is a directory someone else planted or carries the
// inherited parent ACL. If the directory already exists (including one that
// appeared concurrently), every check and the DACL write happen on one handle
// opened without following reparse points:
//
//   - a link, junction or other reparse point, or a non-directory, is refused;
//   - a directory whose owner is neither SYSTEM nor BUILTIN\Administrators is
//     refused with ErrUntrustedDirOwner, and nothing is changed;
//   - every existing entry below it is checked without following reparse
//     points. A reparse point or an entry owned by an untrusted principal is
//     refused before anything is changed.
//
// Otherwise the directory gets a protected DACL (no inherited ACEs) with full
// control for SYSTEM and Administrators, inheritable by children; Windows
// propagates it to existing children that inherit. The tree is then checked
// again, and any entry that is not owned by a trusted principal, is a reparse
// point, or still grants access to any principal other than SYSTEM and
// Administrators is refused (ErrUntrustedDirOwner / ErrUntrustedDirEntry).
// Uses in-process Win32 security APIs only.
func EnsureAdminOnlyDir(path string) error {
	path = filepath.Clean(path)
	created, err := createAdminOnlyDir(path)
	if err != nil {
		return err
	}

	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC)
	if created {
		access |= windows.WRITE_OWNER
	}
	h, err := openNoFollow(path, access)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) && !created {
			// The handle we could not open is never written through; this
			// read-only open only decides which refusal to report.
			if rootOwnerIsUntrusted(path) {
				return fmt.Errorf("%s: %w", path, ErrUntrustedDirOwner)
			}
		}
		return fmt.Errorf("open directory %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if err := requirePlainDir(h, path); err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
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
		// This call created the directory with an admin-only DACL, so
		// assigning it to Administrators cannot hand control to anyone who did
		// not already have it.
		owner, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			return fmt.Errorf("build Administrators SID: %w", err)
		}
		secInfo |= windows.OWNER_SECURITY_INFORMATION
	}

	// Refuse planted entries before changing anything.
	if !created {
		if err := checkTree(path, false); err != nil {
			return err
		}
	}

	dacl, err := adminOnlyDACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, secInfo, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply admin-only security descriptor to %s: %w", path, err)
	}

	// Verify the locked-down tree: catches entries planted before the DACL
	// landed and children whose explicit ACEs the propagation left in place.
	return checkTree(path, true)
}

// createAdminOnlyDir creates path with the admin-only security descriptor. It
// reports created=false when path already exists (as anything); the caller
// then treats it as an existing object and verifies it on a handle.
func createAdminOnlyDir(path string) (created bool, err error) {
	parent := filepath.Dir(path)
	if parent != path {
		if err := os.MkdirAll(parent, 0700); err != nil {
			return false, fmt.Errorf("create parent directory of %s: %w", path, err)
		}
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, fmt.Errorf("invalid directory path %s: %w", path, err)
	}

	err = createDirWithSDDL(p, adminOwnedSDDL)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		// The token cannot name Administrators as owner (not elevated). Create
		// the directory with the same protected DACL and the caller's default
		// owner; EnsureAdminOnlyDir then assigns the owner or fails.
		err = createDirWithSDDL(p, adminOnlyDACLSDDL)
	}
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return false, nil
	default:
		return false, fmt.Errorf("create directory %s: %w", path, err)
	}
}

func createDirWithSDDL(path *uint16, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build admin-only security descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	return windows.CreateDirectory(path, &sa)
}

func adminOnlyDACL() (*windows.ACL, error) {
	dsd, err := windows.SecurityDescriptorFromString(adminOnlyDACLSDDL)
	if err != nil {
		return nil, fmt.Errorf("build admin-only security descriptor: %w", err)
	}
	dacl, _, err := dsd.DACL()
	if err != nil {
		return nil, fmt.Errorf("read admin-only DACL: %w", err)
	}
	return dacl, nil
}

// openNoFollow opens path itself (never a reparse target) for access.
func openNoFollow(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access, shareAll, nil, windows.OPEN_EXISTING, openFlags, 0)
}

// attributesOf returns the file attributes of the object behind h.
func attributesOf(h windows.Handle) (uint32, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0, err
	}
	return info.FileAttributes, nil
}

// requirePlainDir refuses a reparse point or a non-directory behind h.
func requirePlainDir(h windows.Handle, path string) error {
	attrs, err := attributesOf(h)
	if err != nil {
		return fmt.Errorf("stat directory %s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a link or reparse point, refusing to secure it", path)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	return nil
}

// rootOwnerIsUntrusted reports whether the existing path can be read and is
// owned by an untrusted principal, so a directory the caller cannot open for
// WRITE_DAC is still reported as the ownership refusal it is. It returns false
// when the owner cannot be determined; the caller then reports its own open
// error instead.
func rootOwnerIsUntrusted(path string) bool {
	h, err := openNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	trusted, err := ownerIsTrusted(sd)
	return err == nil && !trusted
}

// checkTree verifies every entry below root without following reparse points.
// Each entry must not be a reparse point and must be owned by a trusted
// principal. With checkDACL, each entry's DACL must also grant access to no
// principal other than SYSTEM and Administrators.
func checkTree(root string, checkDACL bool) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("list directory %s: %w", root, err)
	}
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		isDir, err := checkEntry(p, checkDACL)
		if err != nil {
			return err
		}
		if isDir {
			if err := checkTree(p, checkDACL); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkEntry inspects one entry on a handle that does not follow reparse
// points and reports whether it is a (plain) directory to descend into.
func checkEntry(path string, checkDACL bool) (isDir bool, err error) {
	h, err := openNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	attrs, err := attributesOf(h)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, fmt.Errorf("%s is a link or reparse point: %w", path, ErrUntrustedDirEntry)
	}

	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION)
	if checkDACL {
		info |= windows.DACL_SECURITY_INFORMATION
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, info)
	if err != nil {
		return false, fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	trusted, err := ownerIsTrusted(sd)
	if err != nil {
		return false, fmt.Errorf("read owner of %s: %w", path, err)
	}
	if !trusted {
		return false, fmt.Errorf("%s: %w", path, ErrUntrustedDirOwner)
	}
	if checkDACL {
		ok, err := daclIsAdminOnly(sd)
		if err != nil {
			return false, fmt.Errorf("read DACL of %s: %w", path, err)
		}
		if !ok {
			return false, fmt.Errorf("%s grants access to a principal other than SYSTEM or BUILTIN\\Administrators: %w", path, ErrUntrustedDirEntry)
		}
	}
	return attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0, nil
}

// daclIsAdminOnly reports whether every allow ACE in the descriptor's DACL
// names SYSTEM or BUILTIN\Administrators. Deny ACEs only remove access and are
// accepted; a NULL DACL (everyone full control) and any ACE type other than a
// plain allow or deny ACE are refused.
func daclIsAdminOnly(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	acl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if acl == nil {
		return false, nil
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return false, err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sid.IsWellKnown(windows.WinLocalSystemSid) &&
				!sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	return true, nil
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
	if owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true, nil
	}
	return ownerIsElevatedCaller(owner), nil
}

// ownerIsElevatedCaller reports whether owner is the user of the current
// process and that process is elevated (an administrator's token). An elevated
// administrator account may own a directory it created, e.g. one under its own
// profile or temp directory; a non-admin principal still never qualifies.
func ownerIsElevatedCaller(owner *windows.SID) bool {
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		return false
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	return user.User.Sid.Equals(owner)
}
