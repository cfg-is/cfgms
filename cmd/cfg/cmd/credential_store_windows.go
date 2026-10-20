// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// credentialOpenFlags opens the object itself, never the target of a junction or
// symbolic link, and allows directories to be opened.
const credentialOpenFlags = windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT

// credentialShareAll lets the security handle coexist with any other open.
const credentialShareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// secureCredentialsDir makes dir readable and writable by the current user and
// SYSTEM only. Mode bits set no ACL on Windows, so without this the directory
// would inherit whatever the user profile grants.
//
// A missing directory is created with its final security descriptor (owner the
// current user, protected DACL with full control for the current user and
// SYSTEM, inheritable to the files in it), so it never exists with the
// inherited profile ACL. An existing directory is checked on a handle that does
// not follow reparse points: a link or non-directory is refused, and so is a
// directory whose owner is neither the current user nor SYSTEM, since its
// owner could grant itself access again. Otherwise it gets the protected DACL.
// Uses in-process Win32 security APIs only.
func secureCredentialsDir(dir string) error {
	dir = filepath.Clean(dir)
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	if parent := filepath.Dir(dir); parent != dir {
		// #nosec G301 - parent of the credentials directory (the user's config dir)
		if err := os.MkdirAll(parent, 0700); err != nil {
			return fmt.Errorf("create parent of %s: %w", dir, err)
		}
	}

	sid := user.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + credentialDirDACLSDDL(sid))
	if err != nil {
		return fmt.Errorf("build credentials directory security descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("invalid credentials directory %s: %w", dir, err)
	}
	err = windows.CreateDirectory(p, &sa)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create credentials directory %s: %w", dir, err)
	}

	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC, credentialShareAll, nil,
		windows.OPEN_EXISTING, credentialOpenFlags, 0)
	if err != nil {
		return fmt.Errorf("open credentials directory %s: %w", dir, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("stat credentials directory %s: %w", dir, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("credentials directory %s is a link or reparse point, refusing to use it", dir)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("credentials directory %s exists and is not a directory", dir)
	}

	osd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read owner of credentials directory %s: %w", dir, err)
	}
	owner, _, err := osd.Owner()
	if err != nil {
		return fmt.Errorf("read owner of credentials directory %s: %w", dir, err)
	}
	if owner == nil || (!owner.Equals(user) && !owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return fmt.Errorf("credentials directory %s is owned by a principal other than the current user or SYSTEM, refusing to use it; "+
			"if you created it (for example from an elevated shell), remove it and store the credential again with 'cfg connect' or 'cfg credential enroll'", dir)
	}

	dacl, err := daclFromSDDL(credentialDirDACLSDDL(sid))
	if err != nil {
		return err
	}
	secInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, secInfo, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict credentials directory %s to the current user and SYSTEM: %w", dir, err)
	}
	return nil
}

// secureCredentialFile gives the credential file at path its own protected
// DACL (current user and SYSTEM only), so it stays private even if the
// directory's ACL is later loosened. The file is opened without following
// reparse points.
func secureCredentialFile(path string) error {
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	dacl, err := daclFromSDDL(credentialFileDACLSDDL(user.String()))
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("invalid credential path %s: %w", path, err)
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC, credentialShareAll, nil,
		windows.OPEN_EXISTING, credentialOpenFlags, 0)
	if err != nil {
		return fmt.Errorf("open credential file %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	secInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, secInfo, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict credential file %s to the current user and SYSTEM: %w", path, err)
	}
	return nil
}

// credentialDirDACLSDDL is a protected DACL (P: no inherited ACEs) granting
// full control to the user SID and SYSTEM, inheritable by files and
// subdirectories (OICI).
func credentialDirDACLSDDL(userSID string) string {
	return "D:P(A;OICI;FA;;;" + userSID + ")(A;OICI;FA;;;SY)"
}

// credentialFileDACLSDDL is credentialDirDACLSDDL for a file, which has no
// children to pass ACEs on to.
func credentialFileDACLSDDL(userSID string) string {
	return "D:P(A;;FA;;;" + userSID + ")(A;;FA;;;SY)"
}

func daclFromSDDL(sddl string) (*windows.ACL, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build credential security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, fmt.Errorf("read credential DACL: %w", err)
	}
	return dacl, nil
}

// currentUserSID returns the SID of the user the process runs as.
func currentUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read current user: %w", err)
	}
	return tu.User.Sid, nil
}
