// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build windows

package package_module

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// chocoWriteMask is every access right that lets a principal modify the
// object, its metadata, its children, or its security descriptor.
const chocoWriteMask = windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	0x40 | // FILE_DELETE_CHILD
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.GENERIC_WRITE |
	windows.GENERIC_ALL

// sidTrustedInstaller is NT SERVICE\TrustedInstaller.
const sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// chocoTrusted returns an error unless the file at path and its parent
// directory are owned by SYSTEM or BUILTIN\Administrators, are not reparse
// points, and grant no write-capable access to any other principal. Read and
// execute grants (a stock Chocolatey install leaves them for Users) are
// allowed. The steward runs Chocolatey as SYSTEM, so anything a standard user
// can write here is a local privilege escalation.
func chocoTrusted(path string) error {
	if err := checkTrustedObject(path); err != nil {
		return err
	}
	return checkTrustedObject(filepath.Dir(path))
}

func checkTrustedObject(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("%s: invalid path: %w", path, err)
	}
	// FILE_FLAG_OPEN_REPARSE_POINT opens a link itself rather than its
	// target, so a reparse point is seen rather than traversed. Security info and
	// attributes are then read from this one handle (no check/use gap).
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("%s: cannot open for verification: %w", path, err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("%s: cannot read attributes: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s: is a reparse point", path)
	}

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: cannot read security descriptor: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s: cannot determine owner", path)
	}
	if !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("%s: owner is not SYSTEM or Administrators", path)
	}
	return checkDACLNoUntrustedWrite(path, sd)
}

func checkDACLNoUntrustedWrite(path string, sd *windows.SECURITY_DESCRIPTOR) error {
	acl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: cannot read DACL: %w", path, err)
	}
	if acl == nil {
		return fmt.Errorf("%s: has no DACL (full access for everyone)", path)
	}
	installer, err := windows.StringToSid(sidTrustedInstaller)
	if err != nil {
		return fmt.Errorf("%s: internal SID error: %w", path, err)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("%s: cannot read DACL entry: %w", path, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, 9: // 9: ACCESS_ALLOWED_CALLBACK, same leading layout
		case windows.ACCESS_DENIED_ACE_TYPE, 2, 3, 10, 13, 14, 15, 0x11, 0x12, 0x13:
			// deny, audit, alarm, denied-callback, audit/alarm callbacks and
			// label/attribute/scope ACEs never grant access.
			continue
		default:
			return fmt.Errorf("%s: has an unrecognised DACL entry type", path)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinLocalSystemSid) ||
			sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
			sid.Equals(installer) {
			continue
		}
		if uint32(ace.Mask)&chocoWriteMask != 0 {
			return fmt.Errorf("%s: grants write access to a principal other than SYSTEM or Administrators", path)
		}
	}
	return nil
}
