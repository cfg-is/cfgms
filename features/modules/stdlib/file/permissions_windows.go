//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package file

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/features/modules"
)

// platformSupportsPermissions returns false on Windows because NTFS uses
// ACLs, not Unix permission bits. os.FileMode permission bits are not
// enforced by the filesystem and read back as 0666 regardless of what
// was requested.
func platformSupportsPermissions() bool {
	return false
}

// getFilePermissions returns 0 on Windows since Unix permission bits
// are not meaningful on NTFS.
func getFilePermissions(_ os.FileInfo) int {
	return 0
}

// defaultFileMode returns the default file mode for new files on Windows.
// NTFS ignores these bits; actual access control uses Windows ACLs.
func defaultFileMode() os.FileMode {
	return 0666
}

// getFileACL reads the NTFS DACL and owner for the file at path.
func getFileACL(path string) (*modules.WindowsACL, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("GetNamedSecurityInfo: %w", err)
	}
	if sd == nil {
		return nil, nil
	}

	var ownerName string
	if ownerSID, _, oErr := sd.Owner(); oErr == nil && ownerSID != nil {
		if account, domain, _, lErr := ownerSID.LookupAccount(""); lErr == nil {
			if domain != "" {
				ownerName = domain + `\` + account
			} else {
				ownerName = account
			}
		}
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, fmt.Errorf("DACL: %w", err)
	}

	var entries []modules.ACLEntry
	if dacl != nil {
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if gErr := windows.GetAce(dacl, i, &ace); gErr != nil {
				continue
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				continue
			}
			//nolint:gosec // unsafe required to extract SID from ACE's embedded SidStart field
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			account, domain, _, lErr := sid.LookupAccount("")
			if lErr != nil {
				continue
			}
			var principal string
			if domain != "" {
				principal = domain + `\` + account
			} else {
				principal = account
			}
			entries = append(entries, modules.ACLEntry{
				Principal: principal,
				Access:    maskToAccessString(ace.Mask),
			})
		}
	}

	return &modules.WindowsACL{
		Owner:   ownerName,
		Entries: entries,
	}, nil
}

// setFileACL applies the NTFS DACL and owner declared in acl to the file at path.
func setFileACL(path string, acl *modules.WindowsACL) error {
	if acl == nil {
		return nil
	}

	// Build EXPLICIT_ACCESS entries; keep *SID pointers alive until the API call returns.
	sids := make([]*windows.SID, 0, len(acl.Entries))
	explicitEntries := make([]windows.EXPLICIT_ACCESS, 0, len(acl.Entries))

	for _, entry := range acl.Entries {
		mask, err := accessStringToMask(entry.Access)
		if err != nil {
			return err
		}
		sid, _, _, err := windows.LookupSID("", entry.Principal)
		if err != nil {
			return fmt.Errorf("lookup principal %q: %w", entry.Principal, err)
		}
		sids = append(sids, sid)
		explicitEntries = append(explicitEntries, windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}

	// ACLFromEntries calls SetEntriesInAclW; keep sids alive via runtime.KeepAlive.
	dacl, err := windows.ACLFromEntries(explicitEntries, nil)
	runtime.KeepAlive(sids)
	if err != nil {
		return fmt.Errorf("ACLFromEntries: %w", err)
	}

	// PROTECTED_DACL_SECURITY_INFORMATION prevents inheriting ACEs from the parent.
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("SetNamedSecurityInfo (DACL): %w", err)
	}

	if acl.Owner != "" {
		ownerSID, _, _, err := windows.LookupSID("", acl.Owner)
		if err != nil {
			return fmt.Errorf("lookup owner %q: %w", acl.Owner, err)
		}
		if sErr := windows.SetNamedSecurityInfo(
			path,
			windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION,
			ownerSID, nil, nil, nil,
		); sErr != nil {
			runtime.KeepAlive(ownerSID)
			return fmt.Errorf("SetNamedSecurityInfo (owner): %w", sErr)
		}
		runtime.KeepAlive(ownerSID)
	}

	return nil
}

// accessStringToMask converts a named access level to the corresponding Windows ACCESS_MASK.
func accessStringToMask(access string) (windows.ACCESS_MASK, error) {
	switch access {
	case "FullControl":
		return windows.GENERIC_ALL, nil
	case "ReadAndExecute":
		return windows.GENERIC_READ | windows.GENERIC_EXECUTE, nil
	case "Modify":
		return windows.GENERIC_WRITE | windows.GENERIC_READ | windows.GENERIC_EXECUTE, nil
	case "Write":
		return windows.GENERIC_WRITE, nil
	case "Read":
		return windows.GENERIC_READ, nil
	default:
		return 0, fmt.Errorf("unsupported access level %q: must be one of FullControl, ReadAndExecute, Modify, Write, Read", access)
	}
}

// Windows maps generic access rights to file-specific rights when storing ACEs.
// These are the object-specific values returned by GetNamedSecurityInfo.
const (
	// fileACLFullControl = FILE_ALL_ACCESS
	fileACLFullControl windows.ACCESS_MASK = 0x001F01FF
	// fileACLRead = FILE_GENERIC_READ
	fileACLRead windows.ACCESS_MASK = 0x00120089
	// fileACLWrite = FILE_GENERIC_WRITE
	fileACLWrite windows.ACCESS_MASK = 0x00120116
	// fileACLExecute = FILE_GENERIC_EXECUTE
	fileACLExecute windows.ACCESS_MASK = 0x001200A0
	// fileACLReadAndExecute = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
	fileACLReadAndExecute windows.ACCESS_MASK = fileACLRead | fileACLExecute
	// fileACLModify = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE
	fileACLModify windows.ACCESS_MASK = fileACLRead | fileACLWrite | fileACLExecute
)

// maskToAccessString converts a Windows ACCESS_MASK to a named access level string.
// Handles both the generic constants used when setting and the file-specific
// constants that Windows stores (and returns via GetNamedSecurityInfo).
func maskToAccessString(mask windows.ACCESS_MASK) string {
	switch mask {
	case windows.GENERIC_ALL, fileACLFullControl:
		return "FullControl"
	case windows.GENERIC_READ | windows.GENERIC_EXECUTE, fileACLReadAndExecute:
		return "ReadAndExecute"
	case windows.GENERIC_WRITE | windows.GENERIC_READ | windows.GENERIC_EXECUTE, fileACLModify:
		return "Modify"
	case windows.GENERIC_WRITE, fileACLWrite:
		return "Write"
	case windows.GENERIC_READ, fileACLRead:
		return "Read"
	default:
		return fmt.Sprintf("0x%08X", uint32(mask))
	}
}
