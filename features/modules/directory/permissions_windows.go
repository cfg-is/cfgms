//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package directory

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
// enforced by the filesystem and read back incorrectly.
func platformSupportsPermissions() bool {
	return false
}

// getDirectoryPermissions returns 0 on Windows since Unix permission bits
// are not meaningful on NTFS.
func getDirectoryPermissions(_ os.FileInfo) int {
	return 0
}

// defaultDirectoryMode returns the default directory mode on Windows.
// NTFS ignores these bits; actual access control uses Windows ACLs.
func defaultDirectoryMode() os.FileMode {
	return 0777
}

// getDirectoryACL reads the NTFS DACL and owner for the directory at path.
func getDirectoryACL(path string) (*modules.WindowsACL, error) {
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

// setDirectoryACL applies the NTFS DACL and owner declared in acl to the directory at path.
func setDirectoryACL(path string, acl *modules.WindowsACL) error {
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

// maskToAccessString converts a Windows ACCESS_MASK to a named access level string.
func maskToAccessString(mask windows.ACCESS_MASK) string {
	switch mask {
	case windows.GENERIC_ALL:
		return "FullControl"
	case windows.GENERIC_READ | windows.GENERIC_EXECUTE:
		return "ReadAndExecute"
	case windows.GENERIC_WRITE | windows.GENERIC_READ | windows.GENERIC_EXECUTE:
		return "Modify"
	case windows.GENERIC_WRITE:
		return "Write"
	case windows.GENERIC_READ:
		return "Read"
	default:
		return fmt.Sprintf("0x%08X", uint32(mask))
	}
}
