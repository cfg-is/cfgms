// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/security"
)

// currentRunAccount probes the process token. SYSTEM and an elevated
// administrator are the default accounts; any other token lacks the right to
// take ownership of data entries it did not create.
func currentRunAccount() runAccount {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return runAccount{
			Name:    "unknown account",
			Missing: []string{"a readable process token"},
		}
	}
	sid := user.User.Sid
	acct := runAccount{SID: sid.String(), Name: sid.String()}
	if account, domain, _, lerr := sid.LookupAccount(""); lerr == nil {
		acct.Name = domain + "\\" + account
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || token.IsElevated() {
		acct.Default = true
		return acct
	}
	acct.Missing = []string{"SYSTEM or an elevated administrator token (take ownership of data directory entries)"}
	return acct
}

// processRunAccount is the account secureStewardDataDir classifies the data
// directory against; tests substitute it.
var processRunAccount = currentRunAccount

// dataDirClass is how the steward data directory relates to the run account.
type dataDirClass int

const (
	// dataDirNotOwned: the root is absent or not owned by the run account; the
	// regular lockdown applies.
	dataDirNotOwned dataDirClass = iota
	// dataDirOwnAccount: the tree is owned by the run account and nobody else
	// can write to it. Legitimate for a non-default account.
	dataDirOwnAccount
	// dataDirTampered: the tree is owned by the run account but a reparse point,
	// foreign owner or a write grant to another non-admin principal is present.
	dataDirTampered
)

// writeMask is the set of rights that let a principal change an entry or its
// permissions.
const writeMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild | windows.DELETE |
	windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

const (
	inheritOnlyACE  = 0x08
	fileDeleteChild = 0x40 // FILE_DELETE_CHILD
)

// classifyDataDir classifies dir against the run account SID. The own-account
// branch applies only when every entry is owned by that SID (or SYSTEM /
// Administrators) AND no principal other than SYSTEM, Administrators and that
// SID holds a write right. S12's tamper handling consumes the dataDirTampered
// result.
func classifyDataDir(dir, accountSID string) (dataDirClass, error) {
	own, err := windows.StringToSid(accountSID)
	if err != nil {
		return dataDirNotOwned, fmt.Errorf("parse run account SID: %w", err)
	}
	rootOwner, _, err := entryOwnerAndDACL(dir)
	if errors.Is(err, os.ErrNotExist) {
		return dataDirNotOwned, nil
	}
	if err != nil {
		return dataDirNotOwned, err
	}
	if !rootOwner.Equals(own) {
		return dataDirNotOwned, nil
	}
	tampered, err := treeHasForeignEntry(dir, own)
	if err != nil {
		return dataDirNotOwned, err
	}
	if tampered {
		return dataDirTampered, nil
	}
	return dataDirOwnAccount, nil
}

// treeHasForeignEntry walks dir and reports whether any entry disqualifies the
// tree from the own-account branch (see entryIsForeign).
func treeHasForeignEntry(dir string, own *windows.SID) (bool, error) {
	tampered := false
	walkErr := filepath.WalkDir(dir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		foreign, err := entryIsForeign(dir, p, d, own)
		if err != nil {
			return err
		}
		if foreign {
			tampered = true
			return filepath.SkipAll
		}
		return nil
	})
	return tampered, walkErr
}

// entryIsForeign reports whether entry p under root is something other than a
// regular file or real directory, is owned by a principal other than own,
// SYSTEM or Administrators, or grants write access to another principal.
func entryIsForeign(root, p string, d os.DirEntry, own *windows.SID) (bool, error) {
	if !d.IsDir() && !d.Type().IsRegular() {
		return true, nil
	}
	if d.IsDir() && p != root && d.Type()&os.ModeSymlink != 0 {
		return true, nil
	}
	owner, dacl, err := entryOwnerAndDACL(p)
	if err != nil {
		return false, err
	}
	if !owner.Equals(own) && !isSystemOrAdmins(owner) {
		return true, nil
	}
	return daclGrantsForeignWrite(dacl, own), nil
}

func isSystemOrAdmins(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

func entryOwnerAndDACL(path string) (*windows.SID, *windows.ACL, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, nil, os.ErrNotExist
		}
		return nil, nil, fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil, nil, fmt.Errorf("read owner of %s: unavailable", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, nil, fmt.Errorf("read DACL of %s: %w", path, err)
	}
	return owner, dacl, nil
}

// daclGrantsForeignWrite reports whether the DACL lets a principal other than
// SYSTEM, Administrators and own write, or is a NULL DACL or holds an ACE type
// it cannot interpret.
func daclGrantsForeignWrite(acl *windows.ACL, own *windows.SID) bool {
	if acl == nil {
		return true
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return true
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if ace.Header.AceFlags&inheritOnlyACE != 0 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if isSystemOrAdmins(sid) || sid.Equals(own) {
				continue
			}
			if ace.Mask&writeMask != 0 {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// secureOwnAccountDataDir handles the non-default-account case before the
// regular lockdown. handled is true when the data directory is the account's
// own and legitimately left as is; err is non-nil for a tampered tree.
func secureOwnAccountDataDir(dir string) (handled bool, err error) {
	acct := processRunAccount()
	if acct.Default || acct.SID == "" {
		return false, nil
	}
	class, cerr := classifyDataDir(dir, acct.SID)
	if cerr != nil {
		return false, nil // regular lockdown decides, and refuses what it cannot verify
	}
	switch class {
	case dataDirOwnAccount:
		return true, nil
	case dataDirTampered:
		return false, fmt.Errorf("%s is owned by the run account but grants write access to another principal or holds a foreign entry: %w", dir, security.ErrUntrustedDirEntry)
	}
	return false, nil
}
