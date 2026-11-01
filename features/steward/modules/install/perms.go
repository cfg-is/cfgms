// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package install

import (
	"errors"
	"strconv"
	"strings"
)

// ErrTreeNotProtected is returned when a directory tree is writable by someone
// other than administrators (or the process's own effective user on Unix), or is
// not a plain tree of real directories and files.
var ErrTreeNotProtected = errors.New("module tree is not protected against non-administrator writes")

// EnsureProtectedDir creates path (and its missing parents) if it does not
// exist and makes it administrator-writable only, then verifies the result.
//
// Windows: the DACL is protected (no inherited entries) and grants SYSTEM and
// Administrators full control and Users read/execute only; the entries are
// inheritable so files and directories created below keep them.
// Unix: mode 0755, owned by root or the process's effective uid.
//
// It is the helper both the installer and the load-time tree check (CheckProtectedTree)
// build on, and it lives here so neither needs to import the other's package.
func EnsureProtectedDir(path string) error {
	if err := ensureProtectedDir(path); err != nil {
		return err
	}
	return checkProtectedDir(path)
}

// CheckProtectedTree verifies that root and everything below it is a plain tree
// of real directories and regular files (no symlinks or reparse points) that
// only administrators can write: on Unix every entry is owned by root or the
// process's effective uid and has no group or other write bit; on Windows no
// allow entry grants write-class rights to any principal other than SYSTEM,
// Administrators and TrustedInstaller. A violation returns ErrTreeNotProtected;
// the error names no path.
func CheckProtectedTree(root string) error {
	return checkProtectedTree(root)
}

// The Windows DACL rule is parsed from the SDDL form of the descriptor. The
// parser is platform-neutral so it is unit-tested on every platform.

// writeRightTokens are the SDDL right tokens (and generic aliases) that allow
// modifying a directory or file.
var writeRightTokens = []string{"GA", "GW", "FA", "FW", "WD", "WO", "SD", "CC", "DC", "WP", "DT"}

// Access-mask bits that allow modification: FILE_WRITE_DATA/ADD_FILE,
// FILE_APPEND_DATA/ADD_SUBDIRECTORY, FILE_WRITE_EA, FILE_DELETE_CHILD,
// FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE and
// GENERIC_ALL.
const writeMaskBits uint32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000

// trustedPrincipals are the SIDs (and SDDL aliases) allowed to hold write rights.
var trustedPrincipals = map[string]bool{
	"SY":                true,
	"BA":                true,
	"S-1-5-18":          true,
	"S-1-5-32-544":      true,
	trustedInstallerSID: true,
}

// trustedInstallerSID is NT SERVICE\TrustedInstaller, which owns the default
// Program Files tree. Other NT SERVICE\* virtual accounts are not trusted.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// checkSDDL applies the write-right rule to an SDDL string.
func checkSDDL(sddl string) error {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return ErrTreeNotProtected
	}
	rest := sddl[i+2:]
	if j := strings.Index(rest, "S:"); j >= 0 {
		rest = rest[:j]
	}
	for _, ace := range splitACEs(rest) {
		fields := strings.Split(ace, ";")
		if len(fields) < 6 {
			return ErrTreeNotProtected
		}
		aceType, rights, sid := fields[0], fields[2], fields[5]
		switch aceType {
		case "A", "OA", "XA", "ZA":
			// allow-class entries are examined below
		case "D", "OD", "XD", "AU", "AL", "OU", "OL", "ML", "XU", "RA", "SP":
			continue // deny, audit, label and resource entries never widen access
		default:
			return ErrTreeNotProtected // unknown ACE type: fail closed
		}
		if trustedPrincipals[sid] {
			continue
		}
		if grantsWrite(rights) {
			return ErrTreeNotProtected
		}
	}
	return nil
}

// splitACEs returns the parenthesised ACE bodies of a DACL string.
func splitACEs(dacl string) []string {
	var out []string
	for {
		open := strings.IndexByte(dacl, '(')
		if open < 0 {
			return out
		}
		closeIdx := strings.IndexByte(dacl[open:], ')')
		if closeIdx < 0 {
			return append(out, "") // malformed: forces a refusal
		}
		out = append(out, dacl[open+1:open+closeIdx])
		dacl = dacl[open+closeIdx+1:]
	}
}

// grantsWrite reports whether an SDDL rights field (hex mask or two-letter
// tokens) includes a write-class right. An unparseable field counts as write.
func grantsWrite(rights string) bool {
	if strings.HasPrefix(rights, "0x") || strings.HasPrefix(rights, "0X") {
		mask, err := strconv.ParseUint(rights[2:], 16, 32)
		if err != nil {
			return true
		}
		return uint32(mask)&writeMaskBits != 0
	}
	if len(rights)%2 != 0 {
		return true
	}
	for k := 0; k < len(rights); k += 2 {
		tok := rights[k : k+2]
		for _, w := range writeRightTokens {
			if tok == w {
				return true
			}
		}
	}
	return false
}

// ownerAcceptable reports whether uid may own a protected entry: root, or the
// effective user of the process (which could write the tree anyway).
func ownerAcceptable(uid, euid uint32) bool {
	return uid == 0 || uid == euid
}
