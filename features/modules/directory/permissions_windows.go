//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package directory

import "os"

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
