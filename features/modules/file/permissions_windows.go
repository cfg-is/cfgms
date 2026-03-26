//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package file

import "os"

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
