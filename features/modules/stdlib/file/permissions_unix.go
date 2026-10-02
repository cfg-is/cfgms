//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package file

import (
	"os"

	"github.com/cfgis/cfgms/features/modules"
)

// platformSupportsPermissions returns true on Unix-like systems where
// file permission bits are enforced by the filesystem.
func platformSupportsPermissions() bool {
	return true
}

// getFilePermissions returns the Unix permission bits for the given file.
func getFilePermissions(info os.FileInfo) int {
	return int(info.Mode().Perm())
}

// defaultFileMode returns the default file mode for new files on this platform.
func defaultFileMode() os.FileMode {
	return 0644
}

// getFileACL returns nil on non-Windows platforms (NTFS ACLs are Windows-only).
func getFileACL(_ string) (*modules.WindowsACL, error) { return nil, nil }

// setFileACL is a no-op on non-Windows platforms.
func setFileACL(_ string, _ *modules.WindowsACL) error { return nil }
