//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package file

import "os"

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
