//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package directory

import "os"

// platformSupportsPermissions returns true on Unix-like systems where
// directory permission bits are enforced by the filesystem.
func platformSupportsPermissions() bool {
	return true
}

// getDirectoryPermissions returns the Unix permission bits for the given directory.
func getDirectoryPermissions(info os.FileInfo) int {
	return int(info.Mode().Perm())
}

// defaultDirectoryMode returns the default directory mode on this platform.
func defaultDirectoryMode() os.FileMode {
	return 0755
}
