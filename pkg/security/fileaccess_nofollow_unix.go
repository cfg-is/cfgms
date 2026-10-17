// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package security

import (
	"os"
	"syscall"
)

// openNoFollow opens path without following a symlink at the final component.
func openNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	// #nosec G304 - callers pass a path already validated by ValidateAndCleanPath
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, perm)
}
