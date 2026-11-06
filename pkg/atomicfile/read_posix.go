// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package atomicfile

import "os"

// ReadFile reads path with POSIX semantics. Concurrent rename-over of the
// target never blocks an open-for-read on POSIX, so no retry is needed.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path) //#nosec G304 -- caller validates path
}
