// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package sops

import (
	"os"
	"time"
)

// setLockFileModTime sets path's modification time to t while another handle may
// hold the file open.
func setLockFileModTime(path string, t time.Time) error {
	return os.Chtimes(path, t, t)
}
