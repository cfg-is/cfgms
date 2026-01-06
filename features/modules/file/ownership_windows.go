//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package file

import (
	"os"
	"os/user"
)

// getFileOwnership gets file ownership information on Windows
func getFileOwnership(info os.FileInfo) (string, string, error) {
	// On Windows, just use current user as fallback
	owner := "unknown"
	group := "unknown"

	if current, err := user.Current(); err == nil {
		owner = current.Username
	}

	return owner, group, nil
}
