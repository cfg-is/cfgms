//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package directory

import (
	"os"
	"os/user"
)

// getFileOwnership gets file ownership information on Windows
func getFileOwnership(info os.FileInfo) (string, string, error) {
	// On Windows, just use current user as fallback
	ownerName := "unknown"
	groupName := "unknown"

	if current, err := user.Current(); err == nil {
		ownerName = current.Username
	}

	return ownerName, groupName, nil
}
