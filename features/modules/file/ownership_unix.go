//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package file

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// getFileOwnership gets file ownership information on Unix-like systems
func getFileOwnership(info os.FileInfo) (string, string, error) {
	var owner, group string

	// Get ownership info using syscall.Stat_t (Unix only)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if ownerUser, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10)); err == nil {
			owner = ownerUser.Username
		}

		if groupUser, err := user.LookupGroupId(strconv.FormatUint(uint64(stat.Gid), 10)); err == nil {
			group = groupUser.Name
		}
	}

	// Fallback if owner lookup fails
	if owner == "" {
		if current, err := user.Current(); err == nil {
			owner = current.Username
		} else {
			owner = "unknown"
		}
	}
	if group == "" {
		group = "unknown"
	}

	return owner, group, nil
}
