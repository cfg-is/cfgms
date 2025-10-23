//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors

package directory

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// getFileOwnership gets file ownership information on Unix-like systems
func getFileOwnership(info os.FileInfo) (string, string, error) {
	var ownerName, groupName string

	// Get ownership info using syscall.Stat_t (Unix only)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if owner, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10)); err == nil {
			ownerName = owner.Username
		}

		if grp, err := user.LookupGroupId(strconv.FormatUint(uint64(stat.Gid), 10)); err == nil {
			groupName = grp.Name
		}
	}

	// Fallback if owner lookup fails
	if ownerName == "" {
		if current, err := user.Current(); err == nil {
			ownerName = current.Username
		} else {
			ownerName = "unknown"
		}
	}
	if groupName == "" {
		groupName = "unknown"
	}

	return ownerName, groupName, nil
}
