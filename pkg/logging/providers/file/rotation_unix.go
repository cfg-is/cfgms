//go:build !windows
// +build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package file - Platform-specific disk usage calculation for Unix-like systems

package file

import (
	"fmt"
	"syscall"
)

// calculateDiskUsage calculates disk usage percentage for the log directory
// This implementation uses syscall.Statfs which is available on Unix-like systems.
func (p *FileProvider) calculateDiskUsage() (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(p.config.Directory, &stat); err != nil {
		return 0, fmt.Errorf("failed to get filesystem stats: %w", err)
	}

	// Calculate usage percentage with bounds checking
	if stat.Bsize < 0 {
		return 0, fmt.Errorf("invalid block size: %d", stat.Bsize)
	}
	// #nosec G115 - Block size is validated above to be non-negative
	blockSize := uint64(stat.Bsize)

	totalBytes := stat.Blocks * blockSize
	freeBytes := stat.Bavail * blockSize
	usedBytes := totalBytes - freeBytes

	if totalBytes == 0 {
		return 0, nil
	}

	return float64(usedBytes) / float64(totalBytes) * 100.0, nil
}
