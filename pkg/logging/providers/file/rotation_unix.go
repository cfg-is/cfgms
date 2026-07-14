//go:build !windows
// +build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
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

	// Calculate usage percentage with bounds checking. Statfs_t.Bsize is
	// int64 on Linux but uint32 on Darwin — go through int64 so the guard
	// compiles and lints cleanly on both (a direct `stat.Bsize < 0` is
	// statically false on Darwin and staticcheck SA4003 rejects it there).
	bsize := int64(stat.Bsize) //nolint:unconvert // no-op on linux; required on darwin where Bsize is uint32
	if bsize <= 0 {
		return 0, fmt.Errorf("invalid block size: %d", bsize)
	}
	// #nosec G115 - Block size is validated above to be positive
	blockSize := uint64(bsize)

	totalBytes := stat.Blocks * blockSize
	freeBytes := stat.Bavail * blockSize
	usedBytes := totalBytes - freeBytes

	if totalBytes == 0 {
		return 0, nil
	}

	return float64(usedBytes) / float64(totalBytes) * 100.0, nil
}
