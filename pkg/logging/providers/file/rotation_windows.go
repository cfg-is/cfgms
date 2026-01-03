//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package file - Platform-specific disk usage calculation for Windows

package file

import (
	"fmt"
	"syscall"
	"unsafe"
)

// calculateDiskUsage calculates disk usage percentage for the log directory
// This implementation uses GetDiskFreeSpaceExW Windows API.
func (p *FileProvider) calculateDiskUsage() (float64, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	dirPtr, err := syscall.UTF16PtrFromString(p.config.Directory)
	if err != nil {
		return 0, fmt.Errorf("failed to convert directory path: %w", err)
	}

	var freeBytesAvailable, totalBytes, totalFreeBytes uint64

	ret, _, errno := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(dirPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)

	if ret == 0 {
		return 0, fmt.Errorf("GetDiskFreeSpaceExW failed: %v", errno)
	}

	if totalBytes == 0 {
		return 0, nil
	}

	usedBytes := totalBytes - totalFreeBytes
	return float64(usedBytes) / float64(totalBytes) * 100.0, nil
}
