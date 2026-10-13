// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package identity

import (
	"os"
	"path/filepath"
	"strings"
)

// readDiskSerials returns the serial numbers the kernel exposes for block
// devices under /sys/block/*/device/serial. Best effort: virtual disks and
// containers commonly expose none.
func readDiskSerials() []string {
	paths, err := filepath.Glob("/sys/block/*/device/serial")
	if err != nil {
		return nil
	}
	var serials []string
	for _, p := range paths {
		data, err := os.ReadFile(p) //#nosec G304 -- glob over the fixed /sys/block tree
		if err != nil {
			continue
		}
		serials = append(serials, strings.TrimSpace(string(data)))
	}
	return serials
}
