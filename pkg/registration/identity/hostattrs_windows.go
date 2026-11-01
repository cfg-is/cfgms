// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package identity

// readDiskSerials is best effort and has no in-process source on Windows
// without WMI, so the disk_serials attribute is omitted rather than collected
// through a subprocess.
func readDiskSerials() []string {
	return nil
}
