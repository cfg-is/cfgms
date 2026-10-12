// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package identity

// readDiskSerials is best effort and has no unprivileged in-process source on
// macOS (it would require shelling out to system_profiler), so the disk_serials
// attribute is omitted rather than collected through a subprocess.
func readDiskSerials() []string {
	return nil
}
