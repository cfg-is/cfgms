// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

// checkAndRunAsWindowsService always returns false on non-Windows platforms.
func checkAndRunAsWindowsService() bool {
	return false
}
