// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package sops

// isWindowsPendingDeleteAccessDenied always reports false on non-Windows
// platforms: Linux and macOS return EEXIST (already handled by os.IsExist)
// for the same lock-file-mid-delete overlap, never ACCESS_DENIED (Issue
// #3817).
func isWindowsPendingDeleteAccessDenied(err error) bool {
	return false
}
