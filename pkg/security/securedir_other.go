// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package security

// EnsureAdminOnlyDir is a no-op outside Windows: Unix mode bits already
// restrict the steward data directories, and callers keep creating them with
// their existing permissions.
func EnsureAdminOnlyDir(path string) error {
	return nil
}
