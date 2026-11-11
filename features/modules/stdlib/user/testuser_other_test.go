// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package user

import (
	"os"
	"testing"
)

// currentTestUser returns a username that reliably exists on the current
// platform for read-only conformance testing. It never modifies any account.
// $USER is set by the shell; "root" is the universal fallback.
func currentTestUser(t *testing.T) string {
	t.Helper()
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "root"
}
