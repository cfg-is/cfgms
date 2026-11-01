// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package dex

import "testing"

// assertStubOrSkip is a no-op on Windows: the full ETW/WMI collector is
// built (not the stub), so ErrPlatformNotSupported is never returned.
// The behavioral contract of the Windows collector is exercised by
// TestCollectorRunShort in collector_windows_test.go.
func assertStubOrSkip(t *testing.T, _ *Collector) {
	t.Helper()
	// Windows has the real collector; nothing to assert here.
}
