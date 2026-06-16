// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package hyperv

import "context"

// nonWindowsDetector is the production fallback on non-Windows hosts. Hyper-V is
// a Windows-only feature; this represents real production behaviour on Linux and
// macOS, not a test stub.
type nonWindowsDetector struct{}

func (nonWindowsDetector) IsHypervHost(_ context.Context) (bool, error) {
	return false, nil
}

func newDefaultDetector() HypervDetector {
	return nonWindowsDetector{}
}

// NewDefaultDetector returns the platform-appropriate HypervDetector for
// production use. Called by the steward module factory.
func NewDefaultDetector() HypervDetector {
	return newDefaultDetector()
}
