// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package hyperv

// newExecutor returns the stub executor on non-Windows platforms. The struct
// type is defined in executor.go so tests can reference it on all platforms.
func newExecutor() hypervExecutor {
	return &stubHypervExecutor{}
}
