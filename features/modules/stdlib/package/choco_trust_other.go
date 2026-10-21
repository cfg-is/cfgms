// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build !windows

package package_module

// chocoTrusted is a no-op off Windows: Chocolatey is never selected or run
// there, so there is no install path to verify.
func chocoTrusted(path string) error {
	return nil
}
