// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import "github.com/cfgis/cfgms/pkg/security"

// testTakeOver is the real rights reset: Windows tests run it as Administrator.
func testTakeOver(roots []string) (security.TakeoverReport, error) {
	return security.TakeOverForRepair(roots)
}
