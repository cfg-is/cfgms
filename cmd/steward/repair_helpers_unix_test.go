// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

import (
	"os"

	"github.com/cfgis/cfgms/pkg/security"
)

// testTakeOver runs the real rights reset with the calling user as the owner it
// assigns, so the walk (modes, links, quarantine) runs without root.
func testTakeOver(roots []string) (security.TakeoverReport, error) {
	return security.TakeOverForRepairAs(roots, os.Geteuid())
}
