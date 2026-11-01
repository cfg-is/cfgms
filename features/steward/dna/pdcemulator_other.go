//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package dna

// newPlatformPDCEmulatorResolver returns nil: the PDC-emulator role exists only
// on Windows domain controllers, so other platforms do not emit ad_pdc_emulator.
func newPlatformPDCEmulatorResolver() PDCEmulatorResolver {
	return nil
}
