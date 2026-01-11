//go:build !linux && !darwin && !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

// Platform-specific factory implementations for unsupported platforms
func newPlatformHardwareCollector() HardwareCollector {
	return &GenericHardwareCollector{}
}

func newPlatformSoftwareCollector() SoftwareCollector {
	return &GenericSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &GenericNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &GenericSecurityCollector{}
}
