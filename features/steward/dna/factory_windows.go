//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package dna

// Platform-specific factory implementations for Windows
func newPlatformHardwareCollector() HardwareCollector {
	return &WindowsHardwareCollector{}
}

func newPlatformSoftwareCollector() SoftwareCollector {
	return &WindowsSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &WindowsNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &WindowsSecurityCollector{}
}
