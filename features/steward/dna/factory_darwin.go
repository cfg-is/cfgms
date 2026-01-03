//go:build darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package dna

// Platform-specific factory implementations for macOS
func newPlatformHardwareCollector() HardwareCollector {
	return &DarwinHardwareCollector{}
}

func newPlatformSoftwareCollector() SoftwareCollector {
	return &DarwinSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &DarwinNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &DarwinSecurityCollector{}
}
