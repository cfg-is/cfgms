//go:build darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

import "context"

// Platform-specific factory implementations for macOS
func newPlatformHardwareCollector(_ context.Context) HardwareCollector {
	return &DarwinHardwareCollector{}
}

func newPlatformSoftwareCollector(_ context.Context) SoftwareCollector {
	return &DarwinSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &DarwinNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &DarwinSecurityCollector{}
}
