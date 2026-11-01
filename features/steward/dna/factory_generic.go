//go:build !linux && !darwin && !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import "context"

// Platform-specific factory implementations for unsupported platforms
func newPlatformHardwareCollector(_ context.Context) HardwareCollector {
	return &GenericHardwareCollector{}
}

func newPlatformSoftwareCollector(_ context.Context) SoftwareCollector {
	return &GenericSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &GenericNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &GenericSecurityCollector{}
}
