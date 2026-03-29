//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

import "context"

// Platform-specific factory implementations for Windows
func newPlatformHardwareCollector(_ context.Context) HardwareCollector {
	return &WindowsHardwareCollector{}
}

func newPlatformSoftwareCollector(_ context.Context) SoftwareCollector {
	return &WindowsSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &WindowsNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &WindowsSecurityCollector{}
}
