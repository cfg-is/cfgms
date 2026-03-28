//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

import "context"

// Platform-specific factory implementations for Windows
func newPlatformHardwareCollector(ctx context.Context) HardwareCollector {
	return &WindowsHardwareCollector{ctx: ctx}
}

func newPlatformSoftwareCollector(ctx context.Context) SoftwareCollector {
	return &WindowsSoftwareCollector{ctx: ctx}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &WindowsNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &WindowsSecurityCollector{}
}
