//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

import "context"

// Platform-specific factory implementations for Linux
func newPlatformHardwareCollector(_ context.Context) HardwareCollector {
	return &LinuxHardwareCollector{}
}

func newPlatformSoftwareCollector(_ context.Context) SoftwareCollector {
	return &LinuxSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &LinuxNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &LinuxSecurityCollector{}
}
