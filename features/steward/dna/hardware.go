// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"fmt"
	"runtime"
)

// HardwareCollector defines the interface for platform-specific hardware collection
type HardwareCollector interface {
	// CollectCPU gathers detailed CPU information
	CollectCPU(ctx context.Context, attributes map[string]string) error

	// CollectMemory gathers detailed memory information
	CollectMemory(ctx context.Context, attributes map[string]string) error

	// CollectDisk gathers disk and storage information
	CollectDisk(ctx context.Context, attributes map[string]string) error

	// CollectMotherboard gathers motherboard and system information
	CollectMotherboard(ctx context.Context, attributes map[string]string) error
}

// NewHardwareCollector creates a platform-specific hardware collector.
// The context is used by Windows implementations to enforce per-command timeouts.
func NewHardwareCollector(ctx context.Context) HardwareCollector {
	return newPlatformHardwareCollector(ctx)
}

// GenericHardwareCollector provides basic cross-platform hardware collection
// This is used as a fallback when platform-specific collectors are not available
type GenericHardwareCollector struct{}

func (g *GenericHardwareCollector) CollectCPU(_ context.Context, attributes map[string]string) error {
	// Basic CPU information available on all platforms
	attributes["cpu_count"] = fmt.Sprintf("%d", runtime.NumCPU())
	attributes["cpu_arch"] = runtime.GOARCH
	return nil
}

func (g *GenericHardwareCollector) CollectMemory(_ context.Context, attributes map[string]string) error {
	// Basic memory information from Go runtime
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	attributes["memory_go_alloc"] = fmt.Sprintf("%d", m.Alloc)
	attributes["memory_go_sys"] = fmt.Sprintf("%d", m.Sys)
	return nil
}

func (g *GenericHardwareCollector) CollectDisk(_ context.Context, attributes map[string]string) error {
	// Generic disk collection - limited without platform-specific APIs
	attributes["disk_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericHardwareCollector) CollectMotherboard(_ context.Context, attributes map[string]string) error {
	// Generic motherboard collection - limited without platform-specific APIs
	attributes["system_info"] = "generic_collector_limited"
	return nil
}

// Platform-specific collector types (implementations in separate files)

// WindowsHardwareCollector handles Windows-specific hardware collection.
// Full definition (with ctx field) is in hardware_windows.go.

// LinuxHardwareCollector handles Linux-specific hardware collection
type LinuxHardwareCollector struct{}

// DarwinHardwareCollector handles macOS-specific hardware collection
type DarwinHardwareCollector struct{}
