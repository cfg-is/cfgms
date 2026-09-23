// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"github.com/cfgis/cfgms/pkg/logging"
)

// newGenericCollector builds a Collector wired to this package's own
// cross-platform sub-collectors — GenericHardwareCollector,
// GenericSoftwareCollector, GenericNetworkCollector and
// GenericSecurityCollector, the same real implementations factory_generic.go
// wires on any platform without a specialised collector.
//
// They are real CFGMS components that probe the live host: CPU count and
// architecture from the Go runtime, heap and system memory from
// runtime.ReadMemStats, every non-loopback interface's name, MAC and IPv4
// addresses from net.Interfaces, OS/compiler identity and the process's own
// pid/uid/gid from the os package. What they do not do is shell out — the
// Windows platform collector issues nine WMI queries per run, which is the
// multi-second cost Issue #4222 removes from tests that assert on Collector's
// assembly, caching and partitioning logic rather than on how deeply a given
// OS can be inspected.
//
// Tests that exist to prove per-OS collection works (TestCollectHardwareInfo,
// TestCollectSoftwareInfo, hardware_linux_test.go, hardware_windows_test.go,
// software_windows_test.go, network_windows_test.go, security_windows_test.go)
// keep using the platform default and must not be switched to this helper.
//
// Additional opts (e.g. WithOsquerySource) are applied after the sub-collector
// options, so a caller can still override any of them.
func newGenericCollector(logger logging.Logger, opts ...CollectorOption) *Collector {
	base := []CollectorOption{
		WithHardwareCollector(&GenericHardwareCollector{}),
		WithSoftwareCollector(&GenericSoftwareCollector{}),
		WithNetworkCollector(&GenericNetworkCollector{}),
		WithSecurityCollector(&GenericSecurityCollector{}),
	}
	return NewCollector(logger, append(base, opts...)...)
}
