// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newGenericDNACollector builds a dna.Collector wired to the dna package's own
// cross-platform sub-collectors (dna.GenericHardwareCollector and friends) —
// the same real implementations dna/factory_generic.go wires on any platform
// without a specialised collector. They probe the live host through the Go
// runtime and stdlib instead of shelling out to WMI, which is the multi-second
// per-test cost Issue #4222 removes from tests that assert on the adapter's
// forwarding and fragment-assembly behaviour.
func newGenericDNACollector(logger logging.Logger) *dna.Collector {
	return dna.NewCollector(logger,
		dna.WithHardwareCollector(&dna.GenericHardwareCollector{}),
		dna.WithSoftwareCollector(&dna.GenericSoftwareCollector{}),
		dna.WithNetworkCollector(&dna.GenericNetworkCollector{}),
		dna.WithSecurityCollector(&dna.GenericSecurityCollector{}),
	)
}

// newGenericDNACollectorAdapter builds a dnaCollectorAdapter whose collector
// uses the cross-platform sub-collectors above instead of the platform
// default. modules may be nil, same as newDNACollectorAdapter.
func newGenericDNACollectorAdapter(logger logging.Logger, modules moduleDNASource) *dnaCollectorAdapter {
	a := newDNACollectorAdapter(logger, modules)
	a.collector = newGenericDNACollector(logger)
	return a
}
