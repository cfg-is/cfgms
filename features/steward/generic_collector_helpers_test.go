// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newGenericDNACollector builds a dna.Collector wired to the dna package's own
// cross-platform sub-collectors (dna.GenericHardwareCollector and friends) —
// the same real implementations dna/factory_generic.go wires on any platform
// without a specialised collector. They probe the live host through the Go
// runtime and stdlib instead of shelling out to WMI, which is the multi-second
// per-test cost Issue #4222 removes.
//
// Inject with steward.SetDNACollector so a Standalone steward's convergence
// and drift-detection paths run real DNA assembly without paying that cost.
// Tests that exist to prove per-OS collection works (monitor_e2e_windows_test.go)
// keep the platform default and must not use this helper.
func newGenericDNACollector(logger logging.Logger) *dna.Collector {
	return dna.NewCollector(logger,
		dna.WithHardwareCollector(&dna.GenericHardwareCollector{}),
		dna.WithSoftwareCollector(&dna.GenericSoftwareCollector{}),
		dna.WithNetworkCollector(&dna.GenericNetworkCollector{}),
		dna.WithSecurityCollector(&dna.GenericSecurityCollector{}),
	)
}
