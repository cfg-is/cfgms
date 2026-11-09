// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna_test

import (
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/testing/dnasnapshot"
)

// Compile-time interface conformance: each snapshot-backed type must satisfy
// the real dna sub-collector interface it stands in for.
var (
	_ dna.HardwareCollector = (*dnasnapshot.HardwareCollector)(nil)
	_ dna.SoftwareCollector = (*dnasnapshot.SoftwareCollector)(nil)
	_ dna.NetworkCollector  = (*dnasnapshot.NetworkCollector)(nil)
	_ dna.SecurityCollector = (*dnasnapshot.SecurityCollector)(nil)
)
