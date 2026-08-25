// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package osquery scaffolds an ADR-006-compliant extended module bundle for
// read-only host fact observation via the osquery binary. The four curated fact
// domains served are host:cpu, host:memory, host:os, and host:bios — matching
// the allowlist in features/steward/dna/fragments.go hostFactFragmentSpecs.
//
// This is the S1 scaffold (issue #3561). Set() is permanently unimplemented.
// Get() fact-mapping logic is wired in S4 of epic #2855.
package osquery

import (
	"context"

	"github.com/cfgis/cfgms/features/modules"
)

// pinnedVersion is the osquery release this bundle ships. S9 of epic #2855
// wires this constant into the refresh-pins mechanism; until then it is a
// named constant so a version bump is a single-line, auditable change.
const pinnedVersion = "5.13.1"

// osqueryModule implements modules.Module for read-only host fact observation.
// osquery is never a managed authority — it observes the four curated host:*
// fact domains (host:cpu, host:memory, host:os, host:bios) and never converges
// resource state.
type osqueryModule struct{}

// New returns a new osquery module.
func New() modules.Module {
	return &osqueryModule{}
}

// Get returns the current host facts from the four curated osquery domains.
// Fact-mapping logic is implemented by S4 of epic #2855; this scaffold returns
// ErrNotImplemented until that story lands.
func (m *osqueryModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	return nil, modules.ErrNotImplemented
}

// Set permanently returns ErrNotImplemented — osquery is a read-only observer
// and is never a managed authority that converges resource state. This is an
// architectural invariant of the osquery epic, not a temporary stub.
func (m *osqueryModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return modules.ErrNotImplemented
}
