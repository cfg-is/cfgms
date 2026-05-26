// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward

import (
	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
)

// RunConvergence exposes the unexported runConvergence method for black-box tests.
var RunConvergence = (*Steward).runConvergence

// DetectUnmanagedDNADrift exposes the unexported detectUnmanagedDNADrift method for black-box tests.
var DetectUnmanagedDNADrift = (*Steward).detectUnmanagedDNADrift

// SetPreviousDNA sets the previousDNA field under its mutex for test setup.
var SetPreviousDNA = func(s *Steward, d *commonpb.DNA) {
	s.previousDNAMu.Lock()
	s.previousDNA = d
	s.previousDNAMu.Unlock()
}

// GetPreviousDNA reads the previousDNA field under its mutex for test assertions.
var GetPreviousDNA = func(s *Steward) *commonpb.DNA {
	s.previousDNAMu.Lock()
	defer s.previousDNAMu.Unlock()
	return s.previousDNA
}

// SetDNACollector replaces the dnaCollector field for test injection (e.g. nil-safety tests).
var SetDNACollector = func(s *Steward, c *dna.Collector) {
	s.dnaCollector = c
}

// SetDriftDetector replaces the driftDetector field for test injection (e.g. nil-safety tests).
var SetDriftDetector = func(s *Steward, d drift.Detector) {
	s.driftDetector = d
}
