// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package drift re-exports drift detection functions from pkg/dna/drift.
package drift

import (
	pkgdrift "github.com/cfgis/cfgms/pkg/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

// NewDetector delegates to pkg/dna/drift.NewDetector.
func NewDetector(config *DetectorConfig, logger logging.Logger) (Detector, error) {
	return pkgdrift.NewDetector(config, logger)
}

// DefaultDetectorConfig delegates to pkg/dna/drift.DefaultDetectorConfig.
func DefaultDetectorConfig() *DetectorConfig {
	return pkgdrift.DefaultDetectorConfig()
}
