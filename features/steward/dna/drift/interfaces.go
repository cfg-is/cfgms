// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package drift re-exports the canonical drift detection types from pkg/dna/drift.
//
// All types, constants, and interfaces are identical to those in pkg/dna/drift.
// New callers should import pkg/dna/drift directly.
package drift

import pkgdrift "github.com/cfgis/cfgms/pkg/dna/drift"

// Type aliases — identical to pkg/dna/drift types.

type (
	Detector        = pkgdrift.Detector
	DriftEvent      = pkgdrift.DriftEvent
	AttributeChange = pkgdrift.AttributeChange
	DNAComparison   = pkgdrift.DNAComparison
	DetectorStats   = pkgdrift.DetectorStats
	DetectorConfig  = pkgdrift.DetectorConfig
	DriftSeverity   = pkgdrift.DriftSeverity
	DriftCategory   = pkgdrift.DriftCategory
	ChangeType      = pkgdrift.ChangeType
	DriftImpact     = pkgdrift.DriftImpact
	DriftStatus     = pkgdrift.DriftStatus
)

// Constant re-exports.

const (
	SeverityCritical = pkgdrift.SeverityCritical
	SeverityWarning  = pkgdrift.SeverityWarning
	SeverityInfo     = pkgdrift.SeverityInfo

	CategorySecurity      = pkgdrift.CategorySecurity
	CategoryCompliance    = pkgdrift.CategoryCompliance
	CategoryPerformance   = pkgdrift.CategoryPerformance
	CategoryConfiguration = pkgdrift.CategoryConfiguration
	CategoryInventory     = pkgdrift.CategoryInventory

	ChangeTypeAdded    = pkgdrift.ChangeTypeAdded
	ChangeTypeRemoved  = pkgdrift.ChangeTypeRemoved
	ChangeTypeModified = pkgdrift.ChangeTypeModified

	ImpactHigh   = pkgdrift.ImpactHigh
	ImpactMedium = pkgdrift.ImpactMedium
	ImpactLow    = pkgdrift.ImpactLow

	StatusNew          = pkgdrift.StatusNew
	StatusAcknowledged = pkgdrift.StatusAcknowledged
	StatusResolved     = pkgdrift.StatusResolved
	StatusIgnored      = pkgdrift.StatusIgnored
)
