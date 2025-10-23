// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package patch

import (
	"context"
	"fmt"
	"time"
)

// PatchPolicy defines the patch compliance requirements
type PatchPolicy struct {
	// Patch installation deadlines by severity
	Critical  time.Duration `yaml:"critical"`  // Time limit for critical patches (e.g., 7 days)
	Important time.Duration `yaml:"important"` // Time limit for important patches (e.g., 14 days)
	Moderate  time.Duration `yaml:"moderate"`  // Time limit for moderate patches (e.g., 30 days)
	Low       time.Duration `yaml:"low"`       // Time limit for low severity patches (e.g., 60 days)

	// Major version upgrade policy
	MajorVersionUpgrade MajorVersionPolicy `yaml:"major_version_upgrade,omitempty"`

	// Alerting thresholds
	WarningThreshold  time.Duration `yaml:"warning_threshold"`  // Alert when this much time remains (e.g., 7 days)
	CriticalThreshold time.Duration `yaml:"critical_threshold"` // Alert when this much time remains (e.g., 1 day)
}

// MajorVersionPolicy defines the major version upgrade policy
type MajorVersionPolicy struct {
	Enabled             bool     `yaml:"enabled"`              // Enable automatic major version upgrades
	TargetVersion       string   `yaml:"target_version"`       // Target Windows version (e.g., "11", "23H2")
	RequireCompatible   bool     `yaml:"require_compatible"`   // Only upgrade compatible devices
	CompatibilityChecks []string `yaml:"compatibility_checks"` // DNA checks required (TPM, UEFI, CPU, RAM, disk)
}

// ComplianceStatus represents the compliance status of a device
type ComplianceStatus string

const (
	ComplianceStatusCompliant    ComplianceStatus = "Compliant"
	ComplianceStatusWarning      ComplianceStatus = "Warning"      // Within warning threshold
	ComplianceStatusCritical     ComplianceStatus = "Critical"     // Within critical threshold
	ComplianceStatusNonCompliant ComplianceStatus = "NonCompliant" // Past deadline
)

// ComplianceReport represents the compliance status of a device
type ComplianceReport struct {
	DeviceName           string             `json:"device_name"`
	OSVersion            string             `json:"os_version"`
	PatchLevel           string             `json:"patch_level"`
	Status               ComplianceStatus   `json:"status"`
	MissingPatches       []MissingPatchInfo `json:"missing_patches"`
	DaysUntilBreach      int                `json:"days_until_breach"` // Days until non-compliant
	Win11UpgradeEligible bool               `json:"win11_upgrade_eligible"`
	CompatibilityIssues  []string           `json:"compatibility_issues,omitempty"`
	LastChecked          time.Time          `json:"last_checked"`
}

// MissingPatchInfo represents a missing patch with compliance information
type MissingPatchInfo struct {
	PatchInfo
	DaysOverdue        int       `json:"days_overdue"`        // Days since deadline passed (negative if not yet due)
	ComplianceDeadline time.Time `json:"compliance_deadline"` // When the patch must be installed
}

// PolicyEngine manages patch compliance policies
type PolicyEngine struct {
	policy PatchPolicy
}

// NewPolicyEngine creates a new policy engine with the specified policy
func NewPolicyEngine(policy PatchPolicy) *PolicyEngine {
	return &PolicyEngine{
		policy: policy,
	}
}

// CheckCompliance checks if the device is compliant with the patch policy
func (e *PolicyEngine) CheckCompliance(ctx context.Context, status *PatchStatus) (*ComplianceReport, error) {
	report := &ComplianceReport{
		LastChecked:    time.Now(),
		Status:         ComplianceStatusCompliant,
		MissingPatches: []MissingPatchInfo{},
	}

	if status == nil {
		return nil, fmt.Errorf("patch status is nil")
	}

	// Calculate compliance for each pending patch
	mostCriticalDays := 999999 // Days until most critical deadline
	now := time.Now()

	for _, patch := range status.PendingPatches {
		// Determine deadline based on severity
		deadline := e.calculateDeadline(patch.ReleaseDate, patch.Severity)
		daysOverdue := int(now.Sub(deadline).Hours() / 24)

		missingPatch := MissingPatchInfo{
			PatchInfo:          patch,
			DaysOverdue:        daysOverdue,
			ComplianceDeadline: deadline,
		}
		report.MissingPatches = append(report.MissingPatches, missingPatch)

		// Track the most urgent deadline
		daysUntilDeadline := -daysOverdue
		if daysUntilDeadline < mostCriticalDays {
			mostCriticalDays = daysUntilDeadline
		}
	}

	// Determine overall compliance status
	report.DaysUntilBreach = mostCriticalDays

	if mostCriticalDays < 0 {
		// Already past deadline
		report.Status = ComplianceStatusNonCompliant
	} else if mostCriticalDays <= int(e.policy.CriticalThreshold.Hours()/24) {
		// Within critical threshold
		report.Status = ComplianceStatusCritical
	} else if mostCriticalDays <= int(e.policy.WarningThreshold.Hours()/24) {
		// Within warning threshold
		report.Status = ComplianceStatusWarning
	} else {
		// Compliant
		report.Status = ComplianceStatusCompliant
	}

	return report, nil
}

// calculateDeadline calculates the compliance deadline for a patch based on its severity
func (e *PolicyEngine) calculateDeadline(releaseDate time.Time, severity string) time.Time {
	var deadline time.Duration

	switch severity {
	case "critical":
		deadline = e.policy.Critical
	case "important":
		deadline = e.policy.Important
	case "moderate":
		deadline = e.policy.Moderate
	case "low":
		deadline = e.policy.Low
	default:
		// Default to moderate if severity is unknown
		deadline = e.policy.Moderate
	}

	return releaseDate.Add(deadline)
}

// GetPolicyDeadline returns the deadline duration for a given severity level
func (e *PolicyEngine) GetPolicyDeadline(severity string) time.Duration {
	switch severity {
	case "critical":
		return e.policy.Critical
	case "important":
		return e.policy.Important
	case "moderate":
		return e.policy.Moderate
	case "low":
		return e.policy.Low
	default:
		return e.policy.Moderate
	}
}

// DefaultPolicy returns a default patch policy
func DefaultPolicy() PatchPolicy {
	return PatchPolicy{
		Critical:          7 * 24 * time.Hour,  // 7 days for critical patches
		Important:         14 * 24 * time.Hour, // 14 days for important patches
		Moderate:          30 * 24 * time.Hour, // 30 days for moderate patches
		Low:               60 * 24 * time.Hour, // 60 days for low severity patches
		WarningThreshold:  7 * 24 * time.Hour,  // Warning 7 days before deadline
		CriticalThreshold: 24 * time.Hour,      // Critical alert 1 day before deadline
		MajorVersionUpgrade: MajorVersionPolicy{
			Enabled:           false,
			RequireCompatible: true,
			CompatibilityChecks: []string{
				"TPM2.0",
				"UEFI",
				"CPU",
				"RAM",
				"Disk",
			},
		},
	}
}
