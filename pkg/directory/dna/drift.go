// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package dna - Directory Drift Detection Implementation
//
// This file implements drift detection for directory objects, integrating with
// CFGMS's existing drift detection framework to monitor unauthorized changes
// in identity management systems.

package dna

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DefaultDirectoryDriftDetector is the default implementation of DirectoryDriftDetector.
//
// This detector integrates with CFGMS's drift detection patterns while providing
// directory-specific drift detection capabilities and risk assessment.
type DefaultDirectoryDriftDetector struct {
	logger logging.Logger

	// Configuration
	thresholds         *DriftThresholds
	monitoringInterval time.Duration

	// State management
	mutex        sync.RWMutex
	isMonitoring bool
	handlers     map[string]DirectoryDriftHandler

	// Statistics
	stats *DriftDetectionStats

	// Monitoring control
	stopChan       chan struct{}
	monitoringDone chan struct{}
}

// DriftDetectionStats provides statistics about drift detection.
type DriftDetectionStats struct {
	// Detection Statistics
	TotalComparisons int64 `json:"total_comparisons"`
	DriftsDetected   int64 `json:"drifts_detected"`
	CriticalDrifts   int64 `json:"critical_drifts"`
	HighRiskDrifts   int64 `json:"high_risk_drifts"`

	// Performance Statistics
	AverageComparisonTime time.Duration `json:"avg_comparison_time"`
	LastDetectionTime     time.Time     `json:"last_detection_time"`

	// Monitoring Statistics
	MonitoringUptime    time.Duration `json:"monitoring_uptime"`
	LastMonitoringCycle time.Time     `json:"last_monitoring_cycle"`
	MonitoringCycles    int64         `json:"monitoring_cycles"`

	// Handler Statistics
	HandlersTriggered int64 `json:"handlers_triggered"`
	HandlerErrors     int64 `json:"handler_errors"`

	// Health
	HealthStatus    string    `json:"health_status"`
	LastHealthCheck time.Time `json:"last_health_check"`
}

// NewDirectoryDriftDetector creates a new directory drift detector.
func NewDirectoryDriftDetector(logger logging.Logger) *DefaultDirectoryDriftDetector {
	return &DefaultDirectoryDriftDetector{
		logger:             logger,
		thresholds:         getDefaultDriftThresholds(),
		monitoringInterval: 5 * time.Minute,
		handlers:           make(map[string]DirectoryDriftHandler),
		stats: &DriftDetectionStats{
			HealthStatus:    "healthy",
			LastHealthCheck: time.Now(),
		},
	}
}

// getDefaultDriftThresholds returns default drift detection thresholds.
func getDefaultDriftThresholds() *DriftThresholds {
	return &DriftThresholds{
		MaxAttributeChanges:    10,
		AttributeChangeWindow:  1 * time.Hour,
		MaxMembershipChanges:   5,
		MembershipChangeWindow: 30 * time.Minute,
		CriticalAttributes: []string{
			"account_enabled",
			"is_active",
			"user_principal_name",
			"sam_account_name",
			"group_type",
			"group_scope",
			"distinguished_name",
		},
		LowRiskThreshold:      25.0,
		MediumRiskThreshold:   50.0,
		HighRiskThreshold:     75.0,
		CriticalRiskThreshold: 90.0,
	}
}

// Core Drift Detection Methods

// DetectDrift detects drift between current and baseline DirectoryDNA records.
func (d *DefaultDirectoryDriftDetector) DetectDrift(ctx context.Context, current *DirectoryDNA, baseline *DirectoryDNA) (*DirectoryDrift, error) {
	startTime := time.Now()

	// Validate inputs
	if current == nil || baseline == nil {
		return nil, fmt.Errorf("current and baseline DNA records cannot be nil")
	}

	if current.ObjectID != baseline.ObjectID {
		return nil, fmt.Errorf("object IDs do not match: %s vs %s", current.ObjectID, baseline.ObjectID)
	}

	if current.ObjectType != baseline.ObjectType {
		return nil, fmt.Errorf("object types do not match: %s vs %s", current.ObjectType, baseline.ObjectType)
	}

	d.logger.Debug("Detecting drift for directory object",
		"object_id", current.ObjectID,
		"object_type", current.ObjectType)

	// Compare attributes to detect changes
	changes := d.compareAttributes(current, baseline)

	// If no changes detected, return drift with empty changes for single detection
	// but return nil for bulk detection (handled by caller)
	if len(changes) == 0 {
		d.updateStats(func(stats *DriftDetectionStats) {
			stats.TotalComparisons++
		})

		// Return drift object with no changes for consistency in single detection
		drift := &DirectoryDrift{
			DriftID:          d.generateDriftID(current.ObjectID),
			ObjectID:         current.ObjectID,
			ObjectType:       current.ObjectType,
			DriftType:        DirectoryDriftTypeNoChange,
			Severity:         DriftSeverityLow,
			RiskScore:        0.0,
			Changes:          []*DirectoryChange{},
			DetectedAt:       time.Now(),
			Description:      "No changes detected",
			AutoRemediable:   false,
			SuggestedActions: []string{},
		}

		return drift, nil
	}

	// Create drift record
	drift := &DirectoryDrift{
		DriftID:    d.generateDriftID(current.ObjectID),
		ObjectID:   current.ObjectID,
		ObjectType: current.ObjectType,
		Changes:    changes,
		DetectedAt: time.Now(),
		Provider:   current.Provider,
		TenantID:   current.TenantID,
	}

	// Analyze drift characteristics
	d.analyzeDrift(drift)

	// Assess risk
	d.assessRisk(drift)

	// Generate suggested actions
	d.generateSuggestedActions(drift)

	// Update statistics
	d.updateStats(func(stats *DriftDetectionStats) {
		stats.TotalComparisons++
		stats.DriftsDetected++
		stats.LastDetectionTime = time.Now()

		switch drift.Severity {
		case DriftSeverityCritical:
			stats.CriticalDrifts++
		case DriftSeverityHigh:
			stats.HighRiskDrifts++
		}

		// Update average comparison time
		comparisonTime := time.Since(startTime)
		if stats.AverageComparisonTime == 0 {
			stats.AverageComparisonTime = comparisonTime
		} else {
			stats.AverageComparisonTime = (stats.AverageComparisonTime + comparisonTime) / 2
		}
	})

	d.logger.Info("Drift detected for directory object",
		"object_id", current.ObjectID,
		"drift_type", drift.DriftType,
		"severity", drift.Severity,
		"changes", len(drift.Changes),
		"risk_score", drift.RiskScore)

	return drift, nil
}

// DetectBulkDrift detects drift for multiple DirectoryDNA records.
func (d *DefaultDirectoryDriftDetector) DetectBulkDrift(ctx context.Context, currentSet []*DirectoryDNA, baselineSet []*DirectoryDNA) ([]*DirectoryDrift, error) {
	startTime := time.Now()
	d.logger.Info("Detecting bulk drift",
		"current_count", len(currentSet),
		"baseline_count", len(baselineSet))

	// Create lookup maps for efficient comparison
	currentMap := make(map[string]*DirectoryDNA)
	for _, dna := range currentSet {
		currentMap[dna.ObjectID] = dna
	}

	baselineMap := make(map[string]*DirectoryDNA)
	for _, dna := range baselineSet {
		baselineMap[dna.ObjectID] = dna
	}

	var allDrifts []*DirectoryDrift
	var errors []error

	// Control concurrency for bulk operations
	semaphore := make(chan struct{}, 10) // Limit to 10 concurrent comparisons
	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Compare objects that exist in both sets
	for objectID, current := range currentMap {
		if baseline, exists := baselineMap[objectID]; exists {
			wg.Add(1)
			go func(cur, base *DirectoryDNA) {
				defer wg.Done()

				// Acquire semaphore
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				drift, err := d.DetectDrift(ctx, cur, base)

				mutex.Lock()
				if err != nil {
					errors = append(errors, fmt.Errorf("drift detection failed for %s: %w", cur.ObjectID, err))
				} else if drift != nil && len(drift.Changes) > 0 {
					// Only include drifts that have actual changes for bulk detection
					allDrifts = append(allDrifts, drift)
				}
				mutex.Unlock()
			}(current, baseline)
		}
	}

	// Detect new objects (objects in current but not in baseline)
	for objectID, current := range currentMap {
		if _, exists := baselineMap[objectID]; !exists {
			drift := &DirectoryDrift{
				DriftID:     d.generateDriftID(objectID),
				ObjectID:    objectID,
				ObjectType:  current.ObjectType,
				DriftType:   DirectoryDriftTypeObjectCreation,
				Severity:    DriftSeverityMedium,
				Description: fmt.Sprintf("New %s object created", current.ObjectType),
				DetectedAt:  time.Now(),
				Provider:    current.Provider,
				TenantID:    current.TenantID,
				RiskScore:   d.calculateCreationRiskScore(current),
			}

			// Assess if this is an authorized creation or potential security issue
			d.assessCreationRisk(drift, current)
			d.generateSuggestedActions(drift)

			allDrifts = append(allDrifts, drift)
		}
	}

	// Detect deleted objects (objects in baseline but not in current)
	for objectID, baseline := range baselineMap {
		if _, exists := currentMap[objectID]; !exists {
			drift := &DirectoryDrift{
				DriftID:     d.generateDriftID(objectID),
				ObjectID:    objectID,
				ObjectType:  baseline.ObjectType,
				DriftType:   DirectoryDriftTypeObjectDeletion,
				Severity:    DriftSeverityHigh, // Deletions are generally higher risk
				Description: fmt.Sprintf("%s object deleted", baseline.ObjectType),
				DetectedAt:  time.Now(),
				Provider:    baseline.Provider,
				TenantID:    baseline.TenantID,
				RiskScore:   d.calculateDeletionRiskScore(baseline),
			}

			// Assess if this is an authorized deletion or potential security issue
			d.assessDeletionRisk(drift, baseline)
			d.generateSuggestedActions(drift)

			allDrifts = append(allDrifts, drift)
		}
	}

	// Wait for all comparisons to complete
	wg.Wait()

	duration := time.Since(startTime)

	// Log results
	if len(errors) > 0 {
		d.logger.Warn("Bulk drift detection completed with errors",
			"total_comparisons", len(currentSet),
			"drifts_detected", len(allDrifts),
			"errors", len(errors),
			"duration", duration)
	} else {
		d.logger.Info("Bulk drift detection completed successfully",
			"total_comparisons", len(currentSet),
			"drifts_detected", len(allDrifts),
			"duration", duration)
	}

	return allDrifts, nil
}

// Drift Analysis Methods

// compareAttributes compares attributes between current and baseline DNA records.
func (d *DefaultDirectoryDriftDetector) compareAttributes(current, baseline *DirectoryDNA) []*DirectoryChange {
	var changes []*DirectoryChange

	// Track all attributes from both records
	allAttributes := make(map[string]bool)
	for attr := range current.Attributes {
		allAttributes[attr] = true
	}
	for attr := range baseline.Attributes {
		allAttributes[attr] = true
	}

	// Compare each attribute
	for attr := range allAttributes {
		currentValue := current.Attributes[attr]
		baselineValue := baseline.Attributes[attr]

		if currentValue != baselineValue {
			changeType := d.determineChangeType(attr, currentValue, baselineValue)

			change := &DirectoryChange{
				ChangeID:     d.generateChangeID(current.ObjectID, attr),
				ChangeType:   changeType,
				Field:        attr,
				OldValue:     baselineValue,
				NewValue:     currentValue,
				ChangedAt:    time.Now(),
				ChangeSource: "drift_detection",
			}

			changes = append(changes, change)
		}
	}

	return changes
}

// determineChangeType determines the type of change based on old and new values.
func (d *DefaultDirectoryDriftDetector) determineChangeType(field, newValue, oldValue string) DirectoryChangeType {
	if oldValue == "" && newValue != "" {
		return DirectoryChangeTypeCreate
	}
	if oldValue != "" && newValue == "" {
		return DirectoryChangeTypeDelete
	}
	if field == "distinguished_name" {
		return DirectoryChangeTypeMove
	}
	if field == "name" {
		return DirectoryChangeTypeRename
	}
	return DirectoryChangeTypeUpdate
}

// analyzeDrift analyzes the drift characteristics and determines drift type and severity.
func (d *DefaultDirectoryDriftDetector) analyzeDrift(drift *DirectoryDrift) {
	// Count different types of changes
	criticalChanges := 0
	securityRelevant := 0
	membershipChanges := 0

	for _, change := range drift.Changes {
		// Check if change is in critical attributes
		for _, criticalAttr := range d.thresholds.CriticalAttributes {
			if strings.Contains(change.Field, criticalAttr) {
				criticalChanges++
				break
			}
		}

		// Check if change is security relevant
		if d.isSecurityRelevantChange(change) {
			securityRelevant++
		}

		// Check if change is membership related
		if d.isMembershipChange(change) {
			membershipChanges++
		}
	}

	// Determine primary drift type based on change characteristics
	if d.hasPermissionEscalationIndicators(drift.Changes) {
		drift.DriftType = DirectoryDriftTypePermissionEscalation
	} else if d.hasUnauthorizedChangeIndicators(drift.Changes) {
		drift.DriftType = DirectoryDriftTypeUnauthorizedChange
	} else if membershipChanges > 0 {
		drift.DriftType = DirectoryDriftTypeMembershipChange
	} else {
		drift.DriftType = DirectoryDriftTypeAttributeChange
	}

	// Determine severity based on thresholds and change characteristics
	riskFactors := 0
	if criticalChanges > 0 {
		riskFactors += 3
	}
	if securityRelevant > 0 {
		riskFactors += 2
	}
	if membershipChanges > d.thresholds.MaxMembershipChanges {
		riskFactors += 2
	}
	if len(drift.Changes) > d.thresholds.MaxAttributeChanges {
		riskFactors += 1
	}

	// Boost severity for specific high-risk drift types
	if drift.DriftType == DirectoryDriftTypePermissionEscalation {
		riskFactors += 2 // Ensure permission escalation gets high/critical severity
	}
	if drift.DriftType == DirectoryDriftTypeUnauthorizedChange {
		riskFactors += 3 // Ensure unauthorized changes get critical severity
	}

	// Map risk factors to severity
	switch {
	case riskFactors >= 5:
		drift.Severity = DriftSeverityCritical
	case riskFactors >= 3:
		drift.Severity = DriftSeverityHigh
	case riskFactors >= 2:
		drift.Severity = DriftSeverityMedium
	default:
		drift.Severity = DriftSeverityLow
	}

	// Create summary
	drift.Summary = &DriftSummary{
		TotalChanges:       len(drift.Changes),
		CriticalChanges:    criticalChanges,
		SecurityRelevant:   securityRelevant,
		AffectedAttributes: d.extractAffectedAttributes(drift.Changes),
		TimeSpan:           d.calculateTimeSpan(drift.Changes),
	}

	// Set description based on analysis
	drift.Description = d.generateDriftDescription(drift)
}

// isSecurityRelevantChange checks if a change is security relevant.
func (d *DefaultDirectoryDriftDetector) isSecurityRelevantChange(change *DirectoryChange) bool {
	securityFields := []string{
		"account_enabled",
		"is_active",
		"password_expiry",
		"group_type",
		"group_scope",
		"groups",
		"access",
		"member_count",
		"members",
		"permissions",
		"email",
		"email_address",
		"last_login",
		"failed_logins",
	}

	for _, field := range securityFields {
		if strings.Contains(change.Field, field) {
			return true
		}
	}

	return false
}

// hasPermissionEscalationIndicators checks if changes indicate permission escalation.
func (d *DefaultDirectoryDriftDetector) hasPermissionEscalationIndicators(changes []*DirectoryChange) bool {
	for _, change := range changes {
		if change.Field == "groups" || change.Field == "access" {
			// Check if groups or access level are being elevated
			if change.Field == "groups" {
				newVal, newOk := change.NewValue.(string)
				oldVal, oldOk := change.OldValue.(string)
				if newOk && oldOk && len(newVal) > len(oldVal) {
					return true
				}
			}
			if change.Field == "access" {
				newVal, ok := change.NewValue.(string)
				if ok && (newVal == "elevated" || newVal == "admin") {
					return true
				}
			}
		}
	}
	return false
}

// hasUnauthorizedChangeIndicators checks if changes indicate unauthorized activity.
func (d *DefaultDirectoryDriftDetector) hasUnauthorizedChangeIndicators(changes []*DirectoryChange) bool {
	suspiciousChangeCount := 0
	for _, change := range changes {
		// Multiple suspicious changes together indicate unauthorized activity
		newVal, newOk := change.NewValue.(string)
		oldVal, oldOk := change.OldValue.(string)

		if newOk && oldOk {
			if ((change.Field == "email" || change.Field == "email_address") && newVal != oldVal) ||
				(change.Field == "last_login" && newVal == "unknown_location") ||
				(change.Field == "failed_logins" && newVal != "0" && oldVal == "0") {
				suspiciousChangeCount++
			}
		}
	}
	// Multiple suspicious changes indicate compromise
	return suspiciousChangeCount >= 2
}

// isMembershipChange checks if a change is related to group membership.
func (d *DefaultDirectoryDriftDetector) isMembershipChange(change *DirectoryChange) bool {
	membershipFields := []string{
		"groups",
		"member_count",
		"members",
		"member_of",
	}

	for _, field := range membershipFields {
		if strings.Contains(change.Field, field) {
			return true
		}
	}

	return false
}

// Risk Assessment Methods

// assessRisk calculates the risk score for the detected drift.
func (d *DefaultDirectoryDriftDetector) assessRisk(drift *DirectoryDrift) {
	baseRisk := 0.0

	// Base risk from number of changes
	changeRisk := float64(len(drift.Changes)) * 5.0

	// Risk from critical attributes
	criticalRisk := float64(drift.Summary.CriticalChanges) * 20.0

	// Risk from security relevant changes
	securityRisk := float64(drift.Summary.SecurityRelevant) * 15.0

	// Risk from object type
	objectTypeRisk := d.calculateObjectTypeRisk(drift.ObjectType)

	// Risk from drift type
	driftTypeRisk := d.calculateDriftTypeRisk(drift.DriftType)

	// Combine risks
	baseRisk = changeRisk + criticalRisk + securityRisk + objectTypeRisk + driftTypeRisk

	// Apply multipliers based on severity
	switch drift.Severity {
	case DriftSeverityCritical:
		baseRisk *= 2.0
	case DriftSeverityHigh:
		baseRisk *= 1.5
	case DriftSeverityMedium:
		baseRisk *= 1.2
	}

	// Cap at 100
	if baseRisk > 100 {
		baseRisk = 100
	}

	drift.RiskScore = baseRisk

	// Assess impact
	drift.Impact = DirectoryDriftImpact{
		SecurityImpact:    d.assessSecurityImpact(drift),
		OperationalImpact: d.assessOperationalImpact(drift),
		ComplianceImpact:  d.assessComplianceImpact(drift),
		UserImpact:        d.assessUserImpact(drift),
	}

	// Determine if auto-remediable
	drift.AutoRemediable = d.isAutoRemediable(drift)
}

// calculateObjectTypeRisk calculates risk based on object type.
func (d *DefaultDirectoryDriftDetector) calculateObjectTypeRisk(objectType interfaces.DirectoryObjectType) float64 {
	switch objectType {
	case interfaces.DirectoryObjectTypeUser:
		return 10.0 // Users are medium risk
	case interfaces.DirectoryObjectTypeGroup:
		return 15.0 // Groups are higher risk (affect multiple users)
	case interfaces.DirectoryObjectTypeOU:
		return 20.0 // OUs are highest risk (affect organizational structure)
	default:
		return 5.0
	}
}

// calculateDriftTypeRisk calculates risk based on drift type.
func (d *DefaultDirectoryDriftDetector) calculateDriftTypeRisk(driftType DirectoryDriftType) float64 {
	switch driftType {
	case DirectoryDriftTypePermissionEscalation:
		return 25.0
	case DirectoryDriftTypeUnauthorizedChange:
		return 20.0
	case DirectoryDriftTypeMembershipChange:
		return 15.0
	case DirectoryDriftTypeObjectDeletion:
		return 20.0
	case DirectoryDriftTypeObjectCreation:
		return 10.0
	case DirectoryDriftTypeRelationshipChange:
		return 15.0
	default:
		return 5.0
	}
}

// Impact assessment methods
func (d *DefaultDirectoryDriftDetector) assessSecurityImpact(drift *DirectoryDrift) ImpactLevel {
	if drift.Summary.SecurityRelevant > 0 || drift.DriftType == DirectoryDriftTypePermissionEscalation {
		if drift.RiskScore > d.thresholds.CriticalRiskThreshold {
			return ImpactLevelCritical
		}
		if drift.RiskScore > d.thresholds.HighRiskThreshold {
			return ImpactLevelHigh
		}
		return ImpactLevelMedium
	}
	return ImpactLevelLow
}

func (d *DefaultDirectoryDriftDetector) assessOperationalImpact(drift *DirectoryDrift) ImpactLevel {
	if drift.ObjectType == interfaces.DirectoryObjectTypeOU {
		return ImpactLevelHigh
	}
	if drift.ObjectType == interfaces.DirectoryObjectTypeGroup && len(drift.Changes) > 5 {
		return ImpactLevelMedium
	}
	return ImpactLevelLow
}

func (d *DefaultDirectoryDriftDetector) assessComplianceImpact(drift *DirectoryDrift) ImpactLevel {
	// This would be enhanced with compliance-specific rules
	if drift.Summary.CriticalChanges > 0 {
		return ImpactLevelMedium
	}
	return ImpactLevelLow
}

func (d *DefaultDirectoryDriftDetector) assessUserImpact(drift *DirectoryDrift) ImpactLevel {
	if drift.ObjectType == interfaces.DirectoryObjectTypeGroup {
		// High impact if group changes affect many users
		return ImpactLevelMedium
	}
	if drift.ObjectType == interfaces.DirectoryObjectTypeUser {
		return ImpactLevelLow
	}
	return ImpactLevelLow
}

// isAutoRemediable determines if the drift can be automatically remediated.
func (d *DefaultDirectoryDriftDetector) isAutoRemediable(drift *DirectoryDrift) bool {
	// Only low-risk, non-security changes should be auto-remediable
	if drift.RiskScore > d.thresholds.MediumRiskThreshold {
		return false
	}
	if drift.Summary.SecurityRelevant > 0 {
		return false
	}
	if drift.Summary.CriticalChanges > 0 {
		return false
	}
	return true
}

// Helper Methods

// generateDriftID generates a unique identifier for drift records.
func (d *DefaultDirectoryDriftDetector) generateDriftID(objectID string) string {
	timestamp := time.Now().Unix()
	return fmt.Sprintf("drift_%s_%d", objectID, timestamp)
}

// generateChangeID generates a unique identifier for change records.
func (d *DefaultDirectoryDriftDetector) generateChangeID(objectID, field string) string {
	timestamp := time.Now().Unix()
	return fmt.Sprintf("change_%s_%s_%d", objectID, field, timestamp)
}

// extractAffectedAttributes extracts the list of affected attributes from changes.
func (d *DefaultDirectoryDriftDetector) extractAffectedAttributes(changes []*DirectoryChange) []string {
	var attributes []string
	seen := make(map[string]bool)

	for _, change := range changes {
		if !seen[change.Field] {
			attributes = append(attributes, change.Field)
			seen[change.Field] = true
		}
	}

	return attributes
}

// calculateTimeSpan calculates the time span covered by changes.
func (d *DefaultDirectoryDriftDetector) calculateTimeSpan(changes []*DirectoryChange) time.Duration {
	if len(changes) == 0 {
		return 0
	}

	earliest := changes[0].ChangedAt
	latest := changes[0].ChangedAt

	for _, change := range changes {
		if change.ChangedAt.Before(earliest) {
			earliest = change.ChangedAt
		}
		if change.ChangedAt.After(latest) {
			latest = change.ChangedAt
		}
	}

	return latest.Sub(earliest)
}

// generateDriftDescription generates a human-readable description of the drift.
func (d *DefaultDirectoryDriftDetector) generateDriftDescription(drift *DirectoryDrift) string {
	objectTypeName := string(drift.ObjectType)

	switch drift.DriftType {
	case DirectoryDriftTypeUnauthorizedChange:
		return fmt.Sprintf("Unauthorized changes detected in %s: %d attributes modified",
			objectTypeName, len(drift.Changes))
	case DirectoryDriftTypePermissionEscalation:
		return fmt.Sprintf("Potential permission escalation in %s: security-relevant changes detected",
			objectTypeName)
	case DirectoryDriftTypeMembershipChange:
		return fmt.Sprintf("Group membership changes detected for %s", objectTypeName)
	case DirectoryDriftTypeObjectCreation:
		return fmt.Sprintf("New %s object created", objectTypeName)
	case DirectoryDriftTypeObjectDeletion:
		return fmt.Sprintf("%s object deleted", capitalize(objectTypeName))
	default:
		return fmt.Sprintf("Changes detected in %s: %d attributes modified",
			objectTypeName, len(drift.Changes))
	}
}

// calculateCreationRiskScore calculates risk score for object creation.
func (d *DefaultDirectoryDriftDetector) calculateCreationRiskScore(dna *DirectoryDNA) float64 {
	baseRisk := 30.0 // Base risk for new objects

	// Higher risk for privileged objects
	if dna.ObjectType == interfaces.DirectoryObjectTypeGroup {
		baseRisk += 15.0
	}
	if dna.ObjectType == interfaces.DirectoryObjectTypeOU {
		baseRisk += 20.0
	}

	// Check for high-privilege indicators
	if strings.Contains(strings.ToLower(dna.Attributes["name"]), "admin") {
		baseRisk += 25.0
	}
	if strings.Contains(strings.ToLower(dna.Attributes["display_name"]), "admin") {
		baseRisk += 25.0
	}

	return math.Min(baseRisk, 100.0)
}

// calculateDeletionRiskScore calculates risk score for object deletion.
func (d *DefaultDirectoryDriftDetector) calculateDeletionRiskScore(dna *DirectoryDNA) float64 {
	baseRisk := 50.0 // Base risk for deletions (higher than creations)

	// Higher risk for privileged objects
	if dna.ObjectType == interfaces.DirectoryObjectTypeGroup {
		baseRisk += 20.0
	}
	if dna.ObjectType == interfaces.DirectoryObjectTypeOU {
		baseRisk += 25.0
	}

	// Check for high-privilege indicators
	if strings.Contains(strings.ToLower(dna.Attributes["name"]), "admin") {
		baseRisk += 30.0
	}

	return math.Min(baseRisk, 100.0)
}

// assessCreationRisk assesses the risk of object creation.
func (d *DefaultDirectoryDriftDetector) assessCreationRisk(drift *DirectoryDrift, dna *DirectoryDNA) {
	// Analyze creation patterns for suspicious activity
	if strings.Contains(strings.ToLower(dna.Attributes["name"]), "admin") ||
		strings.Contains(strings.ToLower(dna.Attributes["display_name"]), "admin") {
		drift.Severity = DriftSeverityHigh
		drift.Description += " (potential privilege escalation)"
	}
}

// assessDeletionRisk assesses the risk of object deletion.
func (d *DefaultDirectoryDriftDetector) assessDeletionRisk(drift *DirectoryDrift, dna *DirectoryDNA) {
	// Deletions are generally higher risk, especially for privileged objects
	if strings.Contains(strings.ToLower(dna.Attributes["name"]), "admin") {
		drift.Severity = DriftSeverityCritical
		drift.Description += " (privileged object deletion)"
	}
}

// generateSuggestedActions generates suggested remediation actions.
func (d *DefaultDirectoryDriftDetector) generateSuggestedActions(drift *DirectoryDrift) {
	var actions []string

	switch drift.DriftType {
	case DirectoryDriftTypeUnauthorizedChange:
		actions = append(actions, "Review change authorization")
		actions = append(actions, "Verify change was intended")
		if drift.AutoRemediable {
			actions = append(actions, "Consider automatic reversion")
		}

	case DirectoryDriftTypePermissionEscalation:
		actions = append(actions, "Immediate security review required")
		actions = append(actions, "Audit user/group permissions")
		actions = append(actions, "Review access logs")

	case DirectoryDriftTypeMembershipChange:
		actions = append(actions, "Review group membership changes")
		actions = append(actions, "Validate business justification")

	case DirectoryDriftTypeObjectCreation:
		actions = append(actions, "Verify object creation was authorized")
		actions = append(actions, "Review object configuration")

	case DirectoryDriftTypeObjectDeletion:
		actions = append(actions, "Verify deletion was authorized")
		actions = append(actions, "Check if restoration is needed")

	default:
		actions = append(actions, "Review detected changes")
		actions = append(actions, "Validate change approval")
	}

	// Add severity-specific actions
	switch drift.Severity {
	case DriftSeverityCritical:
		actions = append([]string{"URGENT: Immediate investigation required"}, actions...)
	case DriftSeverityHigh:
		actions = append([]string{"High priority: Review within 1 hour"}, actions...)
	}

	drift.SuggestedActions = actions
}

// updateStats safely updates drift detection statistics.
func (d *DefaultDirectoryDriftDetector) updateStats(updater func(*DriftDetectionStats)) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	updater(d.stats)
}

// GetDriftDetectionStats returns current drift detection statistics.
func (d *DefaultDirectoryDriftDetector) GetDriftDetectionStats() *DriftDetectionStats {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// Return a copy to prevent race conditions
	statsCopy := *d.stats
	return &statsCopy
}

// IsMonitoring returns whether drift monitoring is currently active
func (d *DefaultDirectoryDriftDetector) IsMonitoring() bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.isMonitoring
}

// GetMonitoringInterval returns the current monitoring interval
func (d *DefaultDirectoryDriftDetector) GetMonitoringInterval() time.Duration {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.monitoringInterval
}

// GetDriftThresholds returns the current drift thresholds
func (d *DefaultDirectoryDriftDetector) GetDriftThresholds() *DriftThresholds {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.thresholds
}

// StartMonitoring starts the drift monitoring process
func (d *DefaultDirectoryDriftDetector) StartMonitoring(ctx context.Context) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.isMonitoring {
		return fmt.Errorf("drift detector already monitoring")
	}

	d.isMonitoring = true
	d.stopChan = make(chan struct{})
	d.monitoringDone = make(chan struct{})

	// Start monitoring goroutine (simplified for this implementation)
	go func() {
		defer close(d.monitoringDone)
		ticker := time.NewTicker(d.monitoringInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stopChan:
				return
			case <-ticker.C:
				// Monitoring logic would go here
			}
		}
	}()

	return nil
}

// StopMonitoring stops the drift monitoring process
func (d *DefaultDirectoryDriftDetector) StopMonitoring() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if !d.isMonitoring {
		return fmt.Errorf("drift detector not running")
	}

	close(d.stopChan)
	<-d.monitoringDone
	d.isMonitoring = false

	return nil
}

// SetMonitoringInterval sets the monitoring interval
func (d *DefaultDirectoryDriftDetector) SetMonitoringInterval(interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("interval must be positive")
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.monitoringInterval = interval
	return nil
}

// SetDriftThresholds sets the drift detection thresholds
func (d *DefaultDirectoryDriftDetector) SetDriftThresholds(thresholds *DriftThresholds) error {
	if thresholds == nil {
		return fmt.Errorf("thresholds cannot be nil")
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.thresholds = thresholds
	return nil
}

// RegisterDriftHandler registers a drift handler
func (d *DefaultDirectoryDriftDetector) RegisterDriftHandler(handler DirectoryDriftHandler) error {
	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}

	id := handler.GetHandlerID()
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, exists := d.handlers[id]; exists {
		return fmt.Errorf("handler %s already registered", id)
	}

	d.handlers[id] = handler
	return nil
}

// UnregisterDriftHandler unregisters a drift handler
func (d *DefaultDirectoryDriftDetector) UnregisterDriftHandler(handlerID string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, exists := d.handlers[handlerID]; !exists {
		return fmt.Errorf("handler %s not found", handlerID)
	}

	delete(d.handlers, handlerID)
	return nil
}

// capitalize capitalizes the first letter of a string
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
