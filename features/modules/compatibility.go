// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package modules

import (
	"fmt"
	"sync"
	"time"
)

// BreakingChange represents a breaking change between versions
type BreakingChange struct {
	Type        BreakingChangeType `json:"type"`
	Description string             `json:"description"`
	AffectedAPI []string           `json:"affected_api"`
	Severity    ChangeSeverity     `json:"severity"`
}

// APIChange represents an API change between versions
type APIChange struct {
	Type        APIChangeType `json:"type"`
	Method      string        `json:"method,omitempty"`
	Field       string        `json:"field,omitempty"`
	Description string        `json:"description"`
}

// BreakingChangeType defines types of breaking changes
type BreakingChangeType int

const (
	BreakingChangeRemoval BreakingChangeType = iota
	BreakingChangeModification
	BreakingChangeSignature
	BreakingChangeBehavior
)

func (t BreakingChangeType) String() string {
	switch t {
	case BreakingChangeRemoval:
		return "removal"
	case BreakingChangeModification:
		return "modification"
	case BreakingChangeSignature:
		return "signature"
	case BreakingChangeBehavior:
		return "behavior"
	default:
		return "unknown"
	}
}

// APIChangeType defines types of API changes
type APIChangeType int

const (
	APIChangeAddition APIChangeType = iota
	APIChangeDeprecation
	APIChangeModification
)

func (t APIChangeType) String() string {
	switch t {
	case APIChangeAddition:
		return "addition"
	case APIChangeDeprecation:
		return "deprecation"
	case APIChangeModification:
		return "modification"
	default:
		return "unknown"
	}
}

// ChangeSeverity defines the severity of changes
type ChangeSeverity int

const (
	SeverityLow ChangeSeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s ChangeSeverity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// CompatibilityMatrix manages version compatibility information across modules
type CompatibilityMatrix interface {
	// Compatibility Management
	RecordCompatibility(moduleName, version string, compatibility *VersionCompatibilityInfo) error
	GetCompatibility(moduleName, version string) (*VersionCompatibilityInfo, error)
	UpdateCompatibility(moduleName, version string, compatibility *VersionCompatibilityInfo) error
	RemoveCompatibility(moduleName, version string) error

	// Cross-Module Compatibility
	CheckCrossModuleCompatibility(moduleVersions map[string]string) (*CompatibilityReport, error)
	FindCompatibleVersionSet(requirements []ModuleVersionRequirement) (*CompatibleVersionSet, error)

	// Breaking Change Analysis
	AnalyzeBreakingChanges(moduleName, fromVersion, toVersion string) (*BreakingChangeAnalysis, error)
	RecordBreakingChange(moduleName, version string, change BreakingChange) error

	// API Change Tracking
	RecordAPIChange(moduleName, version string, change APIChange) error
	GetAPIChanges(moduleName, fromVersion, toVersion string) ([]APIChange, error)

	// Compatibility Queries
	GetBackwardsCompatibleVersions(moduleName, version string) ([]string, error)
	GetForwardsCompatibleVersions(moduleName, version string) ([]string, error)
	IsCompatible(moduleA, versionA, moduleB, versionB string) (bool, error)

	// Matrix Status
	GetMatrixStatus() *CompatibilityMatrixStatus
}

// DefaultCompatibilityMatrix implements the CompatibilityMatrix interface
type DefaultCompatibilityMatrix struct {
	mu sync.RWMutex

	// compatibility maps module names to version compatibility info
	// Format: compatibility["module_name"]["version"] = *VersionCompatibilityInfo
	compatibility map[string]map[string]*VersionCompatibilityInfo

	// crossModuleRules defines compatibility rules between different modules
	crossModuleRules map[string]map[string]*CrossModuleCompatibilityRule

	// breakingChanges tracks breaking changes for each module version
	breakingChanges map[string]map[string][]BreakingChange

	// apiChanges tracks API changes for each module version
	apiChanges map[string]map[string][]APIChange

	// registry reference for version validation
	registry ModuleVersionRegistry
}

// CrossModuleCompatibilityRule defines compatibility rules between different modules
type CrossModuleCompatibilityRule struct {
	ModuleA         string            `json:"module_a"`
	ModuleB         string            `json:"module_b"`
	CompatiblePairs []VersionPair     `json:"compatible_pairs"`
	Conflicts       []VersionConflict `json:"conflicts"`
	LastUpdated     time.Time         `json:"last_updated"`
}

// VersionPair represents a compatible pair of module versions
type VersionPair struct {
	VersionA string `json:"version_a"`
	VersionB string `json:"version_b"`
	Verified bool   `json:"verified"` // Whether this compatibility has been tested
	Notes    string `json:"notes,omitempty"`
}

// CompatibilityReport provides comprehensive compatibility analysis
type CompatibilityReport struct {
	ModuleVersions     map[string]string         `json:"module_versions"`
	OverallStatus      CompatibilityStatus       `json:"overall_status"`
	CompatibilityScore float64                   `json:"compatibility_score"` // 0.0 to 1.0
	Issues             []CompatibilityIssue      `json:"issues"`
	Warnings           []CompatibilityWarning    `json:"warnings"`
	Recommendations    []string                  `json:"recommendations"`
	AnalysisTime       time.Time                 `json:"analysis_time"`
	DetailedResults    []ModulePairCompatibility `json:"detailed_results"`
}

// CompatibilityStatus represents the overall compatibility status
type CompatibilityStatus int

const (
	CompatibilityStatusUnknown CompatibilityStatus = iota
	CompatibilityStatusCompatible
	CompatibilityStatusPartiallyCompatible
	CompatibilityStatusIncompatible
	CompatibilityStatusConflicting
)

func (s CompatibilityStatus) String() string {
	switch s {
	case CompatibilityStatusUnknown:
		return "unknown"
	case CompatibilityStatusCompatible:
		return "compatible"
	case CompatibilityStatusPartiallyCompatible:
		return "partially_compatible"
	case CompatibilityStatusIncompatible:
		return "incompatible"
	case CompatibilityStatusConflicting:
		return "conflicting"
	default:
		return "unknown"
	}
}

// CompatibilityIssue represents a compatibility problem
type CompatibilityIssue struct {
	Type        CompatibilityIssueType `json:"type"`
	Severity    CompatibilitySeverity  `json:"severity"`
	ModuleA     string                 `json:"module_a"`
	VersionA    string                 `json:"version_a"`
	ModuleB     string                 `json:"module_b,omitempty"`
	VersionB    string                 `json:"version_b,omitempty"`
	Description string                 `json:"description"`
	Impact      string                 `json:"impact"`
	Resolution  string                 `json:"resolution,omitempty"`
}

// CompatibilityIssueType defines types of compatibility issues
type CompatibilityIssueType int

const (
	IssueTypeBreakingChange CompatibilityIssueType = iota
	IssueTypeAPIIncompatibility
	IssueTypeVersionConflict
	IssueTypeDependencyMismatch
	IssueTypeUnsupportedFeature
	IssueTypePerformanceDegradation
)

func (t CompatibilityIssueType) String() string {
	switch t {
	case IssueTypeBreakingChange:
		return "breaking_change"
	case IssueTypeAPIIncompatibility:
		return "api_incompatibility"
	case IssueTypeVersionConflict:
		return "version_conflict"
	case IssueTypeDependencyMismatch:
		return "dependency_mismatch"
	case IssueTypeUnsupportedFeature:
		return "unsupported_feature"
	case IssueTypePerformanceDegradation:
		return "performance_degradation"
	default:
		return "unknown"
	}
}

// CompatibilitySeverity defines the severity of compatibility issues
type CompatibilitySeverity int

const (
	SeverityInfo CompatibilitySeverity = iota
	SeverityWarning
	SeverityError
	SeverityCompatCritical
)

func (s CompatibilitySeverity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	case SeverityCompatCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// CompatibilityWarning represents a potential compatibility concern
type CompatibilityWarning struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	ModuleName string `json:"module_name"`
	Version    string `json:"version"`
	Suggestion string `json:"suggestion,omitempty"`
}

// ModulePairCompatibility represents compatibility analysis between two modules
type ModulePairCompatibility struct {
	ModuleA            string               `json:"module_a"`
	VersionA           string               `json:"version_a"`
	ModuleB            string               `json:"module_b"`
	VersionB           string               `json:"version_b"`
	CompatibilityLevel CompatibilityLevel   `json:"compatibility_level"`
	Issues             []CompatibilityIssue `json:"issues"`
	Notes              string               `json:"notes,omitempty"`
}

// CompatibilityLevel defines levels of compatibility between module versions
type CompatibilityLevel int

const (
	CompatibilityLevelUnknown CompatibilityLevel = iota
	CompatibilityLevelFullyCompatible
	CompatibilityLevelBackwardsCompatible
	CompatibilityLevelForwardsCompatible
	CompatibilityLevelPartiallyCompatible
	CompatibilityLevelIncompatible
)

func (l CompatibilityLevel) String() string {
	switch l {
	case CompatibilityLevelUnknown:
		return "unknown"
	case CompatibilityLevelFullyCompatible:
		return "fully_compatible"
	case CompatibilityLevelBackwardsCompatible:
		return "backwards_compatible"
	case CompatibilityLevelForwardsCompatible:
		return "forwards_compatible"
	case CompatibilityLevelPartiallyCompatible:
		return "partially_compatible"
	case CompatibilityLevelIncompatible:
		return "incompatible"
	default:
		return "unknown"
	}
}

// CompatibleVersionSet represents a set of module versions that are mutually compatible
type CompatibleVersionSet struct {
	ID                 string            `json:"id"`
	ModuleVersions     map[string]string `json:"module_versions"`
	CompatibilityScore float64           `json:"compatibility_score"`
	GenerationTime     time.Time         `json:"generation_time"`
	Verified           bool              `json:"verified"`
	Notes              string            `json:"notes,omitempty"`
}

// BreakingChangeAnalysis provides detailed analysis of breaking changes between versions
type BreakingChangeAnalysis struct {
	ModuleName        string           `json:"module_name"`
	FromVersion       string           `json:"from_version"`
	ToVersion         string           `json:"to_version"`
	BreakingChanges   []BreakingChange `json:"breaking_changes"`
	MitigationSteps   []string         `json:"mitigation_steps"`
	OverallSeverity   ChangeSeverity   `json:"overall_severity"`
	MigrationRequired bool             `json:"migration_required"`
	AnalysisTime      time.Time        `json:"analysis_time"`
}

// CompatibilityMatrixStatus provides overview of the compatibility matrix
type CompatibilityMatrixStatus struct {
	TotalModules           int       `json:"total_modules"`
	TotalVersions          int       `json:"total_versions"`
	CoveredPairs           int       `json:"covered_pairs"`
	VerifiedPairs          int       `json:"verified_pairs"`
	KnownIncompatibilities int       `json:"known_incompatibilities"`
	LastUpdated            time.Time `json:"last_updated"`
	MatrixCompleteness     float64   `json:"matrix_completeness"` // Percentage of covered pairs
}

// NewDefaultCompatibilityMatrix creates a new compatibility matrix
func NewDefaultCompatibilityMatrix(registry ModuleVersionRegistry) *DefaultCompatibilityMatrix {
	return &DefaultCompatibilityMatrix{
		compatibility:    make(map[string]map[string]*VersionCompatibilityInfo),
		crossModuleRules: make(map[string]map[string]*CrossModuleCompatibilityRule),
		breakingChanges:  make(map[string]map[string][]BreakingChange),
		apiChanges:       make(map[string]map[string][]APIChange),
		registry:         registry,
	}
}

// RecordCompatibility records compatibility information for a module version
func (m *DefaultCompatibilityMatrix) RecordCompatibility(moduleName, version string, compatibility *VersionCompatibilityInfo) error {
	if moduleName == "" || version == "" {
		return fmt.Errorf("module name and version are required")
	}

	if compatibility == nil {
		return fmt.Errorf("compatibility information cannot be nil")
	}

	// Validate that the version exists
	if !m.registry.IsVersionInstalled(moduleName, version) {
		return fmt.Errorf("version %s of module %s is not installed", version, moduleName)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize module compatibility map if it doesn't exist
	if m.compatibility[moduleName] == nil {
		m.compatibility[moduleName] = make(map[string]*VersionCompatibilityInfo)
	}

	// Clone the compatibility info to prevent external modification
	compatibilityClone := &VersionCompatibilityInfo{
		BackwardsCompatible: make([]string, len(compatibility.BackwardsCompatible)),
		ForwardsCompatible:  make([]string, len(compatibility.ForwardsCompatible)),
		BreakingChanges:     make([]BreakingChange, len(compatibility.BreakingChanges)),
		APIChanges:          make([]APIChange, len(compatibility.APIChanges)),
		MigrationRequired:   compatibility.MigrationRequired,
		MigrationComplexity: compatibility.MigrationComplexity,
	}

	copy(compatibilityClone.BackwardsCompatible, compatibility.BackwardsCompatible)
	copy(compatibilityClone.ForwardsCompatible, compatibility.ForwardsCompatible)
	copy(compatibilityClone.BreakingChanges, compatibility.BreakingChanges)
	copy(compatibilityClone.APIChanges, compatibility.APIChanges)

	m.compatibility[moduleName][version] = compatibilityClone

	// Also record breaking changes and API changes separately for easier access
	if len(compatibility.BreakingChanges) > 0 {
		if m.breakingChanges[moduleName] == nil {
			m.breakingChanges[moduleName] = make(map[string][]BreakingChange)
		}
		m.breakingChanges[moduleName][version] = compatibility.BreakingChanges
	}

	if len(compatibility.APIChanges) > 0 {
		if m.apiChanges[moduleName] == nil {
			m.apiChanges[moduleName] = make(map[string][]APIChange)
		}
		m.apiChanges[moduleName][version] = compatibility.APIChanges
	}

	return nil
}

// GetCompatibility retrieves compatibility information for a module version
func (m *DefaultCompatibilityMatrix) GetCompatibility(moduleName, version string) (*VersionCompatibilityInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	moduleCompat := m.compatibility[moduleName]
	if moduleCompat == nil {
		return nil, fmt.Errorf("no compatibility information for module %s", moduleName)
	}

	compatibility := moduleCompat[version]
	if compatibility == nil {
		return nil, fmt.Errorf("no compatibility information for version %s of module %s", version, moduleName)
	}

	// Return a clone to prevent external modification
	return m.cloneCompatibilityInfo(compatibility), nil
}

// UpdateCompatibility updates existing compatibility information
func (m *DefaultCompatibilityMatrix) UpdateCompatibility(moduleName, version string, compatibility *VersionCompatibilityInfo) error {
	// First check if it exists
	_, err := m.GetCompatibility(moduleName, version)
	if err != nil {
		return fmt.Errorf("cannot update non-existent compatibility info: %v", err)
	}

	// Use RecordCompatibility to update (it will overwrite)
	return m.RecordCompatibility(moduleName, version, compatibility)
}

// RemoveCompatibility removes compatibility information for a module version
func (m *DefaultCompatibilityMatrix) RemoveCompatibility(moduleName, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	moduleCompat := m.compatibility[moduleName]
	if moduleCompat == nil {
		return fmt.Errorf("no compatibility information for module %s", moduleName)
	}

	if _, exists := moduleCompat[version]; !exists {
		return fmt.Errorf("no compatibility information for version %s of module %s", version, moduleName)
	}

	delete(moduleCompat, version)

	// Clean up empty maps
	if len(moduleCompat) == 0 {
		delete(m.compatibility, moduleName)
	}

	// Also clean up breaking changes and API changes
	if m.breakingChanges[moduleName] != nil {
		delete(m.breakingChanges[moduleName], version)
		if len(m.breakingChanges[moduleName]) == 0 {
			delete(m.breakingChanges, moduleName)
		}
	}

	if m.apiChanges[moduleName] != nil {
		delete(m.apiChanges[moduleName], version)
		if len(m.apiChanges[moduleName]) == 0 {
			delete(m.apiChanges, moduleName)
		}
	}

	return nil
}

// CheckCrossModuleCompatibility analyzes compatibility across multiple modules
func (m *DefaultCompatibilityMatrix) CheckCrossModuleCompatibility(moduleVersions map[string]string) (*CompatibilityReport, error) {
	report := &CompatibilityReport{
		ModuleVersions:  make(map[string]string),
		Issues:          make([]CompatibilityIssue, 0),
		Warnings:        make([]CompatibilityWarning, 0),
		Recommendations: make([]string, 0),
		AnalysisTime:    time.Now(),
		DetailedResults: make([]ModulePairCompatibility, 0),
	}

	// Copy module versions
	for k, v := range moduleVersions {
		report.ModuleVersions[k] = v
	}

	totalPairs := 0
	compatiblePairs := 0

	// Check all pairs of modules
	modules := make([]string, 0, len(moduleVersions))
	for module := range moduleVersions {
		modules = append(modules, module)
	}

	for i := 0; i < len(modules); i++ {
		for j := i + 1; j < len(modules); j++ {
			moduleA, moduleB := modules[i], modules[j]
			versionA, versionB := moduleVersions[moduleA], moduleVersions[moduleB]

			totalPairs++

			pairResult := m.analyzePairCompatibility(moduleA, versionA, moduleB, versionB)
			report.DetailedResults = append(report.DetailedResults, *pairResult)

			// Add issues from this pair
			report.Issues = append(report.Issues, pairResult.Issues...)

			// Count compatible pairs
			if pairResult.CompatibilityLevel == CompatibilityLevelFullyCompatible ||
				pairResult.CompatibilityLevel == CompatibilityLevelBackwardsCompatible ||
				pairResult.CompatibilityLevel == CompatibilityLevelForwardsCompatible {
				compatiblePairs++
			}
		}
	}

	// Calculate compatibility score
	if totalPairs > 0 {
		report.CompatibilityScore = float64(compatiblePairs) / float64(totalPairs)
	} else {
		report.CompatibilityScore = 1.0 // Single module is always compatible with itself
	}

	// Determine overall status
	report.OverallStatus = m.calculateOverallStatus(report.CompatibilityScore, len(report.Issues))

	// Generate recommendations
	report.Recommendations = m.generateCompatibilityRecommendations(report)

	return report, nil
}

// analyzePairCompatibility analyzes compatibility between two specific modules
func (m *DefaultCompatibilityMatrix) analyzePairCompatibility(moduleA, versionA, moduleB, versionB string) *ModulePairCompatibility {
	result := &ModulePairCompatibility{
		ModuleA:  moduleA,
		VersionA: versionA,
		ModuleB:  moduleB,
		VersionB: versionB,
		Issues:   make([]CompatibilityIssue, 0),
	}

	// Check if we have a cross-module rule for these modules
	m.mu.RLock()
	rule := m.getCrossModuleRule(moduleA, moduleB)
	m.mu.RUnlock()

	if rule != nil {
		// Check against known compatible pairs
		for _, pair := range rule.CompatiblePairs {
			if (pair.VersionA == versionA && pair.VersionB == versionB) ||
				(pair.VersionA == versionB && pair.VersionB == versionA) {
				if pair.Verified {
					result.CompatibilityLevel = CompatibilityLevelFullyCompatible
				} else {
					result.CompatibilityLevel = CompatibilityLevelPartiallyCompatible
				}
				result.Notes = pair.Notes
				return result
			}
		}

		// Check for known conflicts
		for _, conflict := range rule.Conflicts {
			for _, constraint := range conflict.Constraints {
				// Simple constraint checking - in practice this would be more sophisticated
				if constraint == versionA || constraint == versionB {
					result.CompatibilityLevel = CompatibilityLevelIncompatible
					result.Issues = append(result.Issues, CompatibilityIssue{
						Type:        IssueTypeVersionConflict,
						Severity:    SeverityError,
						ModuleA:     moduleA,
						VersionA:    versionA,
						ModuleB:     moduleB,
						VersionB:    versionB,
						Description: conflict.ConflictReason,
						Impact:      "Modules cannot be used together",
					})
					return result
				}
			}
		}
	}

	// If no specific rule exists, do semantic version analysis
	result.CompatibilityLevel = m.inferCompatibilityLevel(moduleA, versionA, moduleB, versionB)

	return result
}

// inferCompatibilityLevel infers compatibility based on semantic versioning principles
func (m *DefaultCompatibilityMatrix) inferCompatibilityLevel(moduleA, versionA, moduleB, versionB string) CompatibilityLevel {
	// Get compatibility info for both versions
	compatA, errA := m.GetCompatibility(moduleA, versionA)
	compatB, errB := m.GetCompatibility(moduleB, versionB)

	// If we don't have compatibility info, assume unknown
	if errA != nil || errB != nil {
		return CompatibilityLevelUnknown
	}

	// Check for major breaking changes
	if len(compatA.BreakingChanges) > 0 || len(compatB.BreakingChanges) > 0 {
		hasHighSeverityChanges := false
		for _, change := range compatA.BreakingChanges {
			if change.Severity >= SeverityHigh {
				hasHighSeverityChanges = true
				break
			}
		}
		for _, change := range compatB.BreakingChanges {
			if change.Severity >= SeverityHigh {
				hasHighSeverityChanges = true
				break
			}
		}

		if hasHighSeverityChanges {
			return CompatibilityLevelIncompatible
		}
		return CompatibilityLevelPartiallyCompatible
	}

	// Default to partially compatible if no specific information
	return CompatibilityLevelPartiallyCompatible
}

// getCrossModuleRule retrieves cross-module compatibility rule (internal method)
func (m *DefaultCompatibilityMatrix) getCrossModuleRule(moduleA, moduleB string) *CrossModuleCompatibilityRule {
	// Try both directions
	if m.crossModuleRules[moduleA] != nil {
		if rule := m.crossModuleRules[moduleA][moduleB]; rule != nil {
			return rule
		}
	}

	if m.crossModuleRules[moduleB] != nil {
		if rule := m.crossModuleRules[moduleB][moduleA]; rule != nil {
			return rule
		}
	}

	return nil
}

// calculateOverallStatus determines the overall compatibility status
func (m *DefaultCompatibilityMatrix) calculateOverallStatus(score float64, issueCount int) CompatibilityStatus {
	if issueCount == 0 {
		if score >= 0.9 {
			return CompatibilityStatusCompatible
		} else if score >= 0.7 {
			return CompatibilityStatusPartiallyCompatible
		}
	}

	criticalIssues := 0
	// In practice, you'd count critical issues from the issues array
	if criticalIssues > 0 {
		return CompatibilityStatusConflicting
	}

	if score < 0.5 {
		return CompatibilityStatusIncompatible
	}

	return CompatibilityStatusPartiallyCompatible
}

// generateCompatibilityRecommendations generates recommendations based on the compatibility report
func (m *DefaultCompatibilityMatrix) generateCompatibilityRecommendations(report *CompatibilityReport) []string {
	var recommendations []string

	if report.CompatibilityScore < 0.7 {
		recommendations = append(recommendations, "Consider updating modules to more compatible versions")
	}

	criticalIssues := 0
	for _, issue := range report.Issues {
		if issue.Severity == SeverityCompatCritical {
			criticalIssues++
		}
	}

	if criticalIssues > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Address %d critical compatibility issues before deployment", criticalIssues))
	}

	if len(report.DetailedResults) > 10 && report.CompatibilityScore < 0.8 {
		recommendations = append(recommendations, "Consider reducing the number of modules or creating module groups")
	}

	return recommendations
}

// FindCompatibleVersionSet finds a set of module versions that are mutually compatible
func (m *DefaultCompatibilityMatrix) FindCompatibleVersionSet(requirements []ModuleVersionRequirement) (*CompatibleVersionSet, error) {
	// This is a complex optimization problem - for now, implement a simple greedy approach
	versionSet := &CompatibleVersionSet{
		ID:             fmt.Sprintf("set-%d", time.Now().UnixNano()),
		ModuleVersions: make(map[string]string),
		GenerationTime: time.Now(),
		Verified:       false,
	}

	// For each module, find the best compatible version
	for _, req := range requirements {
		compatibleVersions, err := m.registry.GetCompatibleVersions(req.ModuleName, req.Constraint)
		if err != nil {
			return nil, fmt.Errorf("failed to get compatible versions for %s: %v", req.ModuleName, err)
		}

		if len(compatibleVersions) == 0 {
			return nil, fmt.Errorf("no compatible versions found for module %s with constraint %s", req.ModuleName, req.Constraint)
		}

		// For now, select the latest compatible version
		// In practice, this would involve more sophisticated constraint solving
		versionSet.ModuleVersions[req.ModuleName] = compatibleVersions[len(compatibleVersions)-1]
	}

	// Verify the selected set is compatible
	report, err := m.CheckCrossModuleCompatibility(versionSet.ModuleVersions)
	if err != nil {
		return nil, fmt.Errorf("failed to verify compatibility: %v", err)
	}

	versionSet.CompatibilityScore = report.CompatibilityScore
	versionSet.Verified = report.OverallStatus == CompatibilityStatusCompatible

	return versionSet, nil
}

// AnalyzeBreakingChanges analyzes breaking changes between two versions
func (m *DefaultCompatibilityMatrix) AnalyzeBreakingChanges(moduleName, fromVersion, toVersion string) (*BreakingChangeAnalysis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	analysis := &BreakingChangeAnalysis{
		ModuleName:      moduleName,
		FromVersion:     fromVersion,
		ToVersion:       toVersion,
		BreakingChanges: make([]BreakingChange, 0),
		MitigationSteps: make([]string, 0),
		AnalysisTime:    time.Now(),
	}

	// Get breaking changes for the target version
	moduleChanges := m.breakingChanges[moduleName]
	if moduleChanges == nil {
		analysis.OverallSeverity = SeverityLow
		analysis.MigrationRequired = false
		return analysis, nil
	}

	changes := moduleChanges[toVersion]
	if changes == nil {
		analysis.OverallSeverity = SeverityLow
		analysis.MigrationRequired = false
		return analysis, nil
	}

	analysis.BreakingChanges = changes

	// Determine overall severity
	maxSeverity := SeverityLow
	for _, change := range changes {
		if change.Severity > maxSeverity {
			maxSeverity = change.Severity
		}
	}
	analysis.OverallSeverity = maxSeverity

	// Determine if migration is required
	analysis.MigrationRequired = maxSeverity >= SeverityMedium

	// Generate mitigation steps
	analysis.MitigationSteps = m.generateMitigationSteps(changes)

	return analysis, nil
}

// generateMitigationSteps generates mitigation steps for breaking changes
func (m *DefaultCompatibilityMatrix) generateMitigationSteps(changes []BreakingChange) []string {
	var steps []string

	for _, change := range changes {
		switch change.Type {
		case BreakingChangeRemoval:
			steps = append(steps, fmt.Sprintf("Update code to remove usage of removed %s", change.Description))
		case BreakingChangeModification:
			steps = append(steps, fmt.Sprintf("Adapt to modified %s", change.Description))
		case BreakingChangeSignature:
			steps = append(steps, fmt.Sprintf("Update function calls for changed signature: %s", change.Description))
		case BreakingChangeBehavior:
			steps = append(steps, fmt.Sprintf("Review and adapt to behavioral change: %s", change.Description))
		}
	}

	if len(steps) == 0 {
		steps = append(steps, "Review module documentation for migration guidance")
	}

	return steps
}

// RecordBreakingChange records a breaking change for a module version
func (m *DefaultCompatibilityMatrix) RecordBreakingChange(moduleName, version string, change BreakingChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.breakingChanges[moduleName] == nil {
		m.breakingChanges[moduleName] = make(map[string][]BreakingChange)
	}

	m.breakingChanges[moduleName][version] = append(m.breakingChanges[moduleName][version], change)

	// Also update the compatibility info if it exists
	if m.compatibility[moduleName] != nil && m.compatibility[moduleName][version] != nil {
		m.compatibility[moduleName][version].BreakingChanges = append(
			m.compatibility[moduleName][version].BreakingChanges, change)
	}

	return nil
}

// RecordAPIChange records an API change for a module version
func (m *DefaultCompatibilityMatrix) RecordAPIChange(moduleName, version string, change APIChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.apiChanges[moduleName] == nil {
		m.apiChanges[moduleName] = make(map[string][]APIChange)
	}

	m.apiChanges[moduleName][version] = append(m.apiChanges[moduleName][version], change)

	// Also update the compatibility info if it exists
	if m.compatibility[moduleName] != nil && m.compatibility[moduleName][version] != nil {
		m.compatibility[moduleName][version].APIChanges = append(
			m.compatibility[moduleName][version].APIChanges, change)
	}

	return nil
}

// GetAPIChanges returns API changes between two versions
func (m *DefaultCompatibilityMatrix) GetAPIChanges(moduleName, fromVersion, toVersion string) ([]APIChange, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	moduleChanges := m.apiChanges[moduleName]
	if moduleChanges == nil {
		return []APIChange{}, nil
	}

	changes := moduleChanges[toVersion]
	if changes == nil {
		return []APIChange{}, nil
	}

	return changes, nil
}

// GetBackwardsCompatibleVersions returns versions that are backwards compatible with the given version
func (m *DefaultCompatibilityMatrix) GetBackwardsCompatibleVersions(moduleName, version string) ([]string, error) {
	compatibility, err := m.GetCompatibility(moduleName, version)
	if err != nil {
		return nil, err
	}

	return compatibility.BackwardsCompatible, nil
}

// GetForwardsCompatibleVersions returns versions that are forwards compatible with the given version
func (m *DefaultCompatibilityMatrix) GetForwardsCompatibleVersions(moduleName, version string) ([]string, error) {
	compatibility, err := m.GetCompatibility(moduleName, version)
	if err != nil {
		return nil, err
	}

	return compatibility.ForwardsCompatible, nil
}

// IsCompatible checks if two specific module versions are compatible
func (m *DefaultCompatibilityMatrix) IsCompatible(moduleA, versionA, moduleB, versionB string) (bool, error) {
	if moduleA == moduleB {
		// Same module - compatible if versions are the same or one is in the other's compatibility list
		if versionA == versionB {
			return true, nil
		}

		backwardsCompatible, err := m.GetBackwardsCompatibleVersions(moduleA, versionA)
		if err == nil {
			for _, compatVersion := range backwardsCompatible {
				if compatVersion == versionB {
					return true, nil
				}
			}
		}

		forwardsCompatible, err := m.GetForwardsCompatibleVersions(moduleA, versionA)
		if err == nil {
			for _, compatVersion := range forwardsCompatible {
				if compatVersion == versionB {
					return true, nil
				}
			}
		}

		return false, nil
	}

	// Different modules - check cross-module compatibility
	pairResult := m.analyzePairCompatibility(moduleA, versionA, moduleB, versionB)

	switch pairResult.CompatibilityLevel {
	case CompatibilityLevelFullyCompatible,
		CompatibilityLevelBackwardsCompatible,
		CompatibilityLevelForwardsCompatible,
		CompatibilityLevelPartiallyCompatible:
		return true, nil
	case CompatibilityLevelIncompatible:
		return false, nil
	default:
		// Unknown compatibility - assume compatible with warning
		return true, nil
	}
}

// GetMatrixStatus returns the current status of the compatibility matrix
func (m *DefaultCompatibilityMatrix) GetMatrixStatus() *CompatibilityMatrixStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	totalModules := len(m.compatibility)
	totalVersions := 0
	coveredPairs := 0
	verifiedPairs := 0
	knownIncompatibilities := 0

	// Count versions
	for _, moduleVersions := range m.compatibility {
		totalVersions += len(moduleVersions)
	}

	// Count cross-module rules
	for _, moduleRules := range m.crossModuleRules {
		for _, rule := range moduleRules {
			coveredPairs += len(rule.CompatiblePairs)
			for _, pair := range rule.CompatiblePairs {
				if pair.Verified {
					verifiedPairs++
				}
			}
			knownIncompatibilities += len(rule.Conflicts)
		}
	}

	// Calculate matrix completeness
	var completeness float64
	if totalModules > 1 {
		possiblePairs := (totalModules * (totalModules - 1)) / 2
		completeness = float64(coveredPairs) / float64(possiblePairs) * 100
	} else {
		completeness = 100.0
	}

	return &CompatibilityMatrixStatus{
		TotalModules:           totalModules,
		TotalVersions:          totalVersions,
		CoveredPairs:           coveredPairs,
		VerifiedPairs:          verifiedPairs,
		KnownIncompatibilities: knownIncompatibilities,
		LastUpdated:            time.Now(),
		MatrixCompleteness:     completeness,
	}
}

// Helper method to clone compatibility info
func (m *DefaultCompatibilityMatrix) cloneCompatibilityInfo(info *VersionCompatibilityInfo) *VersionCompatibilityInfo {
	clone := &VersionCompatibilityInfo{
		BackwardsCompatible: make([]string, len(info.BackwardsCompatible)),
		ForwardsCompatible:  make([]string, len(info.ForwardsCompatible)),
		BreakingChanges:     make([]BreakingChange, len(info.BreakingChanges)),
		APIChanges:          make([]APIChange, len(info.APIChanges)),
		MigrationRequired:   info.MigrationRequired,
		MigrationComplexity: info.MigrationComplexity,
	}

	copy(clone.BackwardsCompatible, info.BackwardsCompatible)
	copy(clone.ForwardsCompatible, info.ForwardsCompatible)
	copy(clone.BreakingChanges, info.BreakingChanges)
	copy(clone.APIChanges, info.APIChanges)

	return clone
}
