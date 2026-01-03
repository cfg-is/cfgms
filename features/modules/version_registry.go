// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package modules

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// ModuleVersionRegistry manages multiple versions of modules and their lifecycle
type ModuleVersionRegistry interface {
	// Version Registration
	RegisterVersion(metadata *ModuleMetadata) error
	UnregisterVersion(moduleName, version string) error

	// Version Discovery
	GetAvailableVersions(moduleName string) ([]string, error)
	GetLatestVersion(moduleName string) (*SemanticVersion, error)
	GetCompatibleVersions(moduleName, constraint string) ([]string, error)
	IsVersionInstalled(moduleName, version string) bool

	// Version Resolution
	ResolveVersionConstraints(requirements []ModuleVersionRequirement) (*VersionResolution, error)

	// Version History
	GetVersionHistory(moduleName string) (*ModuleVersionHistory, error)
	RecordVersionTransition(moduleName, fromVersion, toVersion string, transitionType VersionTransitionType, metadata map[string]interface{}) error

	// Registry Status
	GetRegistryStatus() *VersionRegistryStatus
	ListAllVersions() map[string][]string
}

// DefaultModuleVersionRegistry implements the ModuleVersionRegistry interface
type DefaultModuleVersionRegistry struct {
	mu sync.RWMutex

	// versions maps module names to their available versions
	// Format: versions["module_name"]["1.2.3"] = *ModuleVersionInfo
	versions map[string]map[string]*ModuleVersionInfo

	// history tracks version transitions for each module
	history map[string]*ModuleVersionHistory

	// activeVersions tracks which version is currently active for each module
	activeVersions map[string]string
}

// ModuleVersionInfo contains comprehensive information about a specific module version
type ModuleVersionInfo struct {
	Metadata        *ModuleMetadata            `json:"metadata"`
	SemanticVersion *SemanticVersion           `json:"semantic_version"`
	InstallTime     time.Time                  `json:"install_time"`
	Status          ModuleVersionStatus        `json:"status"`
	Compatibility   *VersionCompatibilityInfo  `json:"compatibility,omitempty"`
	Dependencies    []ModuleVersionRequirement `json:"dependencies"`
	Dependents      []string                   `json:"dependents"` // Modules that depend on this version
}

// ModuleVersionStatus represents the current status of a module version
type ModuleVersionStatus int

const (
	VersionStatusInstalled ModuleVersionStatus = iota
	VersionStatusActive
	VersionStatusDeprecated
	VersionStatusMigrating
	VersionStatusFailed
)

func (s ModuleVersionStatus) String() string {
	switch s {
	case VersionStatusInstalled:
		return "installed"
	case VersionStatusActive:
		return "active"
	case VersionStatusDeprecated:
		return "deprecated"
	case VersionStatusMigrating:
		return "migrating"
	case VersionStatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// VersionCompatibilityInfo tracks compatibility between module versions
type VersionCompatibilityInfo struct {
	BackwardsCompatible []string                   `json:"backwards_compatible"`
	ForwardsCompatible  []string                   `json:"forwards_compatible"`
	BreakingChanges     []BreakingChange           `json:"breaking_changes"`
	APIChanges          []APIChange                `json:"api_changes"`
	MigrationRequired   bool                       `json:"migration_required"`
	MigrationComplexity VersionMigrationComplexity `json:"migration_complexity"`
}

// ModuleVersionRequirement represents a requirement for a specific module version
type ModuleVersionRequirement struct {
	ModuleName string `json:"module_name"`
	Constraint string `json:"constraint"`
	Optional   bool   `json:"optional"`
	Reason     string `json:"reason,omitempty"`
}

// VersionResolution contains the result of version constraint resolution
type VersionResolution struct {
	Resolved       map[string]string `json:"resolved"` // module_name -> selected_version
	Conflicts      []VersionConflict `json:"conflicts"`
	Warnings       []string          `json:"warnings"`
	ResolutionPath []ResolutionStep  `json:"resolution_path"`
	TotalModules   int               `json:"total_modules"`
	ResolutionTime time.Duration     `json:"resolution_time"`
}

// VersionConflict represents a conflict during version resolution
type VersionConflict struct {
	ModuleName     string   `json:"module_name"`
	Constraints    []string `json:"constraints"`
	RequestedBy    []string `json:"requested_by"`
	ConflictReason string   `json:"conflict_reason"`
	Suggestions    []string `json:"suggestions"`
}

// ResolutionStep tracks the steps taken during version resolution
type ResolutionStep struct {
	Step       int    `json:"step"`
	ModuleName string `json:"module_name"`
	Constraint string `json:"constraint"`
	Selected   string `json:"selected"`
	Reason     string `json:"reason"`
}

// ModuleVersionHistory tracks the version transition history for a module
type ModuleVersionHistory struct {
	ModuleName     string              `json:"module_name"`
	Transitions    []VersionTransition `json:"transitions"`
	CurrentVersion string              `json:"current_version"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
}

// VersionTransition records a single version transition
type VersionTransition struct {
	ID             string                 `json:"id"`
	FromVersion    string                 `json:"from_version"`
	ToVersion      string                 `json:"to_version"`
	TransitionType VersionTransitionType  `json:"transition_type"`
	Timestamp      time.Time              `json:"timestamp"`
	Status         TransitionStatus       `json:"status"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	Duration       time.Duration          `json:"duration,omitempty"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
}

// VersionTransitionType defines types of version transitions
type VersionTransitionType int

const (
	TransitionInstall VersionTransitionType = iota
	TransitionUpgrade
	TransitionDowngrade
	TransitionMigrate
	TransitionRollback
	TransitionUninstall
)

func (t VersionTransitionType) String() string {
	switch t {
	case TransitionInstall:
		return "install"
	case TransitionUpgrade:
		return "upgrade"
	case TransitionDowngrade:
		return "downgrade"
	case TransitionMigrate:
		return "migrate"
	case TransitionRollback:
		return "rollback"
	case TransitionUninstall:
		return "uninstall"
	default:
		return "unknown"
	}
}

// TransitionStatus represents the status of a version transition
type TransitionStatus int

const (
	TransitionPending TransitionStatus = iota
	TransitionInProgress
	TransitionCompleted
	TransitionFailed
	TransitionRolledBack
)

func (s TransitionStatus) String() string {
	switch s {
	case TransitionPending:
		return "pending"
	case TransitionInProgress:
		return "in_progress"
	case TransitionCompleted:
		return "completed"
	case TransitionFailed:
		return "failed"
	case TransitionRolledBack:
		return "rolled_back"
	default:
		return "unknown"
	}
}

// VersionRegistryStatus provides an overview of the version registry
type VersionRegistryStatus struct {
	TotalModules        int               `json:"total_modules"`
	TotalVersions       int               `json:"total_versions"`
	ActiveVersions      map[string]string `json:"active_versions"`
	DeprecatedVersions  []string          `json:"deprecated_versions"`
	PendingMigrations   []string          `json:"pending_migrations"`
	ConflictingModules  []string          `json:"conflicting_modules"`
	RegistryHealthScore float64           `json:"registry_health_score"`
	LastUpdate          time.Time         `json:"last_update"`
}

// NewDefaultModuleVersionRegistry creates a new version registry
func NewDefaultModuleVersionRegistry() *DefaultModuleVersionRegistry {
	return &DefaultModuleVersionRegistry{
		versions:       make(map[string]map[string]*ModuleVersionInfo),
		history:        make(map[string]*ModuleVersionHistory),
		activeVersions: make(map[string]string),
	}
}

// RegisterVersion registers a new version of a module
func (r *DefaultModuleVersionRegistry) RegisterVersion(metadata *ModuleMetadata) error {
	if metadata == nil {
		return fmt.Errorf("module metadata cannot be nil")
	}

	if err := metadata.Validate(); err != nil {
		return fmt.Errorf("invalid module metadata: %v", err)
	}

	semanticVersion, err := ParseVersion(metadata.Version)
	if err != nil {
		return fmt.Errorf("invalid version format: %v", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Initialize module versions map if it doesn't exist
	if r.versions[metadata.Name] == nil {
		r.versions[metadata.Name] = make(map[string]*ModuleVersionInfo)
	}

	// Check if version already exists
	if _, exists := r.versions[metadata.Name][metadata.Version]; exists {
		return fmt.Errorf("version %s of module %s is already registered", metadata.Version, metadata.Name)
	}

	// Create dependencies list
	dependencies := make([]ModuleVersionRequirement, len(metadata.ModuleDependencies))
	for i, dep := range metadata.ModuleDependencies {
		dependencies[i] = ModuleVersionRequirement{
			ModuleName: dep.Name,
			Constraint: dep.Version,
			Optional:   dep.Optional,
		}
	}

	// Create version info
	versionInfo := &ModuleVersionInfo{
		Metadata:        metadata,
		SemanticVersion: semanticVersion,
		InstallTime:     time.Now(),
		Status:          VersionStatusInstalled,
		Dependencies:    dependencies,
		Dependents:      make([]string, 0),
	}

	// Register the version
	r.versions[metadata.Name][metadata.Version] = versionInfo

	// Initialize history if it doesn't exist
	if r.history[metadata.Name] == nil {
		r.history[metadata.Name] = &ModuleVersionHistory{
			ModuleName:     metadata.Name,
			Transitions:    make([]VersionTransition, 0),
			CurrentVersion: metadata.Version,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
	}

	// Record the installation
	err = r.recordVersionTransitionInternal(metadata.Name, "", metadata.Version, TransitionInstall, nil)
	if err != nil {
		// Rollback registration
		delete(r.versions[metadata.Name], metadata.Version)
		return fmt.Errorf("failed to record version transition: %v", err)
	}

	// Set as active version if it's the first version or highest version
	if r.activeVersions[metadata.Name] == "" {
		r.activeVersions[metadata.Name] = metadata.Version
		versionInfo.Status = VersionStatusActive
	} else {
		// Check if this is a higher version
		currentActiveVersion, err := ParseVersion(r.activeVersions[metadata.Name])
		if err == nil && semanticVersion.Compare(currentActiveVersion) > 0 {
			// Mark previous version as installed, new version as active
			if oldVersionInfo, exists := r.versions[metadata.Name][r.activeVersions[metadata.Name]]; exists {
				oldVersionInfo.Status = VersionStatusInstalled
			}
			r.activeVersions[metadata.Name] = metadata.Version
			versionInfo.Status = VersionStatusActive
		}
	}

	return nil
}

// UnregisterVersion removes a specific version of a module
func (r *DefaultModuleVersionRegistry) UnregisterVersion(moduleName, version string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.versions[moduleName] == nil {
		return fmt.Errorf("module %s is not registered", moduleName)
	}

	versionInfo, exists := r.versions[moduleName][version]
	if !exists {
		return fmt.Errorf("version %s of module %s is not registered", version, moduleName)
	}

	// Check if any modules depend on this version
	if len(versionInfo.Dependents) > 0 {
		return fmt.Errorf("cannot unregister version %s of module %s: it is required by %v",
			version, moduleName, versionInfo.Dependents)
	}

	// Remove the version
	delete(r.versions[moduleName], version)

	// If this was the active version, find a new active version
	if r.activeVersions[moduleName] == version {
		r.activeVersions[moduleName] = r.findBestActiveVersion(moduleName)
		if r.activeVersions[moduleName] != "" {
			r.versions[moduleName][r.activeVersions[moduleName]].Status = VersionStatusActive
		}
	}

	// Record the uninstall
	return r.recordVersionTransitionInternal(moduleName, version, "", TransitionUninstall, nil)
}

// GetAvailableVersions returns all available versions of a module
func (r *DefaultModuleVersionRegistry) GetAvailableVersions(moduleName string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	moduleVersions := r.versions[moduleName]
	if moduleVersions == nil {
		return nil, fmt.Errorf("module %s is not registered", moduleName)
	}

	versions := make([]string, 0, len(moduleVersions))
	for version := range moduleVersions {
		versions = append(versions, version)
	}

	// Sort versions semantically
	sort.Slice(versions, func(i, j int) bool {
		v1, err1 := ParseVersion(versions[i])
		v2, err2 := ParseVersion(versions[j])
		if err1 != nil || err2 != nil {
			// Fallback to string comparison if parsing fails
			return versions[i] < versions[j]
		}
		return v1.Compare(v2) < 0
	})

	return versions, nil
}

// GetLatestVersion returns the latest (highest) version of a module
func (r *DefaultModuleVersionRegistry) GetLatestVersion(moduleName string) (*SemanticVersion, error) {
	versions, err := r.GetAvailableVersions(moduleName)
	if err != nil {
		return nil, err
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions available for module %s", moduleName)
	}

	// Return the last version (highest) from the sorted list
	return ParseVersion(versions[len(versions)-1])
}

// GetCompatibleVersions returns versions that satisfy the given constraint
func (r *DefaultModuleVersionRegistry) GetCompatibleVersions(moduleName, constraint string) ([]string, error) {
	availableVersions, err := r.GetAvailableVersions(moduleName)
	if err != nil {
		return nil, err
	}

	var compatibleVersions []string
	for _, version := range availableVersions {
		compatible, err := IsVersionCompatible(version, constraint)
		if err != nil {
			continue // Skip versions that can't be checked
		}
		if compatible {
			compatibleVersions = append(compatibleVersions, version)
		}
	}

	return compatibleVersions, nil
}

// IsVersionInstalled checks if a specific version of a module is installed
func (r *DefaultModuleVersionRegistry) IsVersionInstalled(moduleName, version string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.versions[moduleName] == nil {
		return false
	}

	_, exists := r.versions[moduleName][version]
	return exists
}

// findBestActiveVersion finds the best version to set as active for a module
func (r *DefaultModuleVersionRegistry) findBestActiveVersion(moduleName string) string {
	moduleVersions := r.versions[moduleName]
	if len(moduleVersions) == 0 {
		return ""
	}

	var bestVersion string
	var bestSemanticVersion *SemanticVersion

	for version := range moduleVersions {
		semanticVersion, err := ParseVersion(version)
		if err != nil {
			continue
		}

		if bestSemanticVersion == nil || semanticVersion.Compare(bestSemanticVersion) > 0 {
			bestVersion = version
			bestSemanticVersion = semanticVersion
		}
	}

	return bestVersion
}

// recordVersionTransitionInternal records a version transition (internal method, assumes lock is held)
func (r *DefaultModuleVersionRegistry) recordVersionTransitionInternal(moduleName, fromVersion, toVersion string, transitionType VersionTransitionType, metadata map[string]interface{}) error {
	history := r.history[moduleName]
	if history == nil {
		return fmt.Errorf("no history found for module %s", moduleName)
	}

	transition := VersionTransition{
		ID:             fmt.Sprintf("%s-%d", moduleName, time.Now().UnixNano()),
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		TransitionType: transitionType,
		Timestamp:      time.Now(),
		Status:         TransitionCompleted,
		Metadata:       metadata,
	}

	history.Transitions = append(history.Transitions, transition)
	history.UpdatedAt = time.Now()

	if toVersion != "" {
		history.CurrentVersion = toVersion
	}

	return nil
}

// RecordVersionTransition records a version transition
func (r *DefaultModuleVersionRegistry) RecordVersionTransition(moduleName, fromVersion, toVersion string, transitionType VersionTransitionType, metadata map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.recordVersionTransitionInternal(moduleName, fromVersion, toVersion, transitionType, metadata)
}

// GetVersionHistory returns the version history for a module
func (r *DefaultModuleVersionRegistry) GetVersionHistory(moduleName string) (*ModuleVersionHistory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	history := r.history[moduleName]
	if history == nil {
		return nil, fmt.Errorf("no history found for module %s", moduleName)
	}

	// Return a copy to prevent external modification
	historyCopy := &ModuleVersionHistory{
		ModuleName:     history.ModuleName,
		CurrentVersion: history.CurrentVersion,
		CreatedAt:      history.CreatedAt,
		UpdatedAt:      history.UpdatedAt,
		Transitions:    make([]VersionTransition, len(history.Transitions)),
	}

	copy(historyCopy.Transitions, history.Transitions)

	return historyCopy, nil
}

// GetRegistryStatus returns the current status of the version registry
func (r *DefaultModuleVersionRegistry) GetRegistryStatus() *VersionRegistryStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	totalVersions := 0
	var deprecatedVersions []string

	for moduleName, moduleVersions := range r.versions {
		totalVersions += len(moduleVersions)
		for version, versionInfo := range moduleVersions {
			if versionInfo.Status == VersionStatusDeprecated {
				deprecatedVersions = append(deprecatedVersions, fmt.Sprintf("%s:%s", moduleName, version))
			}
		}
	}

	return &VersionRegistryStatus{
		TotalModules:        len(r.versions),
		TotalVersions:       totalVersions,
		ActiveVersions:      r.copyActiveVersions(),
		DeprecatedVersions:  deprecatedVersions,
		PendingMigrations:   make([]string, 0), // TODO: implement migration tracking
		ConflictingModules:  make([]string, 0), // TODO: implement conflict detection
		RegistryHealthScore: r.calculateHealthScore(),
		LastUpdate:          time.Now(),
	}
}

// ListAllVersions returns a map of all modules and their versions
func (r *DefaultModuleVersionRegistry) ListAllVersions() map[string][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string][]string)
	for moduleName := range r.versions {
		versions, _ := r.GetAvailableVersions(moduleName)
		result[moduleName] = versions
	}

	return result
}

// ResolveVersionConstraints resolves version constraints for multiple modules
func (r *DefaultModuleVersionRegistry) ResolveVersionConstraints(requirements []ModuleVersionRequirement) (*VersionResolution, error) {
	startTime := time.Now()

	resolution := &VersionResolution{
		Resolved:       make(map[string]string),
		Conflicts:      make([]VersionConflict, 0),
		Warnings:       make([]string, 0),
		ResolutionPath: make([]ResolutionStep, 0),
		TotalModules:   len(requirements),
	}

	// Simple resolution algorithm - can be enhanced with more sophisticated constraint solving
	for i, req := range requirements {
		compatibleVersions, err := r.GetCompatibleVersions(req.ModuleName, req.Constraint)
		if err != nil {
			if !req.Optional {
				resolution.Conflicts = append(resolution.Conflicts, VersionConflict{
					ModuleName:     req.ModuleName,
					Constraints:    []string{req.Constraint},
					ConflictReason: err.Error(),
				})
			}
			continue
		}

		if len(compatibleVersions) == 0 {
			if !req.Optional {
				resolution.Conflicts = append(resolution.Conflicts, VersionConflict{
					ModuleName:     req.ModuleName,
					Constraints:    []string{req.Constraint},
					ConflictReason: "no compatible versions found",
				})
			}
			continue
		}

		// Select the latest compatible version
		selectedVersion := compatibleVersions[len(compatibleVersions)-1]
		resolution.Resolved[req.ModuleName] = selectedVersion

		step := ResolutionStep{
			Step:       i + 1,
			ModuleName: req.ModuleName,
			Constraint: req.Constraint,
			Selected:   selectedVersion,
			Reason:     "latest compatible version",
		}
		resolution.ResolutionPath = append(resolution.ResolutionPath, step)
	}

	resolution.ResolutionTime = time.Since(startTime)
	return resolution, nil
}

// Helper methods

func (r *DefaultModuleVersionRegistry) copyActiveVersions() map[string]string {
	result := make(map[string]string)
	for k, v := range r.activeVersions {
		result[k] = v
	}
	return result
}

func (r *DefaultModuleVersionRegistry) calculateHealthScore() float64 {
	if len(r.versions) == 0 {
		return 100.0
	}

	totalVersions := 0
	deprecatedVersions := 0
	failedVersions := 0

	for _, moduleVersions := range r.versions {
		for _, versionInfo := range moduleVersions {
			totalVersions++
			if versionInfo.Status == VersionStatusDeprecated {
				deprecatedVersions++
			}
			if versionInfo.Status == VersionStatusFailed {
				failedVersions++
			}
		}
	}

	healthScore := 100.0
	if totalVersions > 0 {
		// Reduce score based on deprecated and failed versions
		deprecatedRatio := float64(deprecatedVersions) / float64(totalVersions)
		failedRatio := float64(failedVersions) / float64(totalVersions)

		healthScore -= (deprecatedRatio * 20) // Deprecated versions reduce score by up to 20%
		healthScore -= (failedRatio * 30)     // Failed versions reduce score by up to 30%
	}

	if healthScore < 0 {
		healthScore = 0
	}

	return healthScore
}
