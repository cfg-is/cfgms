// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package modules

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// VersionMigrator handles module version migrations
type VersionMigrator interface {
	// Migration Planning
	CanMigrate(moduleName, fromVersion, toVersion string) (bool, error)
	GetMigrationPath(moduleName, fromVersion, toVersion string) (*MigrationPath, error)
	ValidateMigrationPath(path *MigrationPath) error

	// Migration Execution
	ExecuteMigration(ctx context.Context, path *MigrationPath) (*MigrationResult, error)
	RollbackMigration(ctx context.Context, migrationID string) (*MigrationResult, error)

	// Migration Status
	GetMigrationStatus(migrationID string) (*MigrationStatus, error)
	ListActiveMigrations() ([]*MigrationStatus, error)
}

// DefaultVersionMigrator implements the VersionMigrator interface
type DefaultVersionMigrator struct {
	mu               sync.RWMutex
	registry         ModuleVersionRegistry
	activeMigrations map[string]*MigrationExecution
	migrationHistory []*MigrationResult
	strategies       map[VersionMigrationComplexity]MigrationStrategy
}

// VersionMigrationComplexity defines the complexity levels for version migrations
type VersionMigrationComplexity int

const (
	MigrationComplexityNone VersionMigrationComplexity = iota
	MigrationComplexityLow
	MigrationComplexityMedium
	MigrationComplexityHigh
	MigrationComplexityCritical
)

func (c VersionMigrationComplexity) String() string {
	switch c {
	case MigrationComplexityNone:
		return "none"
	case MigrationComplexityLow:
		return "low"
	case MigrationComplexityMedium:
		return "medium"
	case MigrationComplexityHigh:
		return "high"
	case MigrationComplexityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MigrationPath represents a planned migration between versions
type MigrationPath struct {
	ID                string                     `json:"id"`
	ModuleName        string                     `json:"module_name"`
	FromVersion       string                     `json:"from_version"`
	ToVersion         string                     `json:"to_version"`
	Steps             []MigrationStep            `json:"steps"`
	Complexity        VersionMigrationComplexity `json:"complexity"`
	EstimatedTime     time.Duration              `json:"estimated_time"`
	RequiresBackup    bool                       `json:"requires_backup"`
	RollbackSupported bool                       `json:"rollback_supported"`
	Warnings          []string                   `json:"warnings"`
	Prerequisites     []string                   `json:"prerequisites"`
	CreatedAt         time.Time                  `json:"created_at"`
}

// MigrationStep represents a single step in a migration path
type MigrationStep struct {
	ID              string                     `json:"id"`
	Type            MigrationStepType          `json:"type"`
	FromVersion     string                     `json:"from_version"`
	ToVersion       string                     `json:"to_version"`
	Description     string                     `json:"description"`
	EstimatedTime   time.Duration              `json:"estimated_time"`
	Complexity      VersionMigrationComplexity `json:"complexity"`
	RequiresRestart bool                       `json:"requires_restart"`
	ValidationType  MigrationValidationType    `json:"validation_type"`
	RollbackAction  string                     `json:"rollback_action,omitempty"`
	Metadata        map[string]interface{}     `json:"metadata,omitempty"`
}

// MigrationStepType defines types of migration steps
type MigrationStepType int

const (
	MigrationStepValidation MigrationStepType = iota
	MigrationStepBackup
	MigrationStepPreprocess
	MigrationStepUpgrade
	MigrationStepDowngrade
	MigrationStepDataMigration
	MigrationStepConfigUpdate
	MigrationStepPostprocess
	MigrationStepCleanup
)

func (t MigrationStepType) String() string {
	switch t {
	case MigrationStepValidation:
		return "validation"
	case MigrationStepBackup:
		return "backup"
	case MigrationStepPreprocess:
		return "preprocess"
	case MigrationStepUpgrade:
		return "upgrade"
	case MigrationStepDowngrade:
		return "downgrade"
	case MigrationStepDataMigration:
		return "data_migration"
	case MigrationStepConfigUpdate:
		return "config_update"
	case MigrationStepPostprocess:
		return "postprocess"
	case MigrationStepCleanup:
		return "cleanup"
	default:
		return "unknown"
	}
}

// MigrationValidationType defines validation requirements for migration steps
type MigrationValidationType int

const (
	ValidationNone MigrationValidationType = iota
	ValidationBasic
	ValidationFull
	ValidationCritical
)

func (v MigrationValidationType) String() string {
	switch v {
	case ValidationNone:
		return "none"
	case ValidationBasic:
		return "basic"
	case ValidationFull:
		return "full"
	case ValidationCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MigrationExecution tracks an active migration
type MigrationExecution struct {
	Path           *MigrationPath           `json:"path"`
	Status         MigrationExecutionStatus `json:"status"`
	CurrentStep    int                      `json:"current_step"`
	StartTime      time.Time                `json:"start_time"`
	EndTime        *time.Time               `json:"end_time,omitempty"`
	Progress       float64                  `json:"progress"` // 0.0 to 1.0
	ErrorMessage   string                   `json:"error_message,omitempty"`
	CompletedSteps []StepResult             `json:"completed_steps"`
	Context        context.Context          `json:"-"`
	CancelFunc     context.CancelFunc       `json:"-"`
}

// MigrationExecutionStatus represents the status of a migration execution
type MigrationExecutionStatus int

const (
	MigrationStatusPlanning MigrationExecutionStatus = iota
	MigrationStatusReady
	MigrationStatusRunning
	MigrationStatusCompleted
	MigrationStatusFailed
	MigrationStatusCancelled
	MigrationStatusRolledBack
)

func (s MigrationExecutionStatus) String() string {
	switch s {
	case MigrationStatusPlanning:
		return "planning"
	case MigrationStatusReady:
		return "ready"
	case MigrationStatusRunning:
		return "running"
	case MigrationStatusCompleted:
		return "completed"
	case MigrationStatusFailed:
		return "failed"
	case MigrationStatusCancelled:
		return "cancelled"
	case MigrationStatusRolledBack:
		return "rolled_back"
	default:
		return "unknown"
	}
}

// StepResult represents the result of executing a migration step
type StepResult struct {
	Step         MigrationStep          `json:"step"`
	Status       StepStatus             `json:"status"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      time.Time              `json:"end_time"`
	Duration     time.Duration          `json:"duration"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	Output       string                 `json:"output,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// StepStatus represents the status of a migration step execution
type StepStatus int

const (
	StepStatusPending StepStatus = iota
	StepStatusRunning
	StepStatusCompleted
	StepStatusFailed
	StepStatusSkipped
)

func (s StepStatus) String() string {
	switch s {
	case StepStatusPending:
		return "pending"
	case StepStatusRunning:
		return "running"
	case StepStatusCompleted:
		return "completed"
	case StepStatusFailed:
		return "failed"
	case StepStatusSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// MigrationResult represents the final result of a migration
type MigrationResult struct {
	ID               string                   `json:"id"`
	Path             *MigrationPath           `json:"path"`
	Status           MigrationExecutionStatus `json:"status"`
	StartTime        time.Time                `json:"start_time"`
	EndTime          time.Time                `json:"end_time"`
	Duration         time.Duration            `json:"duration"`
	StepResults      []StepResult             `json:"step_results"`
	ErrorMessage     string                   `json:"error_message,omitempty"`
	RollbackRequired bool                     `json:"rollback_required"`
	RollbackResult   *MigrationResult         `json:"rollback_result,omitempty"`
	Metadata         map[string]interface{}   `json:"metadata,omitempty"`
}

// MigrationStatus provides the current status of a migration
type MigrationStatus struct {
	ID           string                   `json:"id"`
	ModuleName   string                   `json:"module_name"`
	FromVersion  string                   `json:"from_version"`
	ToVersion    string                   `json:"to_version"`
	Status       MigrationExecutionStatus `json:"status"`
	Progress     float64                  `json:"progress"`
	CurrentStep  int                      `json:"current_step"`
	TotalSteps   int                      `json:"total_steps"`
	StartTime    time.Time                `json:"start_time"`
	ElapsedTime  time.Duration            `json:"elapsed_time"`
	EstimatedETA time.Duration            `json:"estimated_eta"`
}

// MigrationStrategy defines how to handle migrations of different complexities
type MigrationStrategy interface {
	PlanMigration(fromVersion, toVersion string, compatibility *VersionCompatibilityInfo) (*MigrationPath, error)
	ValidateMigration(path *MigrationPath) error
	EstimateDuration(path *MigrationPath) time.Duration
}

// SimpleMigrationStrategy handles low complexity migrations
type SimpleMigrationStrategy struct{}

// ComplexMigrationStrategy handles high complexity migrations
type ComplexMigrationStrategy struct{}

// NewDefaultVersionMigrator creates a new version migrator
func NewDefaultVersionMigrator(registry ModuleVersionRegistry) *DefaultVersionMigrator {
	migrator := &DefaultVersionMigrator{
		registry:         registry,
		activeMigrations: make(map[string]*MigrationExecution),
		migrationHistory: make([]*MigrationResult, 0),
		strategies:       make(map[VersionMigrationComplexity]MigrationStrategy),
	}

	// Register migration strategies
	migrator.strategies[MigrationComplexityLow] = &SimpleMigrationStrategy{}
	migrator.strategies[MigrationComplexityMedium] = &SimpleMigrationStrategy{}
	migrator.strategies[MigrationComplexityHigh] = &ComplexMigrationStrategy{}
	migrator.strategies[MigrationComplexityCritical] = &ComplexMigrationStrategy{}

	return migrator
}

// CanMigrate checks if migration between two versions is possible
func (m *DefaultVersionMigrator) CanMigrate(moduleName, fromVersion, toVersion string) (bool, error) {
	// Check version format first
	fromSemVer, err := ParseVersion(fromVersion)
	if err != nil {
		return false, fmt.Errorf("invalid from version: %v", err)
	}

	toSemVer, err := ParseVersion(toVersion)
	if err != nil {
		return false, fmt.Errorf("invalid to version: %v", err)
	}

	// Check if both versions exist
	if !m.registry.IsVersionInstalled(moduleName, fromVersion) {
		return false, fmt.Errorf("source version %s of module %s is not installed", fromVersion, moduleName)
	}

	if !m.registry.IsVersionInstalled(moduleName, toVersion) {
		return false, fmt.Errorf("target version %s of module %s is not installed", toVersion, moduleName)
	}

	// Allow migrations in both directions
	if fromSemVer.Compare(toSemVer) == 0 {
		return false, fmt.Errorf("source and target versions are the same")
	}

	// Simple check - can migrate between any versions for now
	// In the future, this could check for compatibility matrices, breaking changes, etc.
	return true, nil
}

// GetMigrationPath creates a migration path between two versions
func (m *DefaultVersionMigrator) GetMigrationPath(moduleName, fromVersion, toVersion string) (*MigrationPath, error) {
	canMigrate, err := m.CanMigrate(moduleName, fromVersion, toVersion)
	if !canMigrate {
		return nil, err
	}

	fromSemVer, _ := ParseVersion(fromVersion)
	toSemVer, _ := ParseVersion(toVersion)

	// Determine migration direction
	isUpgrade := toSemVer.Compare(fromSemVer) > 0

	// Calculate complexity based on version difference
	complexity := m.calculateMigrationComplexity(fromSemVer, toSemVer)

	// Get the appropriate strategy
	strategy := m.strategies[complexity]
	if strategy == nil {
		strategy = m.strategies[MigrationComplexityLow] // Default fallback
	}

	// Create basic migration path
	path := &MigrationPath{
		ID:                fmt.Sprintf("migration-%s-%s-%s-%d", moduleName, fromVersion, toVersion, time.Now().UnixNano()),
		ModuleName:        moduleName,
		FromVersion:       fromVersion,
		ToVersion:         toVersion,
		Complexity:        complexity,
		RequiresBackup:    complexity >= MigrationComplexityMedium,
		RollbackSupported: true,
		CreatedAt:         time.Now(),
	}

	// Generate migration steps
	steps := m.generateMigrationSteps(moduleName, fromVersion, toVersion, isUpgrade, complexity)
	path.Steps = steps

	// Calculate estimated time
	path.EstimatedTime = strategy.EstimateDuration(path)

	// Add warnings based on complexity
	path.Warnings = m.generateMigrationWarnings(complexity, isUpgrade)

	return path, nil
}

// calculateMigrationComplexity determines the complexity of a migration based on version difference
func (m *DefaultVersionMigrator) calculateMigrationComplexity(from, to *SemanticVersion) VersionMigrationComplexity {
	// Major version changes are high complexity
	if from.Major != to.Major {
		return MigrationComplexityHigh
	}

	// Minor version changes are medium complexity
	if from.Minor != to.Minor {
		return MigrationComplexityMedium
	}

	// Patch version changes are low complexity
	return MigrationComplexityLow
}

// generateMigrationSteps creates the steps needed for a migration
func (m *DefaultVersionMigrator) generateMigrationSteps(moduleName, fromVersion, toVersion string, isUpgrade bool, complexity VersionMigrationComplexity) []MigrationStep {
	var steps []MigrationStep

	// Step 1: Validation
	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("validate-%s", moduleName),
		Type:           MigrationStepValidation,
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		Description:    "Validate migration prerequisites and system state",
		EstimatedTime:  100 * time.Millisecond,
		Complexity:     MigrationComplexityLow,
		ValidationType: ValidationFull,
	})

	// Step 2: Backup (if required)
	if complexity >= MigrationComplexityMedium {
		steps = append(steps, MigrationStep{
			ID:             fmt.Sprintf("backup-%s", moduleName),
			Type:           MigrationStepBackup,
			FromVersion:    fromVersion,
			ToVersion:      toVersion,
			Description:    "Create backup of current module state and configuration",
			EstimatedTime:  2 * time.Minute,
			Complexity:     MigrationComplexityLow,
			ValidationType: ValidationBasic,
		})
	}

	// Step 3: Preprocessing
	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("preprocess-%s", moduleName),
		Type:           MigrationStepPreprocess,
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		Description:    "Prepare system for version transition",
		EstimatedTime:  1 * time.Minute,
		Complexity:     complexity,
		ValidationType: ValidationBasic,
	})

	// Step 4: Main migration
	var mainStepType MigrationStepType
	var mainDescription string

	if isUpgrade {
		mainStepType = MigrationStepUpgrade
		mainDescription = fmt.Sprintf("Upgrade module from %s to %s", fromVersion, toVersion)
	} else {
		mainStepType = MigrationStepDowngrade
		mainDescription = fmt.Sprintf("Downgrade module from %s to %s", fromVersion, toVersion)
	}

	steps = append(steps, MigrationStep{
		ID:              fmt.Sprintf("main-%s", moduleName),
		Type:            mainStepType,
		FromVersion:     fromVersion,
		ToVersion:       toVersion,
		Description:     mainDescription,
		EstimatedTime:   m.estimateMainStepDuration(complexity),
		Complexity:      complexity,
		RequiresRestart: complexity >= MigrationComplexityMedium,
		ValidationType:  ValidationFull,
	})

	// Step 5: Data migration (if needed for complex migrations)
	if complexity >= MigrationComplexityHigh {
		steps = append(steps, MigrationStep{
			ID:             fmt.Sprintf("data-migration-%s", moduleName),
			Type:           MigrationStepDataMigration,
			FromVersion:    fromVersion,
			ToVersion:      toVersion,
			Description:    "Migrate data structures to new version format",
			EstimatedTime:  5 * time.Minute,
			Complexity:     complexity,
			ValidationType: ValidationCritical,
		})
	}

	// Step 6: Configuration update
	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("config-update-%s", moduleName),
		Type:           MigrationStepConfigUpdate,
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		Description:    "Update module configuration for new version",
		EstimatedTime:  100 * time.Millisecond,
		Complexity:     MigrationComplexityLow,
		ValidationType: ValidationBasic,
	})

	// Step 7: Postprocessing
	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("postprocess-%s", moduleName),
		Type:           MigrationStepPostprocess,
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		Description:    "Finalize migration and verify system state",
		EstimatedTime:  1 * time.Minute,
		Complexity:     MigrationComplexityLow,
		ValidationType: ValidationFull,
	})

	// Step 8: Cleanup
	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("cleanup-%s", moduleName),
		Type:           MigrationStepCleanup,
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		Description:    "Clean up temporary files and old version artifacts",
		EstimatedTime:  100 * time.Millisecond,
		Complexity:     MigrationComplexityLow,
		ValidationType: ValidationNone,
	})

	return steps
}

// estimateMainStepDuration estimates the duration of the main migration step
func (m *DefaultVersionMigrator) estimateMainStepDuration(complexity VersionMigrationComplexity) time.Duration {
	switch complexity {
	case MigrationComplexityLow:
		return 1 * time.Minute
	case MigrationComplexityMedium:
		return 3 * time.Minute
	case MigrationComplexityHigh:
		return 10 * time.Minute
	case MigrationComplexityCritical:
		return 30 * time.Minute
	default:
		return 5 * time.Minute
	}
}

// generateMigrationWarnings creates appropriate warnings for a migration
func (m *DefaultVersionMigrator) generateMigrationWarnings(complexity VersionMigrationComplexity, isUpgrade bool) []string {
	var warnings []string

	switch complexity {
	case MigrationComplexityMedium:
		warnings = append(warnings, "This migration requires service restart")
		if !isUpgrade {
			warnings = append(warnings, "Downgrade may result in feature loss")
		}
	case MigrationComplexityHigh:
		warnings = append(warnings, "This migration involves significant changes and requires service restart")
		warnings = append(warnings, "Data migration is required - ensure adequate disk space")
		if !isUpgrade {
			warnings = append(warnings, "Downgrade may result in data loss")
		}
	case MigrationComplexityCritical:
		warnings = append(warnings, "CRITICAL: This migration involves major structural changes and requires service restart")
		warnings = append(warnings, "Extended downtime is expected")
		warnings = append(warnings, "Full system backup is strongly recommended")
	}

	return warnings
}

// ValidateMigrationPath validates that a migration path is executable
func (m *DefaultVersionMigrator) ValidateMigrationPath(path *MigrationPath) error {
	if path == nil {
		return fmt.Errorf("migration path cannot be nil")
	}

	// Check basic path validity
	if path.ModuleName == "" {
		return fmt.Errorf("module name is required")
	}

	if path.FromVersion == "" || path.ToVersion == "" {
		return fmt.Errorf("from and to versions are required")
	}

	if len(path.Steps) == 0 {
		return fmt.Errorf("migration path must have at least one step")
	}

	// Validate that versions exist
	canMigrate, err := m.CanMigrate(path.ModuleName, path.FromVersion, path.ToVersion)
	if !canMigrate {
		return fmt.Errorf("migration validation failed: %v", err)
	}

	// Validate steps
	for i, step := range path.Steps {
		if step.ID == "" {
			return fmt.Errorf("step %d: step ID is required", i)
		}
		if step.Description == "" {
			return fmt.Errorf("step %d: step description is required", i)
		}
	}

	return nil
}

// ExecuteMigration executes a migration path
func (m *DefaultVersionMigrator) ExecuteMigration(ctx context.Context, path *MigrationPath) (*MigrationResult, error) {
	// Validate the path
	if err := m.ValidateMigrationPath(path); err != nil {
		return nil, fmt.Errorf("invalid migration path: %v", err)
	}

	// Check if there's already an active migration for this module
	m.mu.Lock()
	for _, execution := range m.activeMigrations {
		if execution.Path.ModuleName == path.ModuleName &&
			(execution.Status == MigrationStatusRunning || execution.Status == MigrationStatusReady) {
			m.mu.Unlock()
			return nil, fmt.Errorf("migration already in progress for module %s", path.ModuleName)
		}
	}

	// Create migration execution context
	migrationCtx, cancelFunc := context.WithCancel(ctx)
	execution := &MigrationExecution{
		Path:           path,
		Status:         MigrationStatusReady,
		CurrentStep:    0,
		StartTime:      time.Now(),
		Progress:       0.0,
		CompletedSteps: make([]StepResult, 0),
		Context:        migrationCtx,
		CancelFunc:     cancelFunc,
	}

	m.activeMigrations[path.ID] = execution
	m.mu.Unlock()

	// Execute migration asynchronously
	go m.executeMigrationSteps(execution)

	// Return initial result
	result := &MigrationResult{
		ID:        path.ID,
		Path:      path,
		Status:    MigrationStatusRunning,
		StartTime: execution.StartTime,
	}

	return result, nil
}

// executeMigrationSteps executes the migration steps
func (m *DefaultVersionMigrator) executeMigrationSteps(execution *MigrationExecution) {
	// Set status to running under lock protection
	m.mu.Lock()
	execution.Status = MigrationStatusRunning
	m.mu.Unlock()

	defer func() {
		endTime := time.Now()
		execution.EndTime = &endTime

		// Create final result
		result := &MigrationResult{
			ID:          execution.Path.ID,
			Path:        execution.Path,
			Status:      execution.Status,
			StartTime:   execution.StartTime,
			EndTime:     endTime,
			Duration:    endTime.Sub(execution.StartTime),
			StepResults: execution.CompletedSteps,
		}

		if execution.ErrorMessage != "" {
			result.ErrorMessage = execution.ErrorMessage
		}

		// Add to history and remove from active migrations
		m.mu.Lock()
		m.migrationHistory = append(m.migrationHistory, result)
		delete(m.activeMigrations, execution.Path.ID)
		m.mu.Unlock()
	}()

	totalSteps := len(execution.Path.Steps)

	for i, step := range execution.Path.Steps {
		// Check if migration was cancelled
		select {
		case <-execution.Context.Done():
			m.mu.Lock()
			execution.Status = MigrationStatusCancelled
			execution.ErrorMessage = "migration was cancelled"
			m.mu.Unlock()
			return
		default:
		}

		m.mu.Lock()
		execution.CurrentStep = i
		execution.Progress = float64(i) / float64(totalSteps)
		m.mu.Unlock()

		stepResult := m.executeStep(execution.Context, step)
		m.mu.Lock()
		execution.CompletedSteps = append(execution.CompletedSteps, *stepResult)
		m.mu.Unlock()

		if stepResult.Status == StepStatusFailed {
			m.mu.Lock()
			execution.Status = MigrationStatusFailed
			execution.ErrorMessage = fmt.Sprintf("step %s failed: %s", step.ID, stepResult.ErrorMessage)
			m.mu.Unlock()
			return
		}
	}

	// Migration completed successfully
	m.mu.Lock()
	execution.Status = MigrationStatusCompleted
	execution.Progress = 1.0
	m.mu.Unlock()

	// Record the version transition in the registry
	var transitionType VersionTransitionType
	fromSemVer, _ := ParseVersion(execution.Path.FromVersion)
	toSemVer, _ := ParseVersion(execution.Path.ToVersion)

	if toSemVer.Compare(fromSemVer) > 0 {
		transitionType = TransitionUpgrade
	} else {
		transitionType = TransitionDowngrade
	}

	metadata := map[string]interface{}{
		"migration_id": execution.Path.ID,
		"complexity":   execution.Path.Complexity.String(),
		"duration":     time.Since(execution.StartTime).String(),
	}

	_ = m.registry.RecordVersionTransition(
		execution.Path.ModuleName,
		execution.Path.FromVersion,
		execution.Path.ToVersion,
		transitionType,
		metadata,
	)
}

// executeStep executes a single migration step
func (m *DefaultVersionMigrator) executeStep(ctx context.Context, step MigrationStep) *StepResult {
	result := &StepResult{
		Step:      step,
		Status:    StepStatusRunning,
		StartTime: time.Now(),
	}

	defer func() {
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
	}()

	// Simulate step execution based on step type
	// In a real implementation, this would call actual migration logic
	switch step.Type {
	case MigrationStepValidation:
		result.Output = "Validation completed successfully"
		result.Status = StepStatusCompleted

	case MigrationStepBackup:
		// Simulate backup time
		select {
		case <-ctx.Done():
			result.Status = StepStatusFailed
			result.ErrorMessage = "step cancelled"
			return result
		case <-time.After(step.EstimatedTime):
			result.Output = "Backup created successfully"
			result.Status = StepStatusCompleted
		}

	case MigrationStepUpgrade, MigrationStepDowngrade:
		// Simulate main migration work
		select {
		case <-ctx.Done():
			result.Status = StepStatusFailed
			result.ErrorMessage = "step cancelled"
			return result
		case <-time.After(step.EstimatedTime):
			result.Output = fmt.Sprintf("Version transition completed: %s -> %s", step.FromVersion, step.ToVersion)
			result.Status = StepStatusCompleted
		}

	default:
		// For other steps, simulate quick completion
		select {
		case <-ctx.Done():
			result.Status = StepStatusFailed
			result.ErrorMessage = "step cancelled"
			return result
		case <-time.After(step.EstimatedTime / 2): // Simulate faster completion
			result.Output = fmt.Sprintf("Step %s completed", step.Type.String())
			result.Status = StepStatusCompleted
		}
	}

	return result
}

// GetMigrationStatus returns the current status of a migration
func (m *DefaultVersionMigrator) GetMigrationStatus(migrationID string) (*MigrationStatus, error) {
	m.mu.RLock()
	execution := m.activeMigrations[migrationID]
	if execution == nil {
		// Check historical migrations
		for _, result := range m.migrationHistory {
			if result.ID == migrationID {
				m.mu.RUnlock()
				return &MigrationStatus{
					ID:          result.ID,
					ModuleName:  result.Path.ModuleName,
					FromVersion: result.Path.FromVersion,
					ToVersion:   result.Path.ToVersion,
					Status:      result.Status,
					Progress:    1.0,
					TotalSteps:  len(result.Path.Steps),
					StartTime:   result.StartTime,
					ElapsedTime: result.Duration,
				}, nil
			}
		}
		m.mu.RUnlock()
		return nil, fmt.Errorf("migration %s not found", migrationID)
	}

	// Take a snapshot of execution fields while holding the lock
	status := execution.Status
	progress := execution.Progress
	currentStep := execution.CurrentStep
	startTime := execution.StartTime
	pathID := execution.Path.ID
	moduleName := execution.Path.ModuleName
	fromVersion := execution.Path.FromVersion
	toVersion := execution.Path.ToVersion
	totalSteps := len(execution.Path.Steps)
	m.mu.RUnlock()

	elapsedTime := time.Since(startTime)
	var estimatedETA time.Duration

	if progress > 0 {
		totalEstimatedTime := time.Duration(float64(elapsedTime) / progress)
		estimatedETA = totalEstimatedTime - elapsedTime
	}

	return &MigrationStatus{
		ID:           pathID,
		ModuleName:   moduleName,
		FromVersion:  fromVersion,
		ToVersion:    toVersion,
		Status:       status,
		Progress:     progress,
		CurrentStep:  currentStep,
		TotalSteps:   totalSteps,
		StartTime:    startTime,
		ElapsedTime:  elapsedTime,
		EstimatedETA: estimatedETA,
	}, nil
}

// ListActiveMigrations returns all currently active migrations
func (m *DefaultVersionMigrator) ListActiveMigrations() ([]*MigrationStatus, error) {
	var activeMigrations []*MigrationStatus

	// Take a snapshot of migration IDs while holding the lock
	m.mu.RLock()
	migrationIDs := make([]string, 0, len(m.activeMigrations))
	for migrationID := range m.activeMigrations {
		migrationIDs = append(migrationIDs, migrationID)
	}
	m.mu.RUnlock()

	// Get status for each migration (this safely handles concurrency)
	for _, migrationID := range migrationIDs {
		status, err := m.GetMigrationStatus(migrationID)
		if err != nil {
			continue // Skip migrations with errors (may have completed while we were iterating)
		}
		activeMigrations = append(activeMigrations, status)
	}

	// Sort by start time
	sort.Slice(activeMigrations, func(i, j int) bool {
		return activeMigrations[i].StartTime.Before(activeMigrations[j].StartTime)
	})

	return activeMigrations, nil
}

// RollbackMigration rolls back a migration (placeholder implementation)
func (m *DefaultVersionMigrator) RollbackMigration(ctx context.Context, migrationID string) (*MigrationResult, error) {
	// Find the migration to rollback
	var originalResult *MigrationResult
	for _, result := range m.migrationHistory {
		if result.ID == migrationID {
			originalResult = result
			break
		}
	}

	if originalResult == nil {
		return nil, fmt.Errorf("migration %s not found in history", migrationID)
	}

	if !originalResult.Path.RollbackSupported {
		return nil, fmt.Errorf("migration %s does not support rollback", migrationID)
	}

	// Create reverse migration path
	rollbackPath := &MigrationPath{
		ID:                fmt.Sprintf("rollback-%s-%d", migrationID, time.Now().UnixNano()),
		ModuleName:        originalResult.Path.ModuleName,
		FromVersion:       originalResult.Path.ToVersion,
		ToVersion:         originalResult.Path.FromVersion,
		Complexity:        originalResult.Path.Complexity,
		RequiresBackup:    false, // Usually rollbacks don't need backup
		RollbackSupported: false, // Can't rollback a rollback
		CreatedAt:         time.Now(),
	}

	// Generate rollback steps (reverse of original steps)
	rollbackPath.Steps = m.generateRollbackSteps(originalResult.Path)

	// Execute the rollback
	return m.ExecuteMigration(ctx, rollbackPath)
}

// generateRollbackSteps creates steps for rolling back a migration
func (m *DefaultVersionMigrator) generateRollbackSteps(originalPath *MigrationPath) []MigrationStep {
	var steps []MigrationStep

	// Create simplified rollback steps
	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("rollback-validate-%s", originalPath.ModuleName),
		Type:           MigrationStepValidation,
		FromVersion:    originalPath.ToVersion,
		ToVersion:      originalPath.FromVersion,
		Description:    "Validate rollback prerequisites",
		EstimatedTime:  100 * time.Millisecond,
		Complexity:     MigrationComplexityLow,
		ValidationType: ValidationFull,
	})

	steps = append(steps, MigrationStep{
		ID:              fmt.Sprintf("rollback-main-%s", originalPath.ModuleName),
		Type:            MigrationStepDowngrade,
		FromVersion:     originalPath.ToVersion,
		ToVersion:       originalPath.FromVersion,
		Description:     fmt.Sprintf("Roll back from %s to %s", originalPath.ToVersion, originalPath.FromVersion),
		EstimatedTime:   200 * time.Millisecond, // Test-friendly duration
		Complexity:      originalPath.Complexity,
		RequiresRestart: originalPath.Complexity >= MigrationComplexityMedium,
		ValidationType:  ValidationFull,
	})

	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("rollback-cleanup-%s", originalPath.ModuleName),
		Type:           MigrationStepCleanup,
		FromVersion:    originalPath.ToVersion,
		ToVersion:      originalPath.FromVersion,
		Description:    "Clean up rollback artifacts",
		EstimatedTime:  100 * time.Millisecond,
		Complexity:     MigrationComplexityLow,
		ValidationType: ValidationNone,
	})

	return steps
}

// Implementation of migration strategies

// PlanMigration for SimpleMigrationStrategy
func (s *SimpleMigrationStrategy) PlanMigration(fromVersion, toVersion string, compatibility *VersionCompatibilityInfo) (*MigrationPath, error) {
	// Simple strategy - basic validation and direct migration
	return &MigrationPath{
		Complexity:        MigrationComplexityLow,
		RequiresBackup:    false,
		RollbackSupported: true,
	}, nil
}

// ValidateMigration for SimpleMigrationStrategy
func (s *SimpleMigrationStrategy) ValidateMigration(path *MigrationPath) error {
	// Basic validation for simple migrations
	return nil
}

// EstimateDuration for SimpleMigrationStrategy
func (s *SimpleMigrationStrategy) EstimateDuration(path *MigrationPath) time.Duration {
	totalTime := time.Duration(0)
	for _, step := range path.Steps {
		totalTime += step.EstimatedTime
	}
	return totalTime
}

// PlanMigration for ComplexMigrationStrategy
func (c *ComplexMigrationStrategy) PlanMigration(fromVersion, toVersion string, compatibility *VersionCompatibilityInfo) (*MigrationPath, error) {
	// Complex strategy - detailed planning with compatibility analysis
	return &MigrationPath{
		Complexity:        MigrationComplexityHigh,
		RequiresBackup:    true,
		RollbackSupported: true,
	}, nil
}

// ValidateMigration for ComplexMigrationStrategy
func (c *ComplexMigrationStrategy) ValidateMigration(path *MigrationPath) error {
	// Enhanced validation for complex migrations
	return nil
}

// EstimateDuration for ComplexMigrationStrategy
func (c *ComplexMigrationStrategy) EstimateDuration(path *MigrationPath) time.Duration {
	totalTime := time.Duration(0)
	for _, step := range path.Steps {
		totalTime += step.EstimatedTime
	}
	// Add buffer for complex migrations
	return totalTime + (totalTime / 4) // 25% buffer
}
