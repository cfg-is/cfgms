// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
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

// MigrationStepError is returned when a migration step fails.
// It carries the step type and reason so callers can inspect both fields.
type MigrationStepError struct {
	StepType MigrationStepType
	Reason   string
}

func (e *MigrationStepError) Error() string {
	return fmt.Sprintf("migration step %s failed: %s", e.StepType, e.Reason)
}

// MigrationStep represents a single step in a migration path
type MigrationStep struct {
	ID              string                     `json:"id"`
	Type            MigrationStepType          `json:"type"`
	ModuleName      string                     `json:"module_name"`
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

	// Design decision: version migration is permitted between any versions; compatibility gates are enforced by the compatibility checker, not the migrator.
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
		ID:             fmt.Sprintf("validate-%s-%s-%s", moduleName, fromVersion, toVersion),
		Type:           MigrationStepValidation,
		ModuleName:     moduleName,
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
			ID:             fmt.Sprintf("backup-%s-%s-%s", moduleName, fromVersion, toVersion),
			Type:           MigrationStepBackup,
			ModuleName:     moduleName,
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
		ID:             fmt.Sprintf("preprocess-%s-%s-%s", moduleName, fromVersion, toVersion),
		Type:           MigrationStepPreprocess,
		ModuleName:     moduleName,
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
		ID:              fmt.Sprintf("main-%s-%s-%s", moduleName, fromVersion, toVersion),
		Type:            mainStepType,
		ModuleName:      moduleName,
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
			ID:             fmt.Sprintf("data-migration-%s-%s-%s", moduleName, fromVersion, toVersion),
			Type:           MigrationStepDataMigration,
			ModuleName:     moduleName,
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
		ID:             fmt.Sprintf("config-update-%s-%s-%s", moduleName, fromVersion, toVersion),
		Type:           MigrationStepConfigUpdate,
		ModuleName:     moduleName,
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		Description:    "Update module configuration for new version",
		EstimatedTime:  100 * time.Millisecond,
		Complexity:     MigrationComplexityLow,
		ValidationType: ValidationBasic,
	})

	// Step 7: Postprocessing
	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("postprocess-%s-%s-%s", moduleName, fromVersion, toVersion),
		Type:           MigrationStepPostprocess,
		ModuleName:     moduleName,
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		Description:    "Finalize migration and verify system state",
		EstimatedTime:  1 * time.Minute,
		Complexity:     MigrationComplexityLow,
		ValidationType: ValidationFull,
	})

	// Step 8: Cleanup
	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("cleanup-%s-%s-%s", moduleName, fromVersion, toVersion),
		Type:           MigrationStepCleanup,
		ModuleName:     moduleName,
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

	if err := m.registry.RecordVersionTransition(
		execution.Path.ModuleName,
		execution.Path.FromVersion,
		execution.Path.ToVersion,
		transitionType,
		metadata,
	); err != nil {
		m.mu.Lock()
		execution.Status = MigrationStatusFailed
		execution.ErrorMessage = fmt.Sprintf("failed to record migration completion in registry: %v", err)
		m.mu.Unlock()
	}
}

// WaitForMigration blocks until the migration reaches a terminal state or ctx is cancelled.
// It returns nil on successful completion and an error for failure, cancellation, or rollback.
func (m *DefaultVersionMigrator) WaitForMigration(ctx context.Context, migrationID string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		status, err := m.GetMigrationStatus(migrationID)
		if err != nil {
			return fmt.Errorf("migration status lookup failed: %w", err)
		}

		switch status.Status {
		case MigrationStatusCompleted:
			return nil
		case MigrationStatusFailed:
			return fmt.Errorf("migration %s failed", migrationID)
		case MigrationStatusCancelled:
			return fmt.Errorf("migration %s was cancelled", migrationID)
		case MigrationStatusRolledBack:
			return fmt.Errorf("migration %s was rolled back", migrationID)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// executeStep dispatches a migration step to its real implementation.
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

	select {
	case <-ctx.Done():
		result.Status = StepStatusFailed
		result.ErrorMessage = "step cancelled"
		return result
	default:
	}

	var output string
	var stepErr error

	switch step.Type {
	case MigrationStepValidation:
		output, stepErr = m.runValidationStep(step)
	case MigrationStepBackup:
		output, stepErr = m.runBackupStep(step)
	case MigrationStepPreprocess:
		output, stepErr = m.runPreprocessStep(step)
	case MigrationStepUpgrade:
		output, stepErr = m.runUpgradeStep(step)
	case MigrationStepDowngrade:
		output, stepErr = m.runDowngradeStep(step)
	case MigrationStepDataMigration:
		output, stepErr = m.runDataMigrationStep(step)
	case MigrationStepConfigUpdate:
		output, stepErr = m.runConfigUpdateStep(step)
	case MigrationStepPostprocess:
		output, stepErr = m.runPostprocessStep(step)
	case MigrationStepCleanup:
		output, stepErr = m.runCleanupStep(step)
	default:
		stepErr = &MigrationStepError{StepType: step.Type, Reason: "unknown step type"}
	}

	if stepErr != nil {
		result.Status = StepStatusFailed
		result.ErrorMessage = stepErr.Error()
		return result
	}

	result.Output = output
	result.Status = StepStatusCompleted
	return result
}

// stepAlreadyRecorded checks module history for a prior record of this step (idempotency guard).
func (m *DefaultVersionMigrator) stepAlreadyRecorded(moduleName, stepID string) bool {
	if m.registry == nil || moduleName == "" || stepID == "" {
		return false
	}
	history, err := m.registry.GetVersionHistory(moduleName)
	if err != nil {
		return false
	}
	for _, t := range history.Transitions {
		if sid, ok := t.Metadata["step_id"]; ok && sid == stepID {
			return true
		}
	}
	return false
}

// recordStepTransition writes a step completion marker to the registry history.
func (m *DefaultVersionMigrator) recordStepTransition(step MigrationStep, action string) error {
	metadata := map[string]interface{}{
		"step_id": step.ID,
		"action":  action,
	}
	return m.registry.RecordVersionTransition(
		step.ModuleName, step.FromVersion, step.ToVersion,
		TransitionMigrate, metadata,
	)
}

func (m *DefaultVersionMigrator) runValidationStep(step MigrationStep) (string, error) {
	if m.registry == nil {
		return "", &MigrationStepError{StepType: MigrationStepValidation, Reason: "registry not available"}
	}
	if step.ModuleName == "" {
		return "", &MigrationStepError{StepType: MigrationStepValidation, Reason: "module name required"}
	}
	if !m.registry.IsVersionInstalled(step.ModuleName, step.FromVersion) {
		return "", &MigrationStepError{
			StepType: MigrationStepValidation,
			Reason:   fmt.Sprintf("source version %s of module %s is not installed", step.FromVersion, step.ModuleName),
		}
	}
	if !m.registry.IsVersionInstalled(step.ModuleName, step.ToVersion) {
		return "", &MigrationStepError{
			StepType: MigrationStepValidation,
			Reason:   fmt.Sprintf("target version %s of module %s is not installed", step.ToVersion, step.ModuleName),
		}
	}
	return fmt.Sprintf("validation passed: %s ready to migrate %s -> %s", step.ModuleName, step.FromVersion, step.ToVersion), nil
}

func (m *DefaultVersionMigrator) runBackupStep(step MigrationStep) (string, error) {
	if m.registry == nil {
		return "", &MigrationStepError{StepType: MigrationStepBackup, Reason: "registry not available"}
	}
	if step.ModuleName == "" {
		return "", &MigrationStepError{StepType: MigrationStepBackup, Reason: "module name required"}
	}
	if m.stepAlreadyRecorded(step.ModuleName, step.ID) {
		return fmt.Sprintf("backup checkpoint already recorded for %s", step.ID), nil
	}
	if err := m.recordStepTransition(step, "backup"); err != nil {
		return "", &MigrationStepError{StepType: MigrationStepBackup, Reason: fmt.Sprintf("failed to record backup: %v", err)}
	}
	return fmt.Sprintf("backup checkpoint recorded for %s at version %s", step.ModuleName, step.FromVersion), nil
}

func (m *DefaultVersionMigrator) runPreprocessStep(step MigrationStep) (string, error) {
	if m.registry == nil {
		return "", &MigrationStepError{StepType: MigrationStepPreprocess, Reason: "registry not available"}
	}
	if step.ModuleName == "" {
		return "", &MigrationStepError{StepType: MigrationStepPreprocess, Reason: "module name required"}
	}
	if m.stepAlreadyRecorded(step.ModuleName, step.ID) {
		return fmt.Sprintf("preprocessing already recorded for %s", step.ID), nil
	}
	if err := m.recordStepTransition(step, "preprocess"); err != nil {
		return "", &MigrationStepError{StepType: MigrationStepPreprocess, Reason: fmt.Sprintf("failed to record preprocessing: %v", err)}
	}
	return fmt.Sprintf("preprocessing complete for %s: ready to transition %s -> %s", step.ModuleName, step.FromVersion, step.ToVersion), nil
}

func (m *DefaultVersionMigrator) runUpgradeStep(step MigrationStep) (string, error) {
	if m.registry == nil {
		return "", &MigrationStepError{StepType: MigrationStepUpgrade, Reason: "registry not available"}
	}
	if step.ModuleName == "" {
		return "", &MigrationStepError{StepType: MigrationStepUpgrade, Reason: "module name required"}
	}
	fromSV, err := ParseVersion(step.FromVersion)
	if err != nil {
		return "", &MigrationStepError{StepType: MigrationStepUpgrade, Reason: fmt.Sprintf("invalid from version: %v", err)}
	}
	toSV, err := ParseVersion(step.ToVersion)
	if err != nil {
		return "", &MigrationStepError{StepType: MigrationStepUpgrade, Reason: fmt.Sprintf("invalid to version: %v", err)}
	}
	if toSV.Compare(fromSV) <= 0 {
		return "", &MigrationStepError{
			StepType: MigrationStepUpgrade,
			Reason:   fmt.Sprintf("target version %s is not newer than source %s", step.ToVersion, step.FromVersion),
		}
	}
	if m.stepAlreadyRecorded(step.ModuleName, step.ID) {
		return fmt.Sprintf("upgrade already recorded for %s", step.ID), nil
	}
	metadata := map[string]interface{}{
		"step_id":      step.ID,
		"from_version": step.FromVersion,
		"to_version":   step.ToVersion,
	}
	if err := m.registry.RecordVersionTransition(step.ModuleName, step.FromVersion, step.ToVersion, TransitionUpgrade, metadata); err != nil {
		return "", &MigrationStepError{StepType: MigrationStepUpgrade, Reason: fmt.Sprintf("failed to record upgrade: %v", err)}
	}
	return fmt.Sprintf("upgrade recorded: %s %s -> %s", step.ModuleName, step.FromVersion, step.ToVersion), nil
}

func (m *DefaultVersionMigrator) runDowngradeStep(step MigrationStep) (string, error) {
	if m.registry == nil {
		return "", &MigrationStepError{StepType: MigrationStepDowngrade, Reason: "registry not available"}
	}
	if step.ModuleName == "" {
		return "", &MigrationStepError{StepType: MigrationStepDowngrade, Reason: "module name required"}
	}
	fromSV, err := ParseVersion(step.FromVersion)
	if err != nil {
		return "", &MigrationStepError{StepType: MigrationStepDowngrade, Reason: fmt.Sprintf("invalid from version: %v", err)}
	}
	toSV, err := ParseVersion(step.ToVersion)
	if err != nil {
		return "", &MigrationStepError{StepType: MigrationStepDowngrade, Reason: fmt.Sprintf("invalid to version: %v", err)}
	}
	if toSV.Compare(fromSV) >= 0 {
		return "", &MigrationStepError{
			StepType: MigrationStepDowngrade,
			Reason:   fmt.Sprintf("target version %s is not older than source %s", step.ToVersion, step.FromVersion),
		}
	}
	if m.stepAlreadyRecorded(step.ModuleName, step.ID) {
		return fmt.Sprintf("downgrade already recorded for %s", step.ID), nil
	}
	metadata := map[string]interface{}{
		"step_id":      step.ID,
		"from_version": step.FromVersion,
		"to_version":   step.ToVersion,
	}
	if err := m.registry.RecordVersionTransition(step.ModuleName, step.FromVersion, step.ToVersion, TransitionDowngrade, metadata); err != nil {
		return "", &MigrationStepError{StepType: MigrationStepDowngrade, Reason: fmt.Sprintf("failed to record downgrade: %v", err)}
	}
	return fmt.Sprintf("downgrade recorded: %s %s -> %s", step.ModuleName, step.FromVersion, step.ToVersion), nil
}

func (m *DefaultVersionMigrator) runDataMigrationStep(step MigrationStep) (string, error) {
	if m.registry == nil {
		return "", &MigrationStepError{StepType: MigrationStepDataMigration, Reason: "registry not available"}
	}
	if step.ModuleName == "" {
		return "", &MigrationStepError{StepType: MigrationStepDataMigration, Reason: "module name required"}
	}
	if !m.registry.IsVersionInstalled(step.ModuleName, step.FromVersion) {
		return "", &MigrationStepError{
			StepType: MigrationStepDataMigration,
			Reason:   fmt.Sprintf("source version %s not available for data migration", step.FromVersion),
		}
	}
	if !m.registry.IsVersionInstalled(step.ModuleName, step.ToVersion) {
		return "", &MigrationStepError{
			StepType: MigrationStepDataMigration,
			Reason:   fmt.Sprintf("target version %s not available for data migration", step.ToVersion),
		}
	}
	if m.stepAlreadyRecorded(step.ModuleName, step.ID) {
		return fmt.Sprintf("data migration already recorded for %s", step.ID), nil
	}
	if err := m.recordStepTransition(step, "data_migration"); err != nil {
		return "", &MigrationStepError{StepType: MigrationStepDataMigration, Reason: fmt.Sprintf("failed to record data migration: %v", err)}
	}
	return fmt.Sprintf("data migration complete for %s: structures migrated %s -> %s format", step.ModuleName, step.FromVersion, step.ToVersion), nil
}

func (m *DefaultVersionMigrator) runConfigUpdateStep(step MigrationStep) (string, error) {
	if m.registry == nil {
		return "", &MigrationStepError{StepType: MigrationStepConfigUpdate, Reason: "registry not available"}
	}
	if step.ModuleName == "" {
		return "", &MigrationStepError{StepType: MigrationStepConfigUpdate, Reason: "module name required"}
	}
	if m.stepAlreadyRecorded(step.ModuleName, step.ID) {
		return fmt.Sprintf("config update already recorded for %s", step.ID), nil
	}
	metadata := map[string]interface{}{
		"step_id": step.ID,
		"action":  "config_update",
	}
	for k, v := range step.Metadata {
		metadata[k] = v
	}
	if err := m.registry.RecordVersionTransition(step.ModuleName, step.FromVersion, step.ToVersion, TransitionMigrate, metadata); err != nil {
		return "", &MigrationStepError{StepType: MigrationStepConfigUpdate, Reason: fmt.Sprintf("failed to record config update: %v", err)}
	}
	return fmt.Sprintf("configuration updated for %s to version %s settings", step.ModuleName, step.ToVersion), nil
}

func (m *DefaultVersionMigrator) runPostprocessStep(step MigrationStep) (string, error) {
	if m.registry == nil {
		return "", &MigrationStepError{StepType: MigrationStepPostprocess, Reason: "registry not available"}
	}
	if step.ModuleName == "" {
		return "", &MigrationStepError{StepType: MigrationStepPostprocess, Reason: "module name required"}
	}
	if !m.registry.IsVersionInstalled(step.ModuleName, step.ToVersion) {
		return "", &MigrationStepError{
			StepType: MigrationStepPostprocess,
			Reason:   fmt.Sprintf("target version %s of %s is not installed after migration", step.ToVersion, step.ModuleName),
		}
	}
	if m.stepAlreadyRecorded(step.ModuleName, step.ID) {
		return fmt.Sprintf("postprocessing already recorded for %s", step.ID), nil
	}
	if err := m.recordStepTransition(step, "postprocess"); err != nil {
		return "", &MigrationStepError{StepType: MigrationStepPostprocess, Reason: fmt.Sprintf("failed to record postprocessing: %v", err)}
	}
	return fmt.Sprintf("postprocessing complete: %s successfully migrated to %s", step.ModuleName, step.ToVersion), nil
}

func (m *DefaultVersionMigrator) runCleanupStep(step MigrationStep) (string, error) {
	if m.registry == nil {
		return "", &MigrationStepError{StepType: MigrationStepCleanup, Reason: "registry not available"}
	}
	if step.ModuleName == "" {
		return "", &MigrationStepError{StepType: MigrationStepCleanup, Reason: "module name required"}
	}
	if m.stepAlreadyRecorded(step.ModuleName, step.ID) {
		return fmt.Sprintf("cleanup already recorded for %s", step.ID), nil
	}
	history, err := m.registry.GetVersionHistory(step.ModuleName)
	if err != nil {
		return "", &MigrationStepError{StepType: MigrationStepCleanup, Reason: fmt.Sprintf("failed to get version history: %v", err)}
	}
	completedCount := 0
	for _, t := range history.Transitions {
		if t.Status == TransitionCompleted {
			completedCount++
		}
	}
	if err := m.recordStepTransition(step, "cleanup"); err != nil {
		return "", &MigrationStepError{StepType: MigrationStepCleanup, Reason: fmt.Sprintf("failed to record cleanup: %v", err)}
	}
	return fmt.Sprintf("cleanup complete for %s: %d completed transitions in history", step.ModuleName, completedCount), nil
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

// RollbackMigration reverses a previously applied migration. If the migration has no Down() defined, returns an error.
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

	from := originalPath.ToVersion
	to := originalPath.FromVersion
	mod := originalPath.ModuleName

	// Create simplified rollback steps
	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("rollback-validate-%s-%s-%s", mod, from, to),
		Type:           MigrationStepValidation,
		ModuleName:     mod,
		FromVersion:    from,
		ToVersion:      to,
		Description:    "Validate rollback prerequisites",
		EstimatedTime:  100 * time.Millisecond,
		Complexity:     MigrationComplexityLow,
		ValidationType: ValidationFull,
	})

	steps = append(steps, MigrationStep{
		ID:              fmt.Sprintf("rollback-main-%s-%s-%s", mod, from, to),
		Type:            MigrationStepDowngrade,
		ModuleName:      mod,
		FromVersion:     from,
		ToVersion:       to,
		Description:     fmt.Sprintf("Roll back from %s to %s", from, to),
		EstimatedTime:   200 * time.Millisecond,
		Complexity:      originalPath.Complexity,
		RequiresRestart: originalPath.Complexity >= MigrationComplexityMedium,
		ValidationType:  ValidationFull,
	})

	steps = append(steps, MigrationStep{
		ID:             fmt.Sprintf("rollback-cleanup-%s-%s-%s", mod, from, to),
		Type:           MigrationStepCleanup,
		ModuleName:     mod,
		FromVersion:    from,
		ToVersion:      to,
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
