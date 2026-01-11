// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package execution provides resource configuration orchestration for steward.
//
// This package implements the execution engine that orchestrates the complete
// Get→Compare→Set→Verify workflow for configuration management. It coordinates
// between modules, handles error policies, and provides detailed reporting.
//
// The execution engine follows this workflow for each resource:
//  1. Load the required module from the factory
//  2. Get the current state using module.Get()
//  3. Compare current vs desired state (drift detection)
//  4. If drift detected, apply changes using module.Set()
//  5. Verify changes by calling module.Get() again
//  6. Generate detailed execution report
//
// Basic usage:
//
//	// Create execution engine
//	engine := execution.New(moduleFactory, comparator, errorConfig, logger)
//
//	// Execute complete configuration
//	report := engine.ExecuteConfiguration(ctx, stewardConfig)
//
//	// Check results
//	log.Printf("Executed %d resources: %d successful, %d failed, %d skipped",
//		report.TotalResources, report.SuccessfulCount,
//		report.FailedCount, report.SkippedCount)
//
// Error handling follows the steward's configured policies and provides
// detailed information for troubleshooting and monitoring.
package execution

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ExecutionEngine orchestrates resource configuration management
type ExecutionEngine struct {
	factory    *factory.ModuleFactory
	comparator *testing.StateComparator
	config     config.ErrorHandlingConfig
	logger     logging.Logger
}

// ExecutionReport contains the results of configuration execution
type ExecutionReport struct {
	StartTime       time.Time
	EndTime         time.Time
	TotalResources  int
	SuccessfulCount int
	FailedCount     int
	SkippedCount    int
	ResourceResults []ResourceResult
	Errors          []string
}

// ResourceResult contains the result of executing a single resource
type ResourceResult struct {
	ResourceName   string
	ModuleName     string
	Status         ResourceStatus
	DriftDetected  bool
	ChangesApplied bool
	ExecutionTime  time.Duration
	Error          string
	StateDiff      *testing.StateDiff
}

// ResourceStatus represents the execution status of a resource
type ResourceStatus int

const (
	StatusSuccess ResourceStatus = iota
	StatusFailed
	StatusSkipped
	StatusNoChange
)

// New creates a new ExecutionEngine instance
func New(factory *factory.ModuleFactory, comparator *testing.StateComparator,
	errorConfig config.ErrorHandlingConfig, logger logging.Logger) *ExecutionEngine {
	return &ExecutionEngine{
		factory:    factory,
		comparator: comparator,
		config:     errorConfig,
		logger:     logger,
	}
}

// ExecuteConfiguration executes the complete configuration for all resources
func (e *ExecutionEngine) ExecuteConfiguration(ctx context.Context, cfg config.StewardConfig) ExecutionReport {
	report := ExecutionReport{
		StartTime:       time.Now(),
		TotalResources:  len(cfg.Resources),
		ResourceResults: make([]ResourceResult, 0, len(cfg.Resources)),
		Errors:          make([]string, 0),
	}

	e.logger.Info("Starting configuration execution",
		"total_resources", report.TotalResources)

	// Execute each resource
	for _, resource := range cfg.Resources {
		select {
		case <-ctx.Done():
			e.logger.Warn("Configuration execution cancelled")
			report.Errors = append(report.Errors, "execution cancelled: "+ctx.Err().Error())
			return report
		default:
			result := e.ExecuteResource(ctx, resource)
			report.ResourceResults = append(report.ResourceResults, result)

			switch result.Status {
			case StatusSuccess, StatusNoChange:
				report.SuccessfulCount++
			case StatusFailed:
				report.FailedCount++
			case StatusSkipped:
				report.SkippedCount++
			}
		}
	}

	report.EndTime = time.Now()

	e.logger.Info("Configuration execution completed",
		"total", report.TotalResources,
		"successful", report.SuccessfulCount,
		"failed", report.FailedCount,
		"skipped", report.SkippedCount,
		"duration", report.EndTime.Sub(report.StartTime))

	return report
}

// ExecuteResource executes configuration for a single resource
func (e *ExecutionEngine) ExecuteResource(ctx context.Context, resource config.ResourceConfig) ResourceResult {
	startTime := time.Now()

	result := ResourceResult{
		ResourceName: resource.Name,
		ModuleName:   resource.Module,
		Status:       StatusFailed,
	}

	// Determine the resource identifier to use with the module
	// For modules that manage filesystem resources (file, directory), use the path from config
	// Otherwise, fall back to the resource name
	resourceID := e.getResourceIdentifier(resource)

	e.logger.Info("Executing resource configuration",
		"resource", resource.Name,
		"resource_id", resourceID,
		"module", resource.Module)

	// Load the required module
	module, err := e.factory.CreateModuleInstance(resource.Module)
	if err != nil {
		result.Error = fmt.Sprintf("failed to load module: %v", err)
		result.ExecutionTime = time.Since(startTime)
		e.handleResourceError(resource, err)
		return result
	}

	if module == nil {
		// Module loading failed but error handling allowed continuation
		result.Status = StatusSkipped
		result.Error = "module loading failed but continuing per configuration"
		result.ExecutionTime = time.Since(startTime)
		return result
	}

	// Convert resource config to ConfigState
	desiredState, err := e.createConfigState(resource.Config)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create config state: %v", err)
		result.ExecutionTime = time.Since(startTime)
		e.handleResourceError(resource, err)
		return result
	}

	// Get current state using the appropriate resource identifier
	currentState, err := module.Get(ctx, resourceID)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get current state: %v", err)
		result.ExecutionTime = time.Since(startTime)
		e.handleResourceError(resource, err)
		return result
	}

	// Compare states to detect drift
	driftDetected, stateDiff := e.comparator.CompareStates(currentState, desiredState)
	result.DriftDetected = driftDetected
	result.StateDiff = &stateDiff

	if !driftDetected {
		result.Status = StatusNoChange
		result.ExecutionTime = time.Since(startTime)
		e.logger.Info("Resource is already in desired state",
			"resource", resource.Name)
		return result
	}

	e.logger.Info("Configuration drift detected",
		"resource", resource.Name,
		"changes_required", len(stateDiff.ChangedFields))

	// Apply changes using the resource identifier
	if err := module.Set(ctx, resourceID, desiredState); err != nil {
		result.Error = fmt.Sprintf("failed to apply configuration: %v", err)
		result.ExecutionTime = time.Since(startTime)
		e.handleResourceError(resource, err)
		return result
	}

	result.ChangesApplied = true

	// Verify changes were applied correctly
	if err := e.verifyChanges(ctx, module, resourceID, desiredState); err != nil {
		result.Error = fmt.Sprintf("verification failed: %v", err)
		result.ExecutionTime = time.Since(startTime)
		e.handleResourceError(resource, err)
		return result
	}

	result.Status = StatusSuccess
	result.ExecutionTime = time.Since(startTime)

	e.logger.Info("Resource configuration applied successfully",
		"resource", resource.Name,
		"duration", result.ExecutionTime)

	return result
}

// createConfigState converts a map[string]interface{} to a ConfigState
func (e *ExecutionEngine) createConfigState(configData map[string]interface{}) (modules.ConfigState, error) {
	// This is a simplified implementation
	// In a real system, you would need to create the appropriate ConfigState
	// implementation based on the module type or use a generic implementation

	// For now, return a generic config state
	return &genericConfigState{data: configData}, nil
}

// getResourceIdentifier determines the appropriate resource identifier for a module.
//
// For modules that manage filesystem resources (file, directory, script), the path
// from the config is used as the identifier. For other modules, the resource name
// is used as a fallback.
//
// This allows file/directory modules to correctly identify resources by their
// filesystem path rather than by an abstract resource name.
func (e *ExecutionEngine) getResourceIdentifier(resource config.ResourceConfig) string {
	// Check if the config has a "path" field (common for file, directory, script modules)
	if path, ok := resource.Config["path"].(string); ok && path != "" {
		return path
	}

	// Fall back to resource name for other modules (firewall, package, etc.)
	return resource.Name
}

// verifyChanges checks that the applied configuration matches the desired state
func (e *ExecutionEngine) verifyChanges(ctx context.Context, module modules.Module,
	resourceID string, desiredState modules.ConfigState) error {

	// Get the state after changes
	currentState, err := module.Get(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("failed to get state for verification: %w", err)
	}

	// Compare again to ensure changes were applied
	driftDetected, stateDiff := e.comparator.CompareStates(currentState, desiredState)
	if driftDetected {
		// Log detailed diff for debugging
		e.logger.Debug("Verification found remaining drift",
			"changed_fields", stateDiff.GetChangedFieldNames(),
			"added_fields", stateDiff.GetAddedFieldNames(),
			"removed_fields", stateDiff.GetRemovedFieldNames(),
			"detailed_diff", stateDiff.GetDetailedDiff())
		return fmt.Errorf("verification failed: changes not fully applied, remaining differences: %d changed, %d added, %d removed",
			len(stateDiff.ChangedFields), len(stateDiff.AddedFields), len(stateDiff.RemovedFields))
	}

	return nil
}

// handleResourceError handles errors according to the configured error handling policy
func (e *ExecutionEngine) handleResourceError(resource config.ResourceConfig, err error) {
	switch e.config.ResourceFailure {
	case config.ActionContinue:
		e.logger.Error("Resource execution failed, continuing",
			"resource", resource.Name,
			"error", err)
	case config.ActionWarn:
		e.logger.Warn("Resource execution failed",
			"resource", resource.Name,
			"error", err)
	case config.ActionFail:
		e.logger.Error("Resource execution failed",
			"resource", resource.Name,
			"error", err)
		// Return an error that propagates up to stop further execution
		panic(fmt.Errorf("resource execution failed (fail policy): %s: %w", resource.Name, err))
	}
}

// genericConfigState is a simple implementation of ConfigState for testing
type genericConfigState struct {
	data map[string]interface{}
}

func (g *genericConfigState) AsMap() map[string]interface{} {
	return g.data
}

func (g *genericConfigState) ToYAML() ([]byte, error) {
	// This would use yaml.Marshal in a real implementation
	return []byte("mock yaml"), nil
}

func (g *genericConfigState) FromYAML(data []byte) error {
	// This would use yaml.Unmarshal in a real implementation
	return nil
}

func (g *genericConfigState) Validate() error {
	return nil
}

func (g *genericConfigState) GetManagedFields() []string {
	// Exclude identifier fields that aren't part of the actual configuration state
	excludedFields := map[string]bool{
		"path": true, // path is the resourceID, not a state field
		"name": true, // name is a resource identifier
	}

	fields := make([]string, 0, len(g.data))
	for key := range g.data {
		if !excludedFields[key] {
			fields = append(fields, key)
		}
	}
	return fields
}
