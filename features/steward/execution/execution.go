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
//	// Create executor
//	executor, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: logger})
//
//	// Execute complete configuration
//	report := executor.ExecuteConfiguration(ctx, stewardConfig)
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
	"time"

	"gopkg.in/yaml.v3"

	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
)

// DriftEventHandler is called when managed resource drift is detected during
// the Compare step of the Get→Compare→Set→Verify cycle, before Set corrects it.
// This provides the controller visibility into what drifted and when.
//
// Parameters:
//   - resourceName: the cfg resource name where drift was detected
//   - moduleName: the module managing the resource (e.g. "file", "package")
//   - diff: the state diff describing exactly what changed
type DriftEventHandler func(resourceName string, moduleName string, diff *stewardtesting.StateDiff)

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
	StateDiff      *stewardtesting.StateDiff
}

// ResourceStatus represents the execution status of a resource
type ResourceStatus int

const (
	StatusSuccess ResourceStatus = iota
	StatusFailed
	StatusSkipped
	StatusNoChange
)

// genericConfigState is a simple map-backed ConfigState implementation used
// when no module-specific state type is needed.
type genericConfigState struct {
	data map[string]interface{}
}

func (g *genericConfigState) AsMap() map[string]interface{} {
	return g.data
}

func (g *genericConfigState) ToYAML() ([]byte, error) {
	return yaml.Marshal(g.data)
}

func (g *genericConfigState) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, &g.data)
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
