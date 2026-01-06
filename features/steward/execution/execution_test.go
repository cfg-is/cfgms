// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package execution

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	// Create real implementations for testing
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)

	assert.NotNil(t, engine)
	assert.Equal(t, moduleFactory, engine.factory)
	assert.Equal(t, comparator, engine.comparator)
	assert.Equal(t, errorConfig, engine.config)
	assert.Equal(t, logger, engine.logger)
}

func TestExecuteConfiguration_EmptyResources(t *testing.T) {
	// Setup with real implementations
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure: config.ActionFail,
	}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)

	// Create empty configuration
	cfg := config.StewardConfig{
		Resources: []config.ResourceConfig{},
	}

	ctx := context.Background()
	report := engine.ExecuteConfiguration(ctx, cfg)

	// Verify report for empty configuration
	assert.Equal(t, 0, report.TotalResources)
	assert.Equal(t, 0, report.SuccessfulCount)
	assert.Equal(t, 0, report.FailedCount)
	assert.Equal(t, 0, report.SkippedCount)
	assert.Len(t, report.ResourceResults, 0)
	assert.True(t, report.EndTime.After(report.StartTime))
}

func TestExecuteConfiguration_WithUnknownModule(t *testing.T) {
	// Setup with real implementations
	registry := discovery.ModuleRegistry{} // Empty registry - no modules available
	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionContinue, // Continue on module load failure
		ResourceFailure:   config.ActionWarn,
	}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)

	// Create configuration with unknown module
	cfg := config.StewardConfig{
		Resources: []config.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "unknown-module",
				Config: map[string]interface{}{"key": "value"},
			},
		},
	}

	ctx := context.Background()
	report := engine.ExecuteConfiguration(ctx, cfg)

	// Verify report shows skipped resource due to module not found
	assert.Equal(t, 1, report.TotalResources)
	assert.Equal(t, 0, report.SuccessfulCount)
	assert.Equal(t, 0, report.FailedCount)
	assert.Equal(t, 1, report.SkippedCount)
	assert.Len(t, report.ResourceResults, 1)

	result := report.ResourceResults[0]
	assert.Equal(t, "test-resource", result.ResourceName)
	assert.Equal(t, "unknown-module", result.ModuleName)
	assert.Equal(t, StatusSkipped, result.Status)
	assert.GreaterOrEqual(t, result.ExecutionTime, time.Duration(0))
}

func TestExecuteConfiguration_CanceledContext(t *testing.T) {
	// Setup with real implementations
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)

	// Create configuration with a resource
	cfg := config.StewardConfig{
		Resources: []config.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "test-module",
				Config: map[string]interface{}{"key": "value"},
			},
		},
	}

	// Create canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	report := engine.ExecuteConfiguration(ctx, cfg)

	// Verify that execution was cancelled
	assert.Equal(t, 1, report.TotalResources)
	assert.Contains(t, report.Errors, "execution cancelled: context canceled")
}

func TestGenericConfigState(t *testing.T) {
	data := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	state := &genericConfigState{data: data}

	// Test AsMap
	assert.Equal(t, data, state.AsMap())

	// Test GetManagedFields
	fields := state.GetManagedFields()
	assert.Len(t, fields, 3)
	assert.Contains(t, fields, "key1")
	assert.Contains(t, fields, "key2")
	assert.Contains(t, fields, "key3")

	// Test ToYAML (mock implementation)
	yaml, err := state.ToYAML()
	assert.NoError(t, err)
	assert.NotEmpty(t, yaml)

	// Test FromYAML (mock implementation)
	err = state.FromYAML([]byte("test"))
	assert.NoError(t, err)

	// Test Validate (mock implementation)
	err = state.Validate()
	assert.NoError(t, err)
}
